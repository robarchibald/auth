package main

import (
	"errors"
	"github.com/robarchibald/onedb"
	"math"
	"time"
)

type RedisSessionBackend struct {
	db     onedb.DBer
	prefix string
}

func NewRedisSessionBackend(server string, port int, password string, maxIdle, maxConnections int, keyPrefix string) SessionBackender {
	r := onedb.NewRedis(server, port, password, maxIdle, maxConnections)
	return &RedisSessionBackend{db: r, prefix: keyPrefix}
}

func (r *RedisSessionBackend) CreateSession(loginID, userID int, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time,
	includeRememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*UserLoginSession, *UserLoginRememberMe, error) {
	session := UserLoginSession{LoginID: loginID, UserID: userID, SessionHash: sessionHash, RenewTimeUTC: sessionRenewTimeUTC, ExpireTimeUTC: sessionExpireTimeUTC}
	err := r.saveSession(&session)
	if err != nil {
		return nil, nil, err
	}

	var rememberMe UserLoginRememberMe
	if includeRememberMe {
		rememberMe = UserLoginRememberMe{LoginID: loginID, Selector: rememberMeSelector, TokenHash: rememberMeTokenHash, RenewTimeUTC: rememberMeRenewTimeUTC, ExpireTimeUTC: rememberMeExpireTimeUTC}
		err = r.saveRememberMe(&rememberMe)
		if err != nil {
			return nil, nil, err
		}
	}

	return &session, &rememberMe, nil
}

func (r *RedisSessionBackend) GetSession(sessionHash string) (*UserLoginSession, error) {
	session := &UserLoginSession{}
	return session, r.db.QueryStruct(onedb.NewRedisGetCommand(r.getSessionUrl(sessionHash)), session)
}

func (r *RedisSessionBackend) RenewSession(sessionHash string, renewTimeUTC time.Time) (*UserLoginSession, error) {
	session := &UserLoginSession{}
	key := r.getSessionUrl(sessionHash)
	err := r.db.QueryStruct(onedb.NewRedisGetCommand(key), session)
	if err != nil {
		return nil, err
	}
	session.RenewTimeUTC = renewTimeUTC
	return session, r.saveSession(session)
}

func (r *RedisSessionBackend) InvalidateSession(sessionHash string) error {
	return r.db.Execute(onedb.NewRedisDelCommand(r.getSessionUrl(sessionHash)))
}

func (r *RedisSessionBackend) GetRememberMe(selector string) (*UserLoginRememberMe, error) {
	rememberMe := &UserLoginRememberMe{}
	return rememberMe, r.db.QueryStruct(onedb.NewRedisGetCommand(r.getRememberMeUrl(selector)), rememberMe)
}

func (r *RedisSessionBackend) RenewRememberMe(selector string, renewTimeUTC time.Time) (*UserLoginRememberMe, error) {
	rememberMe := &UserLoginRememberMe{}
	err := r.db.QueryStruct(onedb.NewRedisGetCommand(r.getRememberMeUrl(selector)), rememberMe)
	if err != nil {
		return nil, errRememberMeNotFound
	} else if rememberMe.ExpireTimeUTC.Before(time.Now().UTC()) {
		return nil, errRememberMeExpired
	} else if rememberMe.ExpireTimeUTC.Before(renewTimeUTC) || renewTimeUTC.Before(time.Now().UTC()) {
		return nil, errInvalidRenewTimeUTC
	}
	rememberMe.RenewTimeUTC = renewTimeUTC
	return rememberMe, nil
}

func (r *RedisSessionBackend) InvalidateRememberMe(selector string) error {
	return r.db.Execute(onedb.NewRedisDelCommand(r.getRememberMeUrl(selector)))
}

func (r *RedisSessionBackend) Close() error {
	return r.db.Close()
}

func (r *RedisSessionBackend) saveSession(session *UserLoginSession) error {
	if time.Since(session.ExpireTimeUTC).Seconds() >= 0 {
		return errors.New("Unable to save expired session")
	}
	return r.save(r.getSessionUrl(session.SessionHash), session, round(rememberMeExpireDuration.Seconds()))
}

func (r *RedisSessionBackend) saveRememberMe(rememberMe *UserLoginRememberMe) error {
	if time.Since(rememberMe.ExpireTimeUTC).Seconds() >= 0 {
		return errors.New("Unable to save expired rememberMe")
	}
	return r.save(r.getRememberMeUrl(rememberMe.Selector), rememberMe, round(rememberMeExpireDuration.Seconds()))
}

func (r *RedisSessionBackend) getSessionUrl(sessionHash string) string {
	return r.prefix + "/session/" + sessionHash
}

func (r *RedisSessionBackend) getRememberMeUrl(selector string) string {
	return r.prefix + "/rememberMe/" + selector
}

func round(num float64) int {
	return int(math.Floor(0.5 + num))
}

func (r *RedisSessionBackend) save(key string, value interface{}, expireSeconds int) error {
	cmd, err := onedb.NewRedisSetCommand(key, value, expireSeconds)
	if err != nil {
		return err
	}
	return r.db.Execute(cmd)
}
