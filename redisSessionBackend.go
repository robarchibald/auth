package main

import (
	"github.com/robarchibald/onedb"
	"time"
)

type SessionBackender interface {
	CreateSession(loginID, userID int, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*UserLoginSession, *UserLoginRememberMe, error)
	GetSession(sessionHash string) (*UserLoginSession, error)
	RenewSession(sessionHash string, renewTimeUTC time.Time) (*UserLoginSession, error)
	InvalidateSession(sessionHash string) error

	GetRememberMe(selector string) (*UserLoginRememberMe, error)
	RenewRememberMe(selector string, renewTimeUTC time.Time) (*UserLoginRememberMe, error)
	InvalidateRememberMe(selector string) error

	Close() error
}

type RedisSessionBackend struct {
	db onedb.DBer
}

func NewRedisSessionBackend(server string, port int, password string, maxIdle, maxConnections int) SessionBackender {
	r := onedb.NewRedis(server, port, password, maxIdle, maxConnections)
	return &RedisSessionBackend{db: r}
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
	var session *UserLoginSession
	return session, r.db.QueryStruct(getSessionUrl(sessionHash), session)
}

func (r *RedisSessionBackend) RenewSession(sessionHash string, renewTimeUTC time.Time) (*UserLoginSession, error) {
	var session *UserLoginSession
	key := getSessionUrl(sessionHash)
	err := r.db.QueryStruct(key, session)
	if err != nil {
		return nil, err
	}
	session.RenewTimeUTC = renewTimeUTC
	return session, r.saveSession(session)
}

func (r *RedisSessionBackend) InvalidateSession(sessionHash string) error {
	return r.db.Execute(onedb.NewRedisDelCommand(getSessionUrl(sessionHash)))
}

func (r *RedisSessionBackend) GetRememberMe(selector string) (*UserLoginRememberMe, error) {
	var rememberMe *UserLoginRememberMe
	return rememberMe, r.db.QueryStruct(getRememberMeUrl(selector), rememberMe)
}

func (r *RedisSessionBackend) RenewRememberMe(selector string, renewTimeUTC time.Time) (*UserLoginRememberMe, error) {
	var rememberMe *UserLoginRememberMe
	err := r.db.QueryStruct(getRememberMeUrl(selector), rememberMe)
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
	return r.db.Execute(onedb.NewRedisDelCommand(getRememberMeUrl(selector)))
}

func (r *RedisSessionBackend) Close() error {
	return r.db.Close()
}

func (r *RedisSessionBackend) saveSession(session *UserLoginSession) error {
	return r.save(getSessionUrl(session.SessionHash), session, 100)
}

func (r *RedisSessionBackend) saveRememberMe(rememberMe *UserLoginRememberMe) error {
	return r.save(getRememberMeUrl(rememberMe.Selector), rememberMe, 100)
}

func (r *RedisSessionBackend) save(key string, value interface{}, expireSeconds int) error {
	cmd, err := onedb.NewRedisSetCommand(key, value, expireSeconds)
	if err != nil {
		return err
	}
	return r.db.Execute(cmd)
}

func getSessionUrl(sessionHash string) string {
	return "session/" + sessionHash
}

func getRememberMeUrl(selector string) string {
	return "rememberMe/" + selector
}
