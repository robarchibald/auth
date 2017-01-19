package main

import (
	"errors"
	"github.com/robarchibald/onedb"
	"math"
	"time"
)

type backendRedisSession struct {
	db     onedb.DBer
	prefix string
}

func NewBackendRedisSession(server string, port int, password string, maxIdle, maxConnections int, keyPrefix string) SessionBackender {
	r := onedb.NewRedis(server, port, password, maxIdle, maxConnections)
	return &backendRedisSession{db: r, prefix: keyPrefix}
}

// need to first check that this emailVerifyHash isn't being used, otherwise we'll clobber existing
func (r *backendRedisSession) CreateEmailSession(email, emailVerifyHash string) error {
	return r.saveEmailSession(&emailSession{Email: email, EmailVerifyHash: emailVerifyHash})
}

func (r *backendRedisSession) GetEmailSession(emailVerifyHash string) (*emailSession, error) {
	session := &emailSession{}
	return session, r.db.QueryStructRow(onedb.NewRedisGetCommand(r.getEmailSessionUrl(emailVerifyHash)), session)
}

func (r *backendRedisSession) DeleteEmailSession(emailVerifyHash string) error {
	return nil
}

func (r *backendRedisSession) CreateSession(email, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time,
	includeRememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*UserLoginSession, *UserLoginRememberMe, error) {
	session := UserLoginSession{Email: email, SessionHash: sessionHash, RenewTimeUTC: sessionRenewTimeUTC, ExpireTimeUTC: sessionExpireTimeUTC}
	err := r.saveSession(&session)
	if err != nil {
		return nil, nil, err
	}

	var rememberMe UserLoginRememberMe
	if includeRememberMe {
		rememberMe = UserLoginRememberMe{Email: email, Selector: rememberMeSelector, TokenHash: rememberMeTokenHash, RenewTimeUTC: rememberMeRenewTimeUTC, ExpireTimeUTC: rememberMeExpireTimeUTC}
		err = r.saveRememberMe(&rememberMe)
		if err != nil {
			return nil, nil, err
		}
	}

	return &session, &rememberMe, nil
}

func (r *backendRedisSession) GetSession(sessionHash string) (*UserLoginSession, error) {
	session := &UserLoginSession{}
	return session, r.db.QueryStructRow(onedb.NewRedisGetCommand(r.getSessionUrl(sessionHash)), session)
}

func (r *backendRedisSession) RenewSession(sessionHash string, renewTimeUTC time.Time) (*UserLoginSession, error) {
	session := &UserLoginSession{}
	key := r.getSessionUrl(sessionHash)
	err := r.db.QueryStructRow(onedb.NewRedisGetCommand(key), session)
	if err != nil {
		return nil, err
	}
	session.RenewTimeUTC = renewTimeUTC
	return session, r.saveSession(session)
}

func (r *backendRedisSession) InvalidateSession(sessionHash string) error {
	return r.db.Execute(onedb.NewRedisDelCommand(r.getSessionUrl(sessionHash)))
}

func (r *backendRedisSession) InvalidateSessions(email string) error {
	return nil
}

func (r *backendRedisSession) GetRememberMe(selector string) (*UserLoginRememberMe, error) {
	rememberMe := &UserLoginRememberMe{}
	return rememberMe, r.db.QueryStructRow(onedb.NewRedisGetCommand(r.getRememberMeUrl(selector)), rememberMe)
}

func (r *backendRedisSession) RenewRememberMe(selector string, renewTimeUTC time.Time) (*UserLoginRememberMe, error) {
	rememberMe := &UserLoginRememberMe{}
	err := r.db.QueryStructRow(onedb.NewRedisGetCommand(r.getRememberMeUrl(selector)), rememberMe)
	if err != nil {
		return nil, err
	} else if rememberMe.ExpireTimeUTC.Before(time.Now().UTC()) {
		return nil, errRememberMeExpired
	} else if rememberMe.ExpireTimeUTC.Before(renewTimeUTC) || renewTimeUTC.Before(time.Now().UTC()) {
		return nil, errInvalidRenewTimeUTC
	}
	rememberMe.RenewTimeUTC = renewTimeUTC
	return rememberMe, nil
}

func (r *backendRedisSession) InvalidateRememberMe(selector string) error {
	return r.db.Execute(onedb.NewRedisDelCommand(r.getRememberMeUrl(selector)))
}

func (r *backendRedisSession) Close() error {
	return r.db.Close()
}

func (r *backendRedisSession) saveEmailSession(session *emailSession) error {
	return r.save(r.getEmailSessionUrl(session.EmailVerifyHash), session, emailExpireMins*60)
}

func (r *backendRedisSession) saveSession(session *UserLoginSession) error {
	if time.Since(session.ExpireTimeUTC).Seconds() >= 0 {
		return errors.New("Unable to save expired session")
	}
	return r.save(r.getSessionUrl(session.SessionHash), session, round(rememberMeExpireDuration.Seconds()))
}

func (r *backendRedisSession) saveRememberMe(rememberMe *UserLoginRememberMe) error {
	if time.Since(rememberMe.ExpireTimeUTC).Seconds() >= 0 {
		return errors.New("Unable to save expired rememberMe")
	}
	return r.save(r.getRememberMeUrl(rememberMe.Selector), rememberMe, round(rememberMeExpireDuration.Seconds()))
}

func (r *backendRedisSession) getEmailSessionUrl(emailVerifyHash string) string {
	return r.prefix + "/email/" + emailVerifyHash
}

func (r *backendRedisSession) getSessionUrl(sessionHash string) string {
	return r.prefix + "/session/" + sessionHash
}

func (r *backendRedisSession) getRememberMeUrl(selector string) string {
	return r.prefix + "/rememberMe/" + selector
}

func round(num float64) int {
	return int(math.Floor(0.5 + num))
}

func (r *backendRedisSession) save(key string, value interface{}, expireSeconds int) error {
	cmd, err := onedb.NewRedisSetCommand(key, value, expireSeconds)
	if err != nil {
		return err
	}
	return r.db.Execute(cmd)
}
