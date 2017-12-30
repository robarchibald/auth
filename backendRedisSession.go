package auth

import (
	"math"
	"time"

	"github.com/EndFirstCorp/onedb"
	"github.com/pkg/errors"
)

type backendRedisSession struct {
	db     onedb.DBer
	prefix string
}

// NewBackendRedisSession returns a SessionBackender for Redis
func NewBackendRedisSession(server string, port int, password string, maxIdle, maxConnections int, keyPrefix string) sessionBackender {
	r := onedb.NewRedis(server, port, password, maxIdle, maxConnections)
	return &backendRedisSession{db: r, prefix: keyPrefix}
}

// need to first check that this emailVerifyHash isn't being used, otherwise we'll clobber existing
func (r *backendRedisSession) CreateEmailSession(email, emailVerifyHash, csrfToken, destinationURL string) error {
	return r.saveEmailSession(&emailSession{"", email, emailVerifyHash, csrfToken, destinationURL})
}

func (r *backendRedisSession) GetEmailSession(emailVerifyHash string) (*emailSession, error) {
	session := &emailSession{}
	return session, r.db.QueryStructRow(onedb.NewRedisGetCommand(r.getEmailSessionKey(emailVerifyHash)), session)
}

func (r *backendRedisSession) UpdateEmailSession(emailVerifyHash, userID string) error {
	s, err := r.GetEmailSession(emailVerifyHash)
	if err != nil {
		return err
	}
	s.UserID = userID
	return r.saveEmailSession(s)
}

func (r *backendRedisSession) DeleteEmailSession(emailVerifyHash string) error {
	return nil
}

func (r *backendRedisSession) CreateSession(userID, email, fullname, sessionHash, csrfToken string, renewTimeUTC, expireTimeUTC time.Time) (*LoginSession, error) {
	session := LoginSession{userID, email, fullname, sessionHash, csrfToken, renewTimeUTC, expireTimeUTC}
	return &session, r.saveSession(&session)
}

func (r *backendRedisSession) CreateRememberMe(userID, email, selector, tokenHash string, renewTimeUTC, expireTimeUTC time.Time) (*rememberMeSession, error) {
	rememberMe := rememberMeSession{userID, email, selector, tokenHash, renewTimeUTC, expireTimeUTC}
	return &rememberMe, r.saveRememberMe(&rememberMe)
}

func (r *backendRedisSession) GetSession(sessionHash string) (*LoginSession, error) {
	session := &LoginSession{}
	return session, r.db.QueryStructRow(onedb.NewRedisGetCommand(r.getSessionKey(sessionHash)), session)
}

func (r *backendRedisSession) UpdateSession(sessionHash string, renewTimeUTC, expireTimeUTC time.Time) error {
	session, err := r.GetSession(sessionHash)
	if err != nil {
		return err
	}
	session.ExpireTimeUTC = expireTimeUTC
	session.RenewTimeUTC = renewTimeUTC
	return r.saveSession(session)
}

func (r *backendRedisSession) DeleteSession(sessionHash string) error {
	return r.db.Execute(onedb.NewRedisDelCommand(r.getSessionKey(sessionHash)))
}

func (r *backendRedisSession) InvalidateSessions(email string) error {
	return nil
}

func (r *backendRedisSession) GetRememberMe(selector string) (*rememberMeSession, error) {
	rememberMe := &rememberMeSession{}
	return rememberMe, r.db.QueryStructRow(onedb.NewRedisGetCommand(r.getRememberMeKey(selector)), rememberMe)
}

func (r *backendRedisSession) UpdateRememberMe(selector string, renewTimeUTC time.Time) error {
	rememberMe, err := r.GetRememberMe(selector)
	if err != nil {
		return err
	}
	rememberMe.RenewTimeUTC = renewTimeUTC
	return r.saveRememberMe(rememberMe)
}

func (r *backendRedisSession) DeleteRememberMe(selector string) error {
	return r.db.Execute(onedb.NewRedisDelCommand(r.getRememberMeKey(selector)))
}

func (r *backendRedisSession) Close() error {
	return r.db.Close()
}

func (r *backendRedisSession) saveEmailSession(session *emailSession) error {
	return r.save(r.getEmailSessionKey(session.EmailVerifyHash), session, emailExpireMins*60)
}

func (r *backendRedisSession) saveSession(session *LoginSession) error {
	if time.Since(session.ExpireTimeUTC).Seconds() >= 0 {
		return errors.New("Unable to save expired session")
	}
	return r.save(r.getSessionKey(session.SessionHash), session, round(rememberMeExpireDuration.Seconds()))
}

func (r *backendRedisSession) saveRememberMe(rememberMe *rememberMeSession) error {
	if time.Since(rememberMe.ExpireTimeUTC).Seconds() >= 0 {
		return errors.New("Unable to save expired rememberMe")
	}
	return r.save(r.getRememberMeKey(rememberMe.Selector), rememberMe, round(rememberMeExpireDuration.Seconds()))
}

func (r *backendRedisSession) getEmailSessionKey(emailVerifyHash string) string {
	return r.prefix + "/email/" + emailVerifyHash
}

func (r *backendRedisSession) getSessionKey(sessionHash string) string {
	return r.prefix + "/session/" + sessionHash
}

func (r *backendRedisSession) getRememberMeKey(selector string) string {
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
