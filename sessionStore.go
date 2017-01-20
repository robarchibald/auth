package main

import (
	"net/http"
	"time"
)

type sessionStorer interface {
	GetSession() (*loginSession, error)
	CreateSession(email string, rememberMe bool) (*loginSession, error)
}

type sessionCookie struct {
	SessionID     string
	RenewTimeUTC  time.Time
	ExpireTimeUTC time.Time
}

type rememberMeCookie struct {
	Selector      string
	Token         string
	RenewTimeUTC  time.Time
	ExpireTimeUTC time.Time
}

type sessionStore struct {
	b           sessionBackender
	cookieStore cookieStorer
	r           *http.Request
}

func newSessionStore(b sessionBackender, w http.ResponseWriter, r *http.Request, customPrefix string, cookieKey []byte, secureOnlyCookie bool) sessionStorer {
	emailCookieName = customPrefix + "Email"
	sessionCookieName = customPrefix + "Session"
	rememberMeCookieName = customPrefix + "RememberMe"
	return &sessionStore{b, newCookieStore(w, r, cookieKey, secureOnlyCookie), r}
}

var emailCookieName = "Email"
var sessionCookieName = "Session"
var rememberMeCookieName = "RememberMe"

const emailExpireMins int = 60 * 24 * 365 // 1 year
const emailExpireDuration time.Duration = time.Duration(emailExpireMins) * time.Minute
const sessionRenewDuration time.Duration = 5 * time.Minute
const sessionExpireDuration time.Duration = time.Hour
const rememberMeRenewDuration time.Duration = time.Hour
const rememberMeExpireDuration time.Duration = time.Hour * 24 * 30 // 30 days

func (s *sessionStore) GetSession() (*loginSession, error) {
	cookie, err := s.getSessionCookie()
	if err != nil || cookie.SessionID == "" { // impossible to get the session if there is no cookie
		return nil, newAuthError("Session cookie not found", err)
	}
	sessionHash, err := decodeStringToHash(cookie.SessionID)
	if err != nil {
		return nil, newAuthError("Unable to decode session cookie", err)
	}

	if cookie.RenewTimeUTC.Before(time.Now().UTC()) || cookie.ExpireTimeUTC.Before(time.Now().UTC()) {
		return s.renewSession(cookie.SessionID, sessionHash, &cookie.RenewTimeUTC, &cookie.ExpireTimeUTC)
	}

	session, err := s.b.GetSession(sessionHash)
	if err != nil {
		if err == errSessionNotFound {
			s.deleteSessionCookie()
		}
		return nil, newLoggedError("Failed to verify session", err)
	}
	return session, nil
}

func (s *sessionStore) getRememberMe() (*rememberMeSession, error) {
	cookie, err := s.getRememberMeCookie()
	if err != nil || cookie.Selector == "" { // impossible to get the remember Me if there is no cookie
		return nil, newAuthError("RememberMe cookie not found", err)
	}
	if cookie.ExpireTimeUTC.Before(time.Now().UTC()) {
		s.deleteRememberMeCookie()
		return nil, newAuthError("RememberMe cookie has expired", nil)
	}

	rememberMe, err := s.b.GetRememberMe(cookie.Selector)
	if err != nil {
		if err == errRememberMeNotFound {
			s.deleteRememberMeCookie()
		}
		return nil, newLoggedError("Unable to find matching RememberMe in DB", err)
	}
	if !encodedHashEquals(cookie.Token, rememberMe.TokenHash) {
		s.deleteRememberMeCookie()
		return nil, newLoggedError("RememberMe cookie doesn't match backend token", nil)
	}
	if rememberMe.RenewTimeUTC.Before(time.Now().UTC()) {
		rememberMe, err = s.b.RenewRememberMe(cookie.Selector, time.Now().UTC().Add(rememberMeRenewDuration))
		if err != nil {
			if err == errRememberMeNotFound {
				s.deleteRememberMeCookie()
			}
			return nil, newLoggedError("Unable to renew RememberMe", err)
		}
	}
	return rememberMe, nil
}

func (s *sessionStore) renewSession(sessionID, sessionHash string, renewTimeUTC, expireTimeUTC *time.Time) (*loginSession, error) {
	if renewTimeUTC.Before(time.Now().UTC()) && expireTimeUTC.After(time.Now().UTC()) {
		session, err := s.b.RenewSession(sessionHash, time.Now().UTC().Add(sessionRenewDuration))
		if err != nil {
			return nil, newLoggedError("Unable to renew session", err)
		}

		if err = s.saveSessionCookie(sessionID, session.RenewTimeUTC, session.ExpireTimeUTC); err != nil {
			return nil, err
		}
		return session, nil
	}

	_, err := s.getRememberMe()
	if err != nil {
		return nil, newAuthError("Unable to renew session", err)
	}

	session, err := s.b.RenewSession(sessionHash, time.Now().UTC().Add(sessionRenewDuration))
	if err != nil {
		if err == errSessionNotFound {
			s.deleteSessionCookie()
		}
		return nil, newLoggedError("Problem renewing session", err)
	}

	if err = s.saveSessionCookie(sessionID, session.RenewTimeUTC, session.ExpireTimeUTC); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *sessionStore) CreateSession(email string, rememberMe bool) (*loginSession, error) {
	var err error
	var selector, token, tokenHash string
	if rememberMe {
		selector, token, tokenHash, err = generateSelectorTokenAndHash()
		if err != nil {
			return nil, newLoggedError("Unable to generate RememberMe", err)
		}
	}
	sessionID, sessionHash, err := generateStringAndHash()
	if err != nil {
		return nil, newLoggedError("Problem generating sessionId", nil)
	}

	session, remember, err := s.b.CreateSession(email, sessionHash, time.Now().UTC().Add(sessionRenewDuration), time.Now().UTC().Add(sessionExpireDuration), rememberMe, selector, tokenHash, time.Now().UTC().Add(rememberMeRenewDuration), time.Now().UTC().Add(rememberMeExpireDuration))
	if err != nil {
		return nil, newLoggedError("Unable to create new session", err)
	}

	sessionCookie, err := s.getSessionCookie()
	if err == nil {
		oldSessionHash, err := decodeStringToHash(sessionCookie.SessionID)
		if err == nil {
			s.b.InvalidateSession(oldSessionHash)
		}
	}

	rememberCookie, err := s.getRememberMeCookie()
	if err == nil {
		s.b.InvalidateRememberMe(rememberCookie.Selector)
		s.deleteRememberMeCookie()
	}

	if rememberMe {
		err := s.saveRememberMeCookie(selector, token, remember.RenewTimeUTC, remember.ExpireTimeUTC)
		if err != nil {
			return nil, newAuthError("Unable to save rememberMe cookie", err)
		}
	}
	err = s.saveSessionCookie(sessionID, session.RenewTimeUTC, session.ExpireTimeUTC)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (s *sessionStore) getSessionCookie() (*sessionCookie, error) {
	session := &sessionCookie{}
	return session, s.cookieStore.Get(sessionCookieName, session)
}

func (s *sessionStore) getRememberMeCookie() (*rememberMeCookie, error) {
	rememberMe := &rememberMeCookie{}
	return rememberMe, s.cookieStore.Get(rememberMeCookieName, rememberMe)
}

func (s *sessionStore) deleteSessionCookie() {
	s.cookieStore.Delete(sessionCookieName)
}

func (s *sessionStore) deleteRememberMeCookie() {
	s.cookieStore.Delete(rememberMeCookieName)
}

func (s *sessionStore) saveSessionCookie(sessionID string, renewTimeUTC, expireTimeUTC time.Time) error {
	cookie := sessionCookie{SessionID: sessionID, RenewTimeUTC: renewTimeUTC, ExpireTimeUTC: expireTimeUTC}
	err := s.cookieStore.Put(sessionCookieName, &cookie)
	if err != nil {
		return newAuthError("Error saving session cookie", err)
	}
	return nil
}

func (s *sessionStore) saveRememberMeCookie(selector, token string, renewTimeUTC, expireTimeUTC time.Time) error {
	cookie := rememberMeCookie{Selector: selector, Token: token, RenewTimeUTC: renewTimeUTC, ExpireTimeUTC: expireTimeUTC}
	return s.cookieStore.Put(rememberMeCookieName, &cookie)
}
