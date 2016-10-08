package main

import (
	"net/http"
	"time"
)

type SessionStorer interface {
	GetSession() (*UserLoginSession, error)
	CreateSession(loginId, userId int, rememberMe bool) (*UserLoginSession, error)
}

type SessionCookie struct {
	SessionId     string
	RenewTimeUTC  time.Time
	ExpireTimeUTC time.Time
}

type RememberMeCookie struct {
	Selector      string
	Token         string
	RenewTimeUTC  time.Time
	ExpireTimeUTC time.Time
}

type SessionStore struct {
	backend     BackendQuerier
	cookieStore CookieStorer
	r           *http.Request
}

func NewSessionStore(backend BackendQuerier, w http.ResponseWriter, r *http.Request, cookieKey []byte, cookiePrefix string, secureOnlyCookie bool) *SessionStore {
	emailCookieName = cookiePrefix + "Email"
	sessionCookieName = cookiePrefix + "Session"
	rememberMeCookieName = cookiePrefix + "RememberMe"
	return &SessionStore{backend, NewCookieStore(w, r, cookieKey, secureOnlyCookie), r}
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

func (s *SessionStore) GetSession() (*UserLoginSession, error) {
	cookie, err := s.getSessionCookie()
	if err != nil || cookie.SessionId == "" { // impossible to get the session if there is no cookie
		return nil, NewAuthError("Session cookie not found", err)
	}
	sessionHash, err := decodeStringToHash(cookie.SessionId)
	if err != nil {
		return nil, NewAuthError("Unable to decode session cookie", err)
	}

	if cookie.RenewTimeUTC.Before(time.Now().UTC()) || cookie.ExpireTimeUTC.Before(time.Now().UTC()) {
		return s.renewSession(cookie.SessionId, sessionHash, &cookie.RenewTimeUTC, &cookie.ExpireTimeUTC)
	}

	session, err := s.backend.GetSession(sessionHash)
	if err != nil {
		if err == ErrSessionNotFound {
			s.deleteSessionCookie()
		}
		return nil, NewLoggedError("Failed to verify session", err)
	}
	return session, nil
}

func (s *SessionStore) getRememberMe() (*UserLoginRememberMe, error) {
	cookie, err := s.getRememberMeCookie()
	if err != nil || cookie.Selector == "" { // impossible to get the remember Me if there is no cookie
		return nil, NewAuthError("RememberMe cookie not found", err)
	}
	if cookie.ExpireTimeUTC.Before(time.Now().UTC()) {
		s.deleteRememberMeCookie()
		return nil, NewAuthError("RememberMe cookie has expired", nil)
	}

	rememberMe, err := s.backend.GetRememberMe(cookie.Selector)
	if err != nil {
		if err == ErrRememberMeNotFound {
			s.deleteRememberMeCookie()
		}
		return nil, NewLoggedError("Unable to find matching RememberMe in DB", err)
	}
	if !encodedHashEquals(cookie.Token, rememberMe.TokenHash) {
		s.deleteRememberMeCookie()
		return nil, NewLoggedError("RememberMe cookie doesn't match backend token", nil)
	}
	if rememberMe.RenewTimeUTC.Before(time.Now().UTC()) {
		rememberMe, err = s.backend.RenewRememberMe(cookie.Selector, time.Now().UTC().Add(rememberMeRenewDuration))
		if err != nil {
			if err == ErrRememberMeNotFound {
				s.deleteRememberMeCookie()
			}
			return nil, NewLoggedError("Unable to renew RememberMe", err)
		}
	}
	return rememberMe, nil
}

func (s *SessionStore) renewSession(sessionID, sessionHash string, renewTimeUTC, expireTimeUTC *time.Time) (*UserLoginSession, error) {
	if renewTimeUTC.Before(time.Now().UTC()) && expireTimeUTC.After(time.Now().UTC()) {
		session, err := s.backend.RenewSession(sessionHash, time.Now().UTC().Add(sessionRenewDuration))
		if err != nil {
			return nil, NewLoggedError("Unable to renew session", err)
		}

		if err = s.saveSessionCookie(sessionID, session.RenewTimeUTC, session.ExpireTimeUTC); err != nil {
			return nil, err
		}
		return session, nil
	}

	_, err := s.getRememberMe()
	if err != nil {
		return nil, NewAuthError("Unable to renew session", err)
	}

	session, err := s.backend.RenewSession(sessionHash, time.Now().UTC().Add(sessionRenewDuration))
	if err != nil {
		if err == ErrSessionNotFound {
			s.deleteSessionCookie()
		}
		return nil, NewLoggedError("Problem renewing session", err)
	}

	if err = s.saveSessionCookie(sessionID, session.RenewTimeUTC, session.ExpireTimeUTC); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *SessionStore) CreateSession(loginId, userId int, rememberMe bool) (*UserLoginSession, error) {
	var err error
	var selector, token, tokenHash string
	if rememberMe {
		selector, token, tokenHash, err = generateSelectorTokenAndHash()
		if err != nil {
			return nil, NewLoggedError("Unable to generate RememberMe", err)
		}
	}
	sessionId, sessionHash, err := generateStringAndHash()
	if err != nil {
		return nil, NewLoggedError("Problem generating sessionId", nil)
	}

	session, remember, err := s.backend.NewLoginSession(loginId, userId, sessionHash, time.Now().UTC().Add(sessionRenewDuration), time.Now().UTC().Add(sessionExpireDuration), rememberMe, selector, tokenHash, time.Now().UTC().Add(rememberMeRenewDuration), time.Now().UTC().Add(rememberMeExpireDuration))
	if err != nil {
		return nil, NewLoggedError("Unable to create new session", err)
	}

	sessionCookie, err := s.getSessionCookie()
	if err == nil {
		oldSessionHash, err := decodeStringToHash(sessionCookie.SessionId)
		if err == nil {
			s.backend.InvalidateSession(oldSessionHash)
		}
	}

	rememberCookie, err := s.getRememberMeCookie()
	if err == nil {
		s.backend.InvalidateRememberMe(rememberCookie.Selector)
		s.deleteRememberMeCookie()
	}

	if rememberMe {
		err := s.saveRememberMeCookie(selector, token, remember.RenewTimeUTC, remember.ExpireTimeUTC)
		if err != nil {
			return nil, NewAuthError("Unable to save rememberMe cookie", err)
		}
	}
	err = s.saveSessionCookie(sessionId, session.RenewTimeUTC, session.ExpireTimeUTC)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (s *SessionStore) getSessionCookie() (*SessionCookie, error) {
	session := &SessionCookie{}
	return session, s.cookieStore.Get(sessionCookieName, session)
}

func (s *SessionStore) getRememberMeCookie() (*RememberMeCookie, error) {
	rememberMe := &RememberMeCookie{}
	return rememberMe, s.cookieStore.Get(rememberMeCookieName, rememberMe)
}

func (s *SessionStore) deleteSessionCookie() {
	s.cookieStore.Delete(sessionCookieName)
}

func (s *SessionStore) deleteRememberMeCookie() {
	s.cookieStore.Delete(rememberMeCookieName)
}

func (s *SessionStore) saveSessionCookie(sessionId string, renewTimeUTC, expireTimeUTC time.Time) error {
	cookie := SessionCookie{SessionId: sessionId, RenewTimeUTC: renewTimeUTC, ExpireTimeUTC: expireTimeUTC}
	err := s.cookieStore.Put(sessionCookieName, &cookie)
	if err != nil {
		return NewAuthError("Error saving session cookie", err)
	}
	return nil
}

func (s *SessionStore) saveRememberMeCookie(selector, token string, renewTimeUTC, expireTimeUTC time.Time) error {
	cookie := RememberMeCookie{Selector: selector, Token: token, RenewTimeUTC: renewTimeUTC, ExpireTimeUTC: expireTimeUTC}
	return s.cookieStore.Put(rememberMeCookieName, &cookie)
}
