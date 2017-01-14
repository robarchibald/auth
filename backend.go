package main

import (
	"errors"
	"time"
)

type Backender interface {
	UserBackender
	LoginBackender
	SessionBackender
	BackendCloser
}

type BackendCloser interface {
	Close() error
}

type UserBackender interface {
	AddUser(email, emailVerifyHash string) error
	VerifyEmail(emailVerifyHash string) (string, error)
	UpdateUser(emailVerifyHash, fullname string, company string, pictureURL string) (string, error)
}

type LoginBackender interface {
	CreateLogin(email, passwordHash, fullName, homeDirectory string, uidNumber, gidNumber int) (*UserLogin, error)
	GetLogin(email, loginProvider string) (*UserLogin, error)
	UpdateEmail(email string, password string, newEmail string) (*UserLoginSession, error)
	UpdatePassword(email string, oldPassword string, newPassword string) (*UserLoginSession, error)
}

type SessionBackender interface {
	CreateSession(loginID, userID int, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*UserLoginSession, *UserLoginRememberMe, error)
	GetSession(sessionHash string) (*UserLoginSession, error)
	RenewSession(sessionHash string, renewTimeUTC time.Time) (*UserLoginSession, error)
	InvalidateSession(sessionHash string) error
	InvalidateSessions(email string) error

	GetRememberMe(selector string) (*UserLoginRememberMe, error)
	RenewRememberMe(selector string, renewTimeUTC time.Time) (*UserLoginRememberMe, error)
	InvalidateRememberMe(selector string) error
}

var errEmailVerifyHashExists = errors.New("DB: Email verify hash already exists")
var errInvalidEmailVerifyHash = errors.New("DB: Invalid verify code")
var errInvalidRenewTimeUTC = errors.New("DB: Invalid RenewTimeUTC")
var errInvalidSessionHash = errors.New("DB: Invalid SessionHash")
var errRememberMeSelectorExists = errors.New("DB: RememberMe selector already exists")
var errUserNotFound = errors.New("DB: User not found")
var errLoginNotFound = errors.New("DB: Login not found")
var errSessionNotFound = errors.New("DB: Session not found")
var errRememberMeNotFound = errors.New("DB: RememberMe not found")
var errRememberMeNeedsRenew = errors.New("DB: RememberMe needs to be renewed")
var errRememberMeExpired = errors.New("DB: RememberMe is expired")
var errUserAlreadyExists = errors.New("DB: User already exists")

type User struct {
	UserID            int
	FullName          string
	PrimaryEmail      string
	EmailVerifyHash   string
	EmailVerified     bool
	LockoutEndTimeUTC *time.Time
	AccessFailedCount int
}

type UserLogin struct {
	LoginID         int
	UserID          int
	LoginProviderID int
	ProviderKey     string
}

type UserLoginSession struct {
	LoginID       int
	SessionHash   string
	UserID        int
	RenewTimeUTC  time.Time
	ExpireTimeUTC time.Time
}

type UserLoginRememberMe struct {
	LoginID       int
	Selector      string
	TokenHash     string
	RenewTimeUTC  time.Time
	ExpireTimeUTC time.Time
}

type UserLoginProvider struct {
	LoginProviderID   int
	Name              string
	OAuthClientID     string
	OAuthClientSecret string
	OAuthURL          string
}

type AuthError struct {
	message    string
	innerError error
	shouldLog  bool
	error
}

func newLoggedError(message string, innerError error) *AuthError {
	return &AuthError{message: message, innerError: innerError, shouldLog: true}
}

func newAuthError(message string, innerError error) *AuthError {
	return &AuthError{message: message, innerError: innerError}
}

func (a *AuthError) Error() string {
	return a.message
}

func (a *AuthError) Trace() string {
	trace := a.message + "\n"
	indent := "  "
	inner := a.innerError
	for inner != nil {
		trace += indent + inner.Error() + "\n"
		e, ok := inner.(*AuthError)
		if !ok {
			break
		}
		indent += "  "
		inner = e.innerError
	}
	return trace
}
