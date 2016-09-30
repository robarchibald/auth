package main

import (
	"errors"
	"time"
)

type BackendQuerier interface {
	GetUserLogin(email, loginProvider string) (*UserLogin, error)
	NewLoginSession(loginId int, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*UserLoginSession, *UserLoginRememberMe, error)
	GetSession(sessionHash string) (*UserLoginSession, error)
	RenewSession(sessionHash string, renewTimeUTC time.Time) (*UserLoginSession, error)
	GetRememberMe(selector string) (*UserLoginRememberMe, error)
	RenewRememberMe(selector string, renewTimeUTC time.Time) (*UserLoginRememberMe, error)
	AddUser(email, emailVerifyHash string) error
	VerifyEmail(emailVerifyHash string) (string, error)
	UpdateUser(session *UserLoginSession, fullname string, company string, pictureUrl string) error
	CreateLogin(emailVerifyHash, passwordHash string, fullName string, company string, pictureUrl string, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time) (*UserLoginSession, error)
	UpdateEmailAndInvalidateSessions(email string, password string, newEmail string) (*UserLoginSession, error)
	UpdatePasswordAndInvalidateSessions(email string, oldPassword string, newPassword string) (*UserLoginSession, error)
	InvalidateSession(sessionHash string) error
	Close() error
}

var ErrEmailVerifyHashExists = errors.New("DB: Email verify hash already exists")
var ErrInvalidEmailVerifyHash = errors.New("DB: Invalid verify code")
var ErrInvalidRenewTimeUTC = errors.New("DB: Invalid RenewTimeUTC")
var ErrInvalidSessionHash = errors.New("DB: Invalid SessionHash")
var ErrRememberMeSelectorExists = errors.New("DB: RememberMe selector already exists")
var ErrUserNotFound = errors.New("DB: User not found")
var ErrLoginNotFound = errors.New("DB: Login not found")
var ErrSessionNotFound = errors.New("DB: Session not found")
var ErrRememberMeNotFound = errors.New("DB: RememberMe not found")
var ErrRememberMeNeedsRenew = errors.New("DB: RememberMe needs to be renewed")
var ErrRememberMeExpired = errors.New("DB: RememberMe is expired")
var ErrUserAlreadyExists = errors.New("DB: User already exists")

type User struct {
	UserId            int
	FullName          string
	PrimaryEmail      string
	EmailVerifyHash   string
	EmailVerified     bool
	LockoutEndTimeUTC *time.Time
	AccessFailedCount int
}

type UserLogin struct {
	LoginId         int
	UserId          int
	LoginProviderId int
	ProviderKey     string
}

type UserLoginSession struct {
	LoginId       int
	SessionHash   string
	UserId        int
	RenewTimeUTC  time.Time
	ExpireTimeUTC time.Time
}

type UserLoginRememberMe struct {
	LoginId       int
	Selector      string
	TokenHash     string
	RenewTimeUTC  time.Time
	ExpireTimeUTC time.Time
}

type UserLoginProvider struct {
	LoginProviderId   int
	Name              string
	OAuthClientId     string
	OAuthClientSecret string
	OAuthUrl          string
}

type AuthError struct {
	Message    string
	InnerError error
	ShouldLog  bool
	error
}

func NewLoggedError(message string, innerError error) *AuthError {
	return &AuthError{Message: message, InnerError: innerError, ShouldLog: true}
}

func NewAuthError(message string, innerError error) *AuthError {
	return &AuthError{Message: message, InnerError: innerError}
}

func (a *AuthError) Error() string {
	return a.Message
}

func (a *AuthError) Trace() string {
	trace := a.Message + "\n"
	indent := "  "
	inner := a.InnerError
	for inner != nil {
		trace += indent + inner.Error() + "\n"
		e, ok := inner.(*AuthError)
		if !ok {
			break
		}
		indent += "  "
		inner = e.InnerError
	}
	return trace
}
