package nginxauth

import (
	"errors"
	"time"
)

type BackendQuerier interface {
	GetUserLogin(email, loginProvider string) (*UserLogin, error)
	NewLoginSession(loginId int, sessionId string, sessionRenewsAt, sessionExpiresAt time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewsAt, rememberMeExpiresAt time.Time) (*UserLoginSession, *UserLoginRememberMe, error)
	GetSession(sessionId string) (*UserLoginSession, error)
	RenewSession(sessionId string, renewsAt time.Time) (*UserLoginSession, error)
	GetRememberMe(selector string) (*UserLoginRememberMe, error)
	RenewRememberMe(selector string, renewsAt time.Time) (*UserLoginRememberMe, error)
	AddUser(email, emailVerifyHash, sessionId string, sessionRenewsAt, sessionExpiresAt time.Time) (*UserLoginSession, error)
	VerifyEmail(emailVerifyCode, sessionId string, sessionRenewsAt, sessionExpiresAt time.Time) (*UserLoginSession, string, error)
	UpdateUser(session *UserLoginSession, fullname string, company string, pictureUrl string) error
	CreateProfileAndInvalidateSessions(loginId int, passwordHash string, fullName string, company string, pictureUrl string, sessionId string, sessionExpiresAt, sessionRenewsAt time.Time) (*UserLoginSession, error)
	UpdateEmailAndInvalidateSessions(email string, password string, newEmail string) (*UserLoginSession, error)
	UpdatePasswordAndInvalidateSessions(email string, oldPassword string, newPassword string) (*UserLoginSession, error)
	InvalidateUserSessions(userId int) error
}

var ErrEmailVerifyCodeExists = errors.New("DB: Email verify hash already exists")
var ErrInvalidEmailVerifyCode = errors.New("DB: Invalid verify code")
var ErrInvalidRenewsAtTime = errors.New("DB: Invalid RenewsAt time")
var ErrInvalidSessionId = errors.New("DB: Invalid SessionId")
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
	LockoutEndDateUtc *time.Time
	AccessFailedCount int
}

type UserLogin struct {
	LoginId         int
	UserId          int
	LoginProviderId int
	ProviderKey     string
}

type UserLoginSession struct {
	LoginId    int
	SessionId  string
	UserId     int
	ExpiresAt  time.Time
	RenewsAt   time.Time
	IsHalfAuth bool
}

type UserLoginRememberMe struct {
	LoginId   int
	Selector  string
	TokenHash string
	ExpiresAt time.Time
	RenewsAt  time.Time
}

type UserLoginProvider struct {
	LoginProviderId int
	Name            string
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
