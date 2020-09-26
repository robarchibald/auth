package auth

import (
	"fmt"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

var errEmailVerifyHashExists = errors.New("DB: Email verify hash already exists")
var errInvalidEmailVerifyHash = errors.New("DB: Invalid verify code")
var errInvalidRenewTimeUTC = errors.New("DB: Invalid RenewTimeUTC")
var errInvalidSessionHash = errors.New("DB: Invalid SessionHash")
var errRememberMeSelectorExists = errors.New("DB: RememberMe selector already exists")
var errUserNotFound = errors.New("DB: User not found")
var errLoginNotFound = errors.New("DB: Login not found")
var errInvalidCredentials = errors.New("DB: Invalid Credentials")
var errSessionNotFound = errors.New("DB: Session not found")
var errSessionAlreadyExists = errors.New("DB: Session already exists")
var errRememberMeNotFound = errors.New("DB: RememberMe not found")
var errRememberMeNeedsRenew = errors.New("DB: RememberMe needs to be renewed")
var errRememberMeExpired = errors.New("DB: RememberMe is expired")
var errUserAlreadyExists = errors.New("DB: User already exists")

// Backender interface contains all the methods needed to read and write users, sessions and logins
type Backender interface {
	userBackender
	sessionBackender
	backendCloser
	Clone() Backender
}

type backendCloser interface {
	Close() error
}

// UserBackender interface holds methods for user management
type UserBackender interface {
	userBackender
	backendCloser
}

type userBackender interface {
	AddVerifiedUser(email string, info map[string]interface{}) (string, error)
	AddUserFull(email, password string, info map[string]interface{}) (*User, error)
	GetUser(email string) (*User, error)
	UpdateUser(userID, password string, info map[string]interface{}) error
	UpdateInfo(userID string, info map[string]interface{}) error
	UpdatePassword(userID, newPassword string) error
	VerifyEmail(email string) error

	Login(email, password string) error
	LoginAndGetUser(email, password string) (*User, error)
	AddSecondaryEmail(userID, secondaryEmail string) error
	UpdatePrimaryEmail(userID, newPrimaryEmail string) error
}

// SessionBackender interface holds methods for session management
type SessionBackender interface {
	sessionBackender
	backendCloser
}

type sessionBackender interface {
	CreateEmailSession(userID, email string, info map[string]interface{}, emailVerifyHash, csrfToken string) error
	GetEmailSession(verifyHash string) (*emailSession, error)
	UpdateEmailSession(verifyHash string, userID string) error
	DeleteEmailSession(verifyHash string) error

	CreateSession(userID, email string, info map[string]interface{}, sessionHash, csrfToken string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time) (*LoginSession, error)
	GetSession(sessionHash string) (*LoginSession, error)
	UpdateSession(sessionHash string, renewTimeUTC, expireTimeUTC time.Time) error
	DeleteSession(sessionHash string) error
	InvalidateSessions(email string) error
	DeleteSessions(email string) error

	CreateRememberMe(userID, email string, rememberMeSelector, rememberMeTokenHash string, renewTimeUTC, expireTimeUTC time.Time) (*rememberMeSession, error)
	GetRememberMe(selector string) (*rememberMeSession, error)
	UpdateRememberMe(selector string, renewTimeUTC time.Time) error
	DeleteRememberMe(selector string) error
	DeleteRememberMes(email string) error
}

type emailSession struct {
	UserID          string                 `bson:"userID"    json:"userID"`
	Email           string                 `bson:"email"     json:"email"`
	Info            map[string]interface{} `bson:"info"      json:"info"`
	EmailVerifyHash string                 `bson:"_id"       json:"emailVerifyHash"`
	CSRFToken       string                 `bson:"csrfToken" json:"csrfToken"`
}

type user struct {
	UserID            string
	PrimaryEmail      string
	PasswordHash      string
	IsEmailVerified   bool
	Info              map[string]interface{}
	LockoutEndTimeUTC *time.Time
	AccessFailedCount int
}

// User is the struct which holds user information
type User struct {
	UserID          string                 `json:"userID"`
	Email           string                 `json:"email"`
	IsEmailVerified bool                   `json:"isEmailVerified"`
	Info            map[string]interface{} `json:"info"`
}

// LoginSession is the struct which holds session information
type LoginSession struct {
	UserID        string                 `bson:"userID"        json:"userID"`
	Email         string                 `bson:"email"         json:"email"`
	Info          map[string]interface{} `bson:"info"          json:"info"`
	SessionHash   string                 `bson:"_id"           json:"sessionHash"`
	CSRFToken     string                 `bson:"csrfToken"     json:"csrfToken"`
	RenewTimeUTC  time.Time              `bson:"renewTimeUTC"  json:"renewTimeUTC"`
	ExpireTimeUTC time.Time              `bson:"expireTimeUTC" json:"expireTimeUTC"`
}

// GetInfo will return the named info as an interface{}
func (l *LoginSession) GetInfo(name string) interface{} {
	if l == nil {
		return nil
	}
	return GetInfo(l.Info, name)
}

// GetInfoString will return the named info as a string
func (l *LoginSession) GetInfoString(name string) string {
	if l == nil {
		return ""
	}
	return GetInfoString(l.Info, name)
}

// GetInfoStrings will return the named info as an array of strings
func (l *LoginSession) GetInfoStrings(name string) []string {
	if l == nil {
		return nil
	}
	return GetInfoStrings(l.Info, name)
}

// GetInfoInts will return the named info as an array of integers
func (l *LoginSession) GetInfoInts(name string) []int {
	if l == nil {
		return nil
	}
	return GetInfoInts(l.Info, name)
}

// GetInfo will return the named info as an interface{}
func (u *User) GetInfo(name string) interface{} {
	if u == nil {
		return nil
	}
	return GetInfo(u.Info, name)
}

// GetInfoString will return the named info as a string
func (u *User) GetInfoString(name string) string {
	if u == nil {
		return ""
	}
	return GetInfoString(u.Info, name)
}

// GetInfoStrings will return the named info as an array of strings
func (u *User) GetInfoStrings(name string) []string {
	if u == nil {
		return nil
	}
	return GetInfoStrings(u.Info, name)
}

// GetInfoInts will return the named info as an array of integers
func (u *User) GetInfoInts(name string) []int {
	if u == nil {
		return nil
	}
	return GetInfoInts(u.Info, name)
}

// GetInfo will return the named info as an interface{}
func GetInfo(info map[string]interface{}, name string) interface{} {
	if info == nil {
		return nil
	}
	return info[name]
}

// GetInfoString will return the named info as a string
func GetInfoString(info map[string]interface{}, name string) string {
	v := GetInfo(info, name)
	if v == nil {
		return ""
	}
	if i, ok := v.(string); ok {
		return i
	}
	return fmt.Sprint(v)
}

// GetInfoStrings will return the named info as an array of strings
func GetInfoStrings(info map[string]interface{}, name string) []string {
	i := GetInfo(info, name)
	switch v := i.(type) {
	case []string:
		return v
	case []interface{}:
		strArr := make([]string, len(v))
		for i, str := range v {
			if s, ok := str.(string); ok {
				strArr[i] = s
			} else {
				strArr[i] = fmt.Sprint(str)
			}
		}
		return strArr
	}
	return nil
}

// GetInfoInts will return the named info as an array of integers
func GetInfoInts(info map[string]interface{}, name string) []int {
	i := GetInfo(info, name)
	switch v := i.(type) {
	case []int:
		return v
	case []interface{}:
		var intArr []int
		for _, str := range v {
			if s, ok := str.(int); ok {
				intArr = append(intArr, s)
			} else {
				toInt, err := strconv.Atoi(fmt.Sprint(str))
				if err != nil {
					continue
				}
				intArr = append(intArr, toInt)
			}
		}
		return intArr
	}
	return nil
}

type rememberMeSession struct {
	UserID        string    `bson:"userID"        json:"userID"`
	Email         string    `bson:"email"         json:"email"`
	Selector      string    `bson:"_id"           json:"selector"`
	TokenHash     string    `bson:"tokenHash"     json:"tokenHash"`
	RenewTimeUTC  time.Time `bson:"renewTimeUTC"  json:"renewTimeUTC"`
	ExpireTimeUTC time.Time `bson:"expireTimeUTC" json:"expireTimeUTC"`
}

type loginProvider struct {
	LoginProviderID   int
	Name              string
	OAuthClientID     string
	OAuthClientSecret string
	OAuthURL          string
}

// AuthError struct holds detailed auth error info
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

type backend struct {
	UserBackender
	SessionBackender
	backendCloser
}

// NewBackend returns a Backender from a UserBackender, LoginBackender and SessionBackender
func NewBackend(u UserBackender, s SessionBackender) Backender {
	return &backend{UserBackender: u, SessionBackender: s}
}

func (b *backend) Clone() Backender {
	return b
}

func (b *backend) Close() error {
	if err := b.SessionBackender.Close(); err != nil {
		return err
	}
	return b.UserBackender.Close()
}
