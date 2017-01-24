package main

import (
	"errors"
	"time"
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

type backender interface {
	// UserBackender. Write out since it contains duplicate BackendCloser
	AddUser(email string) (int, error)
	GetUser(email string) (*user, error)
	UpdateUser(email, fullname string, company string, pictureURL string) error

	// LoginBackender. Write out since it contains duplicate BackendCloser
	CreateLogin(userID, dbUserID int, email, passwordHash, fullName, homeDirectory string, uidNumber, gidNumber int, mailQuota, fileQuota string) (*userLogin, error)
	Login(email, password string) (*userLogin, error)
	UpdateEmail(email string, password string, newEmail string) (*loginSession, error)
	UpdatePassword(email string, oldPassword string, newPassword string) (*loginSession, error)

	sessionBackender
}

type backendCloser interface {
	Close() error
}

type userBackender interface {
	AddUser(email string) (int, error)
	GetUser(email string) (*user, error)
	UpdateUser(email, fullname string, company string, pictureURL string) error
	backendCloser
}

type loginBackender interface {
	CreateLogin(userID, dbUserID int, email, passwordHash, fullName, homeDirectory string, uidNumber, gidNumber int, mailQuota, fileQuota string) (*userLogin, error)
	Login(email, password string) (*userLogin, error)
	UpdateEmail(email string, password string, newEmail string) (*loginSession, error)
	UpdatePassword(email string, oldPassword string, newPassword string) (*loginSession, error)
	backendCloser
}

type sessionBackender interface {
	CreateEmailSession(email, emailVerifyHash string) error
	GetEmailSession(verifyHash string) (*emailSession, error)
	UpdateEmailSession(verifyHash string, userID int, email string) error
	DeleteEmailSession(verifyHash string) error

	CreateSession(userID int, email, fullname, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*loginSession, *rememberMeSession, error)
	GetSession(sessionHash string) (*loginSession, error)
	RenewSession(sessionHash string, renewTimeUTC time.Time) (*loginSession, error)
	InvalidateSession(sessionHash string) error
	InvalidateSessions(email string) error

	GetRememberMe(selector string) (*rememberMeSession, error)
	RenewRememberMe(selector string, renewTimeUTC time.Time) (*rememberMeSession, error)
	InvalidateRememberMe(selector string) error
	backendCloser
}

type emailSession struct {
	UserID          int
	Email           string
	EmailVerifyHash string
}

type user struct {
	UserID            int
	FullName          string
	PrimaryEmail      string
	LockoutEndTimeUTC *time.Time
	AccessFailedCount int
}

type userLogin struct {
	UserID   int
	Email    string
	FullName string
}

type loginSession struct {
	UserID        int
	Email         string
	FullName      string
	SessionHash   string
	RenewTimeUTC  time.Time
	ExpireTimeUTC time.Time
}

type rememberMeSession struct {
	UserID        int
	Email         string
	Selector      string
	TokenHash     string
	RenewTimeUTC  time.Time
	ExpireTimeUTC time.Time
}

type loginProvider struct {
	LoginProviderID   int
	Name              string
	OAuthClientID     string
	OAuthClientSecret string
	OAuthURL          string
}

type authError struct {
	message    string
	innerError error
	shouldLog  bool
	error
}

func newLoggedError(message string, innerError error) *authError {
	return &authError{message: message, innerError: innerError, shouldLog: true}
}

func newAuthError(message string, innerError error) *authError {
	return &authError{message: message, innerError: innerError}
}

func (a *authError) Error() string {
	return a.message
}

func (a *authError) Trace() string {
	trace := a.message + "\n"
	indent := "  "
	inner := a.innerError
	for inner != nil {
		trace += indent + inner.Error() + "\n"
		e, ok := inner.(*authError)
		if !ok {
			break
		}
		indent += "  "
		inner = e.innerError
	}
	return trace
}

type backend struct {
	u userBackender
	l loginBackender
	s sessionBackender
	backendCloser
}

func (b *backend) Login(email, password string) (*userLogin, error) {
	return b.l.Login(email, password)
}

func (b *backend) CreateSession(userID int, email, fullname, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*loginSession, *rememberMeSession, error) {
	return b.s.CreateSession(userID, email, fullname, sessionHash, sessionRenewTimeUTC, sessionExpireTimeUTC, rememberMe, rememberMeSelector, rememberMeTokenHash, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC)
}

func (b *backend) GetSession(sessionHash string) (*loginSession, error) {
	return b.s.GetSession(sessionHash)
}

func (b *backend) RenewSession(sessionHash string, renewTimeUTC time.Time) (*loginSession, error) {
	return b.s.RenewSession(sessionHash, renewTimeUTC)
}

func (b *backend) GetRememberMe(selector string) (*rememberMeSession, error) {
	return b.s.GetRememberMe(selector)
}

func (b *backend) RenewRememberMe(selector string, renewTimeUTC time.Time) (*rememberMeSession, error) {
	return b.s.RenewRememberMe(selector, renewTimeUTC)
}

func (b *backend) CreateEmailSession(email, emailVerifyHash string) error {
	return b.s.CreateEmailSession(email, emailVerifyHash)
}

func (b *backend) GetEmailSession(emailVerifyHash string) (*emailSession, error) {
	return b.s.GetEmailSession(emailVerifyHash)
}

func (b *backend) UpdateEmailSession(emailVerifyHash string, userID int, email string) error {
	return b.s.UpdateEmailSession(emailVerifyHash, userID, email)
}

func (b *backend) DeleteEmailSession(emailVerifyHash string) error {
	return b.s.DeleteEmailSession(emailVerifyHash)
}

func (b *backend) AddUser(email string) (int, error) {
	return b.u.AddUser(email)
}

func (b *backend) GetUser(email string) (*user, error) {
	return b.u.GetUser(email)
}

func (b *backend) UpdateUser(email, fullname string, company string, pictureURL string) error {
	return b.u.UpdateUser(email, fullname, company, pictureURL)
}

func (b *backend) CreateLogin(userID, dbUserID int, email, passwordHash, fullName, homeDirectory string, uidNumber, gidNumber int, mailQuota, fileQuota string) (*userLogin, error) {
	return b.l.CreateLogin(userID, dbUserID, email, passwordHash, fullName, homeDirectory, uidNumber, gidNumber, mailQuota, fileQuota)
}

func (b *backend) UpdateEmail(email string, password string, newEmail string) (*loginSession, error) {
	return b.l.UpdateEmail(email, password, newEmail)
}

func (b *backend) UpdatePassword(email string, oldPassword string, newPassword string) (*loginSession, error) {
	return b.l.UpdatePassword(email, oldPassword, newPassword)
}

func (b *backend) InvalidateSession(sessionHash string) error {
	return b.s.InvalidateSession(sessionHash)
}

func (b *backend) InvalidateSessions(email string) error {
	return b.s.InvalidateSessions(email)
}

func (b *backend) InvalidateRememberMe(selector string) error {
	return b.s.InvalidateRememberMe(selector)
}

func (b *backend) Close() error {
	if err := b.s.Close(); err != nil {
		return err
	}
	if err := b.u.Close(); err != nil {
		return err
	}
	if err := b.l.Close(); err != nil {
		return err
	}
	return nil
}
