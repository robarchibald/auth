package main

import (
	"errors"
	"testing"
	"time"
)

func TestAuthError(t *testing.T) {
	e3 := NewAuthError("error 3", errors.New("other"))
	e2 := NewAuthError("error 2", e3)
	e1 := NewAuthError("error 1", e2)
	if e1.Message != "error 1" || e2.Message != "error 2" || e1.Error() != e1.Message || e2.Error() != e2.Message ||
		e1.Trace() != "error 1\n  error 2\n    error 3\n      other\n" ||
		e2.Trace() != "error 2\n  error 3\n    other\n" ||
		e3.Trace() != "error 3\n  other\n" {
		t.Error("expected valid error structs", e1, e2, e3, e1.Trace(), e2.Trace(), e3.Trace())
	}
}

/***********************************************************************/

type SessionReturn struct {
	Session *UserLoginSession
	Err     error
}

type SessionRememberReturn struct {
	Session    *UserLoginSession
	RememberMe *UserLoginRememberMe
	Err        error
}

type RememberMeReturn struct {
	RememberMe *UserLoginRememberMe
	Err        error
}

type VerifyEmailReturn struct {
	Email string
	Err   error
}

type MockBackend struct {
	BackendQuerier
	LoginReturn                               *UserLogin
	ExpirationReturn                          *time.Time
	GetSessionReturn                          *SessionReturn
	NewSessionReturn                          *SessionRememberReturn
	RenewSessionReturn                        *SessionReturn
	AddUserReturn                             error
	VerifyEmailReturn                         *VerifyEmailReturn
	CreateLoginReturn                         *SessionReturn
	UpdateEmailAndInvalidateSessionsReturn    *SessionReturn
	UpdatePasswordAndInvalidateSessionsReturn *SessionReturn
	GetRememberMeReturn                       *RememberMeReturn
	RenewRememberMeReturn                     *RememberMeReturn
	RememberMeReturn                          *RememberMeReturn
	ErrReturn                                 error
	MethodsCalled                             []string
}

func (b *MockBackend) GetUserLogin(email, loginProvider string) (*UserLogin, error) {
	b.MethodsCalled = append(b.MethodsCalled, "GetUserLogin")
	return b.LoginReturn, b.ErrReturn
}
func (b *MockBackend) GetSession(sessionHash string) (*UserLoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "GetSession")
	return b.GetSessionReturn.Session, b.GetSessionReturn.Err
}
func (b *MockBackend) NewLoginSession(loginId int, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*UserLoginSession, *UserLoginRememberMe, error) {
	b.MethodsCalled = append(b.MethodsCalled, "NewSession")
	return b.NewSessionReturn.Session, b.NewSessionReturn.RememberMe, b.NewSessionReturn.Err
}
func (b *MockBackend) RenewSession(sessionHash string, renewTimeUTC time.Time) (*UserLoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "RenewSession")
	return b.RenewSessionReturn.Session, b.RenewSessionReturn.Err
}
func (b *MockBackend) GetRememberMe(selector string) (*UserLoginRememberMe, error) {
	b.MethodsCalled = append(b.MethodsCalled, "GetRememberMe")
	return b.GetRememberMeReturn.RememberMe, b.GetRememberMeReturn.Err
}
func (b *MockBackend) RenewRememberMe(selector string, renewTimeUTC time.Time) (*UserLoginRememberMe, error) {
	b.MethodsCalled = append(b.MethodsCalled, "RenewRememberMe")
	return b.RenewRememberMeReturn.RememberMe, b.RenewRememberMeReturn.Err
}
func (b *MockBackend) AddUser(email, emailVerifyHash string) error {
	b.MethodsCalled = append(b.MethodsCalled, "AddUser")
	return b.AddUserReturn
}

func (b *MockBackend) VerifyEmail(emailVerifyHash string) (string, error) {
	b.MethodsCalled = append(b.MethodsCalled, "VerifyEmail")
	return b.VerifyEmailReturn.Email, b.VerifyEmailReturn.Err
}

func (b *MockBackend) UpdateUser(session *UserLoginSession, fullname string, company string, pictureUrl string) error {
	b.MethodsCalled = append(b.MethodsCalled, "UpdateUser")
	return b.ErrReturn
}

func (b *MockBackend) CreateLogin(email string, passwordHash string, fullName string, company string, pictureUrl string, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time) (*UserLoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "CreateLogin")
	return b.CreateLoginReturn.Session, b.CreateLoginReturn.Err
}

func (b *MockBackend) UpdateEmailAndInvalidateSessions(email string, password string, newEmail string) (*UserLoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "UpdateEmailAndInvalidateSessions")
	return b.UpdateEmailAndInvalidateSessionsReturn.Session, b.UpdateEmailAndInvalidateSessionsReturn.Err
}

func (b *MockBackend) UpdatePasswordAndInvalidateSessions(email string, oldPassword string, newPassword string) (*UserLoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "UpdatePasswordAndInvalidateSessions")
	return b.UpdatePasswordAndInvalidateSessionsReturn.Session, b.UpdatePasswordAndInvalidateSessionsReturn.Err
}

func (b *MockBackend) InvalidateSession(sessionHash string) error {
	b.MethodsCalled = append(b.MethodsCalled, "InvalidateSession")
	return b.ErrReturn
}

func session(renewTimeUTC, expireTimeUTC time.Time) *SessionReturn {
	return &SessionReturn{&UserLoginSession{1, "sessionHash", 2, renewTimeUTC, expireTimeUTC}, nil}
}

func sessionErr() *SessionReturn {
	return &SessionReturn{&UserLoginSession{}, errors.New("failed")}
}

func rememberMe(renewTimeUTC, expireTimeUTC time.Time) *RememberMeReturn { // hash of the word "token"
	return &RememberMeReturn{&UserLoginRememberMe{TokenHash: "PEaenWxYddN6Q_NT1PiOYfz4EsZu7jRXRlpAsNpBU-A=", ExpireTimeUTC: expireTimeUTC, RenewTimeUTC: renewTimeUTC}, nil}
}

func rememberErr() *RememberMeReturn {
	return &RememberMeReturn{&UserLoginRememberMe{}, errors.New("failed")}
}

func sessionRemember(renewTimeUTC, expireTimeUTC time.Time) *SessionRememberReturn {
	return &SessionRememberReturn{&UserLoginSession{1, "sessionHash", 2, renewTimeUTC, expireTimeUTC}, &UserLoginRememberMe{TokenHash: "PEaenWxYddN6Q_NT1PiOYfz4EsZu7jRXRlpAsNpBU-A=", ExpireTimeUTC: expireTimeUTC, RenewTimeUTC: renewTimeUTC}, nil}
}

func sessionRememberErr() *SessionRememberReturn {
	return &SessionRememberReturn{nil, nil, errors.New("failed")}
}

func verifyEmailSuccess() *VerifyEmailReturn {
	return &VerifyEmailReturn{"email", nil}
}
func verifyEmailErr() *VerifyEmailReturn {
	return &VerifyEmailReturn{"", errors.New("failed")}
}
