package main

import (
	"errors"
	"testing"
	"time"
)

func TestAuthError(t *testing.T) {
	e3 := newAuthError("error 3", errors.New("other"))
	e2 := newAuthError("error 2", e3)
	e1 := newAuthError("error 1", e2)
	if e1.message != "error 1" || e2.message != "error 2" || e1.Error() != e1.message || e2.Error() != e2.message ||
		e1.Trace() != "error 1\n  error 2\n    error 3\n      other\n" ||
		e2.Trace() != "error 2\n  error 3\n    other\n" ||
		e3.Trace() != "error 3\n  other\n" {
		t.Error("expected valid error structs", e1, e2, e3, e1.Trace(), e2.Trace(), e3.Trace())
	}
}

/***********************************************************************/

type LoginReturn struct {
	Login *UserLogin
	Err   error
}

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
	GetUserLoginReturn                        *LoginReturn
	ExpirationReturn                          *time.Time
	GetSessionReturn                          *SessionReturn
	NewLoginSessionReturn                     *SessionRememberReturn
	RenewSessionReturn                        *SessionReturn
	AddUserReturn                             error
	VerifyEmailReturn                         *VerifyEmailReturn
	CreateLoginReturn                         *LoginReturn
	UpdateEmailAndInvalidateSessionsReturn    *SessionReturn
	UpdatePasswordAndInvalidateSessionsReturn *SessionReturn
	GetRememberMeReturn                       *RememberMeReturn
	RenewRememberMeReturn                     *RememberMeReturn
	RememberMeReturn                          *RememberMeReturn
	ErrReturn                                 error
	MethodsCalled                             []string
}

func (b *MockBackend) GetLogin(email, loginProvider string) (*UserLogin, error) {
	b.MethodsCalled = append(b.MethodsCalled, "GetUserLogin")
	return b.GetUserLoginReturn.Login, b.GetUserLoginReturn.Err
}
func (b *MockBackend) GetSession(sessionHash string) (*UserLoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "GetSession")
	return b.GetSessionReturn.Session, b.GetSessionReturn.Err
}
func (b *MockBackend) CreateSession(loginID, userID int, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*UserLoginSession, *UserLoginRememberMe, error) {
	b.MethodsCalled = append(b.MethodsCalled, "NewLoginSession")
	return b.NewLoginSessionReturn.Session, b.NewLoginSessionReturn.RememberMe, b.NewLoginSessionReturn.Err
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

func (b *MockBackend) UpdateUser(session *UserLoginSession, fullname string, company string, pictureURL string) error {
	b.MethodsCalled = append(b.MethodsCalled, "UpdateUser")
	return b.ErrReturn
}

func (b *MockBackend) CreateLogin(email string, passwordHash string, fullName string, company string, pictureURL string) (*UserLogin, error) {
	b.MethodsCalled = append(b.MethodsCalled, "CreateLogin")
	return b.CreateLoginReturn.Login, b.CreateLoginReturn.Err
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

func (b *MockBackend) InvalidateRememberMe(selector string) error {
	b.MethodsCalled = append(b.MethodsCalled, "InvalidateRememberMe")
	return b.ErrReturn
}

func loginSuccess() *LoginReturn {
	return &LoginReturn{&UserLogin{LoginID: 1, ProviderKey: "zVNfmBbTwQZwyMsAizV1Guh_j7kcFbyG7-LRJeeJfXc="}, nil} // hash of "correctPassword"
}

func loginErr() *LoginReturn {
	return &LoginReturn{nil, errors.New("failed")}
}

func sessionSuccess(renewTimeUTC, expireTimeUTC time.Time) *SessionReturn {
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
