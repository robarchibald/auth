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

func TestGetLogin(t *testing.T) {
	m := &MockBackend{GetUserLoginReturn: loginSuccess()}
	b := backend{u: m, l: m, s: m}
	b.GetLogin("email", "provider")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "GetLogin" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendCreateSession(t *testing.T) {
	m := &MockBackend{CreateSessionReturn: sessionRemember(time.Now(), time.Now())}
	b := backend{u: m, l: m, s: m}
	b.CreateSession(1, 1, "hash", time.Now(), time.Now(), false, "", "", time.Now(), time.Now())
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "CreateSession" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendGetSession(t *testing.T) {
	m := &MockBackend{GetSessionReturn: sessionErr()}
	b := backend{u: m, l: m, s: m}
	b.GetSession("hash")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "GetSession" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendRenewSession(t *testing.T) {
	m := &MockBackend{RenewSessionReturn: sessionErr()}
	b := backend{u: m, l: m, s: m}
	b.RenewSession("hash", time.Now())
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "RenewSession" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendGetRememberMe(t *testing.T) {
	m := &MockBackend{GetRememberMeReturn: rememberErr()}
	b := backend{u: m, l: m, s: m}
	b.GetRememberMe("selector")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "GetRememberMe" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendRenewRememberMe(t *testing.T) {
	m := &MockBackend{RenewRememberMeReturn: rememberErr()}
	b := backend{u: m, l: m, s: m}
	b.RenewRememberMe("selector", time.Now())
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "RenewRememberMe" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendAddUser(t *testing.T) {
	m := &MockBackend{AddUserReturn: nil}
	b := backend{u: m, l: m, s: m}
	b.AddUser("mail", "hash")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "AddUser" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendVerifyEmail(t *testing.T) {
	m := &MockBackend{VerifyEmailReturn: verifyEmailErr()}
	b := backend{u: m, l: m, s: m}
	b.VerifyEmail("hash")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "VerifyEmail" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendUpdateUser(t *testing.T) {
	m := &MockBackend{}
	b := backend{u: m, l: m, s: m}
	b.UpdateUser("hash", "name", "company", "url")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "UpdateUser" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendCreateLogin(t *testing.T) {
	m := &MockBackend{CreateLoginReturn: loginErr()}
	b := backend{u: m, l: m, s: m}
	b.CreateLogin("email", "hash", "name", "homeDir", 1, 1, "quota", "fileQuota")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "CreateLogin" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendUpdateEmail(t *testing.T) {
	m := &MockBackend{UpdateEmailReturn: sessionErr()}
	b := backend{u: m, l: m, s: m}
	b.UpdateEmail("email", "password", "newEmail")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "UpdateEmail" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendUpdatePassword(t *testing.T) {
	m := &MockBackend{UpdatePasswordReturn: sessionErr()}
	b := backend{u: m, l: m, s: m}
	b.UpdatePassword("email", "oldPassword", "newPassword")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "UpdatePassword" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendInvalidateSession(t *testing.T) {
	m := &MockBackend{}
	b := backend{u: m, l: m, s: m}
	b.InvalidateSession("hash")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "InvalidateSession" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendInvalidateSessions(t *testing.T) {
	m := &MockBackend{}
	b := backend{u: m, l: m, s: m}
	b.InvalidateSessions("email")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "InvalidateSessions" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendInvalidateRememberMe(t *testing.T) {
	m := &MockBackend{}
	b := backend{u: m, l: m, s: m}
	b.InvalidateRememberMe("selector")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "InvalidateRememberMe" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendClose(t *testing.T) {
	// all succeed
	m := &MockBackend{}
	b := backend{u: m, l: m, s: m}
	b.Close()
	if len(m.MethodsCalled) != 3 || m.MethodsCalled[0] != "Close" || m.MethodsCalled[1] != "Close" || m.MethodsCalled[2] != "Close" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}

	// error on session close
	m = &MockBackend{}
	e := &MockBackend{ErrReturn: errors.New("failed")}
	b = backend{u: m, l: m, s: e}
	b.Close()
	if len(m.MethodsCalled) != 0 || len(e.MethodsCalled) != 1 || e.MethodsCalled[0] != "Close" {
		t.Error("Expected fail on session close", m.MethodsCalled)
	}

	// error on user close
	m = &MockBackend{}
	e = &MockBackend{ErrReturn: errors.New("failed")}
	b = backend{u: e, l: m, s: m}
	b.Close()
	if len(e.MethodsCalled) != 1 || len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "Close" || e.MethodsCalled[0] != "Close" {
		t.Error("Expected fail on user close", m.MethodsCalled)
	}

	// error on login close
	m = &MockBackend{}
	e = &MockBackend{ErrReturn: errors.New("failed")}
	b = backend{u: m, l: e, s: m}
	b.Close()
	if len(m.MethodsCalled) != 2 || len(e.MethodsCalled) != 1 || m.MethodsCalled[0] != "Close" || m.MethodsCalled[1] != "Close" || e.MethodsCalled[0] != "Close" {
		t.Error("Expected it would call backend", m.MethodsCalled)
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
	Backender
	GetUserLoginReturn    *LoginReturn
	ExpirationReturn      *time.Time
	GetSessionReturn      *SessionReturn
	CreateSessionReturn   *SessionRememberReturn
	RenewSessionReturn    *SessionReturn
	AddUserReturn         error
	VerifyEmailReturn     *VerifyEmailReturn
	CreateLoginReturn     *LoginReturn
	UpdateEmailReturn     *SessionReturn
	UpdatePasswordReturn  *SessionReturn
	GetRememberMeReturn   *RememberMeReturn
	RenewRememberMeReturn *RememberMeReturn
	RememberMeReturn      *RememberMeReturn
	ErrReturn             error
	MethodsCalled         []string
}

func (b *MockBackend) GetLogin(email, loginProvider string) (*UserLogin, error) {
	b.MethodsCalled = append(b.MethodsCalled, "GetLogin")
	return b.GetUserLoginReturn.Login, b.GetUserLoginReturn.Err
}

func (b *MockBackend) GetSession(sessionHash string) (*UserLoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "GetSession")
	return b.GetSessionReturn.Session, b.GetSessionReturn.Err
}

func (b *MockBackend) CreateSession(loginID, userID int, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*UserLoginSession, *UserLoginRememberMe, error) {
	b.MethodsCalled = append(b.MethodsCalled, "CreateSession")
	return b.CreateSessionReturn.Session, b.CreateSessionReturn.RememberMe, b.CreateSessionReturn.Err
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

func (b *MockBackend) UpdateUser(emailVerifyHash, fullname string, company string, pictureURL string) (string, error) {
	b.MethodsCalled = append(b.MethodsCalled, "UpdateUser")
	return "test@test.com", b.ErrReturn
}

func (b *MockBackend) CreateLogin(email, passwordHash, fullName, homeDirectory string, uidNumber, gidNumber int, mailQuota, fileQuota string) (*UserLogin, error) {
	b.MethodsCalled = append(b.MethodsCalled, "CreateLogin")
	return b.CreateLoginReturn.Login, b.CreateLoginReturn.Err
}

func (b *MockBackend) UpdateEmail(email string, password string, newEmail string) (*UserLoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "UpdateEmail")
	return b.UpdateEmailReturn.Session, b.UpdateEmailReturn.Err
}

func (b *MockBackend) UpdatePassword(email string, oldPassword string, newPassword string) (*UserLoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "UpdatePassword")
	return b.UpdatePasswordReturn.Session, b.UpdatePasswordReturn.Err
}

func (b *MockBackend) InvalidateSession(sessionHash string) error {
	b.MethodsCalled = append(b.MethodsCalled, "InvalidateSession")
	return b.ErrReturn
}

func (b *MockBackend) InvalidateSessions(email string) error {
	b.MethodsCalled = append(b.MethodsCalled, "InvalidateSessions")
	return b.ErrReturn
}

func (b *MockBackend) InvalidateRememberMe(selector string) error {
	b.MethodsCalled = append(b.MethodsCalled, "InvalidateRememberMe")
	return b.ErrReturn
}

func (b *MockBackend) Close() error {
	b.MethodsCalled = append(b.MethodsCalled, "Close")
	return b.ErrReturn
}

func loginSuccess() *LoginReturn {
	return &LoginReturn{&UserLogin{LoginID: 1, ProviderKey: "$6$rounds=200000$pYt48w3PgDcRoCMx$sxbuADDhNI9nNe35HcrFYW7vpWLLMNiPBKcbqOgaRxTBYE8hePJWvmuN9dp.783JmDZBhDJRG956Wc/fzghhh."}, nil} // cryptoHash of "correctPassword"
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
