package auth

import (
	"testing"
	"time"

	"github.com/pkg/errors"
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

func TestBackendLogin(t *testing.T) {
	m := &mockBackend{}
	b := backend{u: m, s: m}
	b.Login("email", "password")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "Login" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendCreateSession(t *testing.T) {
	m := &mockBackend{CreateSessionReturn: sessionSuccess(time.Now(), time.Now())}
	b := backend{u: m, s: m}
	b.CreateSession("1", "test@test.com", map[string]interface{}{"info": "values"}, "hash", "csrfToken", time.Now(), time.Now())
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "CreateSession" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendCreateRemember(t *testing.T) {
	m := &mockBackend{CreateRememberMeReturn: rememberMe(time.Now(), time.Now())}
	b := backend{u: m, s: m}
	b.CreateRememberMe("1", "test@test.com", "", "", time.Now(), time.Now())
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "CreateRememberMe" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendGetSession(t *testing.T) {
	m := &mockBackend{GetSessionReturn: sessionErr()}
	b := backend{u: m, s: m}
	b.GetSession("hash")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "GetSession" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendUpdateSession(t *testing.T) {
	m := &mockBackend{UpdateSessionErr: errors.New("failed")}
	b := backend{u: m, s: m}
	b.UpdateSession("hash", time.Now(), time.Now())
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "UpdateSession" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendGetRememberMe(t *testing.T) {
	m := &mockBackend{GetRememberMeReturn: rememberErr()}
	b := backend{u: m, s: m}
	b.GetRememberMe("selector")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "GetRememberMe" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendUpdateRememberMe(t *testing.T) {
	m := &mockBackend{UpdateRememberMeErr: errors.New("failed")}
	b := backend{u: m, s: m}
	b.UpdateRememberMe("selector", time.Now())
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "UpdateRememberMe" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendAddUser(t *testing.T) {
	m := &mockBackend{AddUserErr: nil}
	b := backend{u: m, s: m}
	b.AddUser("mail", map[string]interface{}{"info": "value"})
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "AddUser" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendGetEmailSession(t *testing.T) {
	m := &mockBackend{getEmailSessionReturn: getEmailSessionErr()}
	b := backend{u: m, s: m}
	b.GetEmailSession("hash")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "GetEmailSession" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendUpdateUser(t *testing.T) {
	m := &mockBackend{}
	b := backend{u: m, s: m}
	b.UpdateUser("1", "password", map[string]interface{}{"fullName": "name", "company": "companyName"})
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "UpdateUser" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendSetPrimaryEmail(t *testing.T) {
	m := &mockBackend{UpdatePrimaryEmailErr: errors.New("fail")}
	b := backend{u: m, s: m}
	b.UpdatePrimaryEmail("userID", "newEmail")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "UpdatePrimaryEmail" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendUpdatePassword(t *testing.T) {
	m := &mockBackend{UpdatePasswordErr: errors.New("fail")}
	b := backend{u: m, s: m}
	b.UpdatePassword("userID", "newPassword")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "UpdatePassword" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendAddSecondaryEmail(t *testing.T) {
	m := &mockBackend{AddSecondaryEmailErr: errors.New("fail")}
	b := backend{u: m, s: m}
	b.AddSecondaryEmail("userID", "secondaryEmail@test.com")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "AddSecondaryEmail" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendDeleteSession(t *testing.T) {
	m := &mockBackend{}
	b := backend{u: m, s: m}
	b.DeleteSession("hash")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "DeleteSession" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendInvalidateSessions(t *testing.T) {
	m := &mockBackend{}
	b := backend{u: m, s: m}
	b.InvalidateSessions("email")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "InvalidateSessions" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendDeleteRememberMe(t *testing.T) {
	m := &mockBackend{}
	b := backend{u: m, s: m}
	b.DeleteRememberMe("selector")
	if len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "DeleteRememberMe" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}
}

func TestBackendClose(t *testing.T) {
	// all succeed
	m := &mockBackend{}
	b := backend{u: m, s: m}
	b.Close()
	if len(m.MethodsCalled) != 2 || m.MethodsCalled[0] != "Close" || m.MethodsCalled[1] != "Close" {
		t.Error("Expected it would call backend", m.MethodsCalled)
	}

	// error on session close
	m = &mockBackend{}
	e := &mockBackend{ErrReturn: errors.New("failed")}
	b = backend{u: m, s: e}
	b.Close()
	if len(m.MethodsCalled) != 0 || len(e.MethodsCalled) != 1 || e.MethodsCalled[0] != "Close" {
		t.Error("Expected fail on session close", m.MethodsCalled)
	}

	// error on user close
	m = &mockBackend{}
	e = &mockBackend{ErrReturn: errors.New("failed")}
	b = backend{u: e, s: m}
	b.Close()
	if len(e.MethodsCalled) != 1 || len(m.MethodsCalled) != 1 || m.MethodsCalled[0] != "Close" || e.MethodsCalled[0] != "Close" {
		t.Error("Expected fail on user close", m.MethodsCalled)
	}
}

/***********************************************************************/

type UserReturn struct {
	User *User
	Err  error
}

type SessionReturn struct {
	Session *LoginSession
	Err     error
}

type RememberMeReturn struct {
	RememberMe *rememberMeSession
	Err        error
}

type EmailSessionReturn struct {
	Session *emailSession
	Err     error
}

type mockBackend struct {
	Backender
	GetLoginReturn         *UserReturn
	LoginAndGetUserReturn  *UserReturn
	LoginErr               error
	ExpirationReturn       *time.Time
	GetSessionReturn       *SessionReturn
	CreateSessionReturn    *SessionReturn
	CreateRememberMeReturn *RememberMeReturn
	UpdateSessionErr       error
	AddUserErr             error
	DeleteEmailSessionErr  error
	UpdateEmailSessionErr  error
	GetUserReturn          *UserReturn
	getEmailSessionReturn  *EmailSessionReturn
	AddSecondaryEmailErr   error
	UpdatePrimaryEmailErr  error
	UpdateUserErr          error
	UpdatePasswordErr      error
	UpdateInfoErr          error
	GetRememberMeReturn    *RememberMeReturn
	UpdateRememberMeErr    error
	ErrReturn              error
	MethodsCalled          []string
}

func (b *mockBackend) GetLogin(email string) (*User, error) {
	b.MethodsCalled = append(b.MethodsCalled, "GetLogin")
	if b.GetLoginReturn == nil {
		return nil, errors.New("GetLoginReturn not initialized")
	}
	return b.GetLoginReturn.User, b.GetLoginReturn.Err
}

func (b *mockBackend) LoginAndGetUser(email, password string) (*User, error) {
	b.MethodsCalled = append(b.MethodsCalled, "LoginAndGetUser")
	if b.LoginAndGetUserReturn == nil {
		return nil, errors.New("LoginAndGetUserReturn not initialized")
	}
	return b.LoginAndGetUserReturn.User, b.LoginAndGetUserReturn.Err
}

func (b *mockBackend) Login(email, password string) error {
	b.MethodsCalled = append(b.MethodsCalled, "Login")
	return b.LoginErr
}

func (b *mockBackend) GetSession(sessionHash string) (*LoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "GetSession")
	if b.GetSessionReturn == nil {
		return nil, errors.New("GetSessionReturn not initialized")
	}
	return b.GetSessionReturn.Session, b.GetSessionReturn.Err
}

func (b *mockBackend) CreateSession(userID, email string, info map[string]interface{}, sessionHash, csrfToken string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time) (*LoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "CreateSession")
	if b.CreateSessionReturn == nil {
		return nil, errors.New("CreateSessionReturn not initialized")
	}
	return b.CreateSessionReturn.Session, b.CreateSessionReturn.Err
}

func (b *mockBackend) CreateRememberMe(userID, email, selector, tokenHash string, renewTimeUTC, expireTimeUTC time.Time) (*rememberMeSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "CreateRememberMe")
	if b.CreateRememberMeReturn == nil {
		return nil, errors.New("CreateRememberMeReturn not initialized")
	}
	return b.CreateRememberMeReturn.RememberMe, b.CreateRememberMeReturn.Err
}

func (b *mockBackend) UpdateSession(sessionHash string, renewTimeUTC, expireTimeUTC time.Time) error {
	b.MethodsCalled = append(b.MethodsCalled, "UpdateSession")
	return b.UpdateSessionErr
}
func (b *mockBackend) GetRememberMe(selector string) (*rememberMeSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "GetRememberMe")
	if b.GetRememberMeReturn == nil {
		return nil, errors.New("GetRememberMeReturn not initialized")
	}
	return b.GetRememberMeReturn.RememberMe, b.GetRememberMeReturn.Err
}
func (b *mockBackend) UpdateRememberMe(selector string, renewTimeUTC time.Time) error {
	b.MethodsCalled = append(b.MethodsCalled, "UpdateRememberMe")
	return b.UpdateRememberMeErr
}
func (b *mockBackend) AddUser(email string, info map[string]interface{}) (string, error) {
	b.MethodsCalled = append(b.MethodsCalled, "AddUser")
	return "1", b.AddUserErr
}

func (b *mockBackend) CreateEmailSession(email string, info map[string]interface{}, emailVerifyHash, csrfToken string) error {
	b.MethodsCalled = append(b.MethodsCalled, "CreateEmailSession")
	return b.ErrReturn
}

func (b *mockBackend) GetEmailSession(emailVerifyHash string) (*emailSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "GetEmailSession")
	if b.getEmailSessionReturn == nil {
		return nil, errors.New("getEmailSessionReturn not initialized")
	}
	return b.getEmailSessionReturn.Session, b.getEmailSessionReturn.Err
}

func (b *mockBackend) UpdateEmailSession(emailVerifyHash, userID string) error {
	b.MethodsCalled = append(b.MethodsCalled, "UpdateEmailSession")
	return b.UpdateEmailSessionErr
}

func (b *mockBackend) DeleteEmailSession(emailVerifyHash string) error {
	b.MethodsCalled = append(b.MethodsCalled, "DeleteEmailSession")
	return b.DeleteEmailSessionErr
}

func (b *mockBackend) GetUser(email string) (*User, error) {
	b.MethodsCalled = append(b.MethodsCalled, "GetUser")
	if b.GetUserReturn == nil {
		return nil, errors.New("GetUserReturn not initialized")
	}
	return b.GetUserReturn.User, b.GetUserReturn.Err
}

func (b *mockBackend) UpdateUser(userID, password string, info map[string]interface{}) error {
	b.MethodsCalled = append(b.MethodsCalled, "UpdateUser")
	return b.UpdateUserErr
}

func (b *mockBackend) UpdatePassword(userID, password string) error {
	b.MethodsCalled = append(b.MethodsCalled, "UpdatePassword")
	return b.UpdatePasswordErr
}

func (b *mockBackend) UpdateInfo(userID string, info map[string]interface{}) error {
	b.MethodsCalled = append(b.MethodsCalled, "UpdateInfo")
	return b.UpdateInfoErr
}

func (b *mockBackend) AddSecondaryEmail(userID, secondaryEmail string) error {
	b.MethodsCalled = append(b.MethodsCalled, "AddSecondaryEmail")
	return b.AddSecondaryEmailErr
}
func (b *mockBackend) UpdatePrimaryEmail(userID, newPrimaryEmail string) error {
	b.MethodsCalled = append(b.MethodsCalled, "UpdatePrimaryEmail")
	return b.UpdatePrimaryEmailErr

}
func (b *mockBackend) DeleteSession(sessionHash string) error {
	b.MethodsCalled = append(b.MethodsCalled, "DeleteSession")
	return b.ErrReturn
}

func (b *mockBackend) InvalidateSessions(email string) error {
	b.MethodsCalled = append(b.MethodsCalled, "InvalidateSessions")
	return b.ErrReturn
}

func (b *mockBackend) DeleteRememberMe(selector string) error {
	b.MethodsCalled = append(b.MethodsCalled, "DeleteRememberMe")
	return b.ErrReturn
}

func (b *mockBackend) Close() error {
	b.MethodsCalled = append(b.MethodsCalled, "Close")
	return b.ErrReturn
}

func userSuccess() *UserReturn {
	return &UserReturn{&User{Email: "test@test.com"}, nil}
}

func userErr() *UserReturn {
	return &UserReturn{nil, errors.New("failed")}
}

func sessionSuccess(renewTimeUTC, expireTimeUTC time.Time) *SessionReturn {
	return &SessionReturn{&LoginSession{"1", "test@test.com", map[string]interface{}{"info": "values"}, "sessionHash", "csrfToken", renewTimeUTC, expireTimeUTC}, nil}
}

func sessionErr() *SessionReturn {
	return &SessionReturn{&LoginSession{}, errors.New("failed")}
}

func rememberMe(renewTimeUTC, expireTimeUTC time.Time) *RememberMeReturn { // hash of the word "token"
	return &RememberMeReturn{&rememberMeSession{TokenHash: "PEaenWxYddN6Q_NT1PiOYfz4EsZu7jRXRlpAsNpBU-A=", ExpireTimeUTC: expireTimeUTC, RenewTimeUTC: renewTimeUTC}, nil}
}

func rememberErr() *RememberMeReturn {
	return &RememberMeReturn{&rememberMeSession{}, errors.New("failed")}
}

func getEmailSessionSuccess() *EmailSessionReturn {
	return &EmailSessionReturn{&emailSession{Email: "email@test.com", EmailVerifyHash: "hash", Info: map[string]interface{}{"key": "value"}, CSRFToken: "csrfToken"}, nil}
}
func getEmailSessionErr() *EmailSessionReturn {
	return &EmailSessionReturn{nil, errors.New("failed")}
}
