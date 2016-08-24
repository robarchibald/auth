package nginxauth

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
	Session *UserLoginSession
	Email   string
	Err     error
}

type MockBackend struct {
	BackendQuerier
	LoginReturn                               *UserLogin
	ExpirationReturn                          *time.Time
	GetSessionReturn                          *SessionReturn
	NewSessionReturn                          *SessionRememberReturn
	RenewSessionReturn                        *SessionReturn
	AddUserReturn                             *SessionReturn
	VerifyEmailReturn                         *VerifyEmailReturn
	CreateProfileAndInvalidateSessionsReturn  *SessionReturn
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
func (b *MockBackend) GetSession(sessionId string) (*UserLoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "GetSession")
	return b.GetSessionReturn.Session, b.GetSessionReturn.Err
}
func (b *MockBackend) NewLoginSession(loginId int, sessionId string, sessionRenewsAt, sessionExpiresAt time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewsAt, rememberMeExpiresAt time.Time) (*UserLoginSession, *UserLoginRememberMe, error) {
	b.MethodsCalled = append(b.MethodsCalled, "NewSession")
	return b.NewSessionReturn.Session, b.NewSessionReturn.RememberMe, b.NewSessionReturn.Err
}
func (b *MockBackend) RenewSession(sessionId string, renewsAt time.Time) (*UserLoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "RenewSession")
	return b.RenewSessionReturn.Session, b.RenewSessionReturn.Err
}
func (b *MockBackend) GetRememberMe(selector string) (*UserLoginRememberMe, error) {
	b.MethodsCalled = append(b.MethodsCalled, "GetRememberMe")
	return b.GetRememberMeReturn.RememberMe, b.GetRememberMeReturn.Err
}
func (b *MockBackend) RenewRememberMe(selector string, renewsAt time.Time) (*UserLoginRememberMe, error) {
	b.MethodsCalled = append(b.MethodsCalled, "RenewRememberMe")
	return b.RenewRememberMeReturn.RememberMe, b.RenewRememberMeReturn.Err
}
func (b *MockBackend) AddUser(email, emailVerifyHash, sessionId string, sessionRenewsAt, sessionExpiresAt time.Time) (*UserLoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "AddUser")
	return b.AddUserReturn.Session, b.AddUserReturn.Err
}

func (b *MockBackend) VerifyEmail(emailVerifyCode string, sessionId string, sessionRenewsAt, sessionExpiresAt time.Time) (*UserLoginSession, string, error) {
	b.MethodsCalled = append(b.MethodsCalled, "VerifyEmail")
	return b.VerifyEmailReturn.Session, b.VerifyEmailReturn.Email, b.VerifyEmailReturn.Err
}

func (b *MockBackend) UpdateUser(session *UserLoginSession, fullname string, company string, pictureUrl string) error {
	b.MethodsCalled = append(b.MethodsCalled, "UpdateUser")
	return b.ErrReturn
}

func (b *MockBackend) CreateProfileAndInvalidateSessions(loginId int, passwordHash string, fullName string, company string, pictureUrl string, sessionId string, sessionExpiresAt, sessionRenewsAt time.Time) (*UserLoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "CreateProfileAndInvalidateSessions")
	return b.CreateProfileAndInvalidateSessionsReturn.Session, b.CreateProfileAndInvalidateSessionsReturn.Err
}

func (b *MockBackend) UpdateEmailAndInvalidateSessions(email string, password string, newEmail string) (*UserLoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "UpdateEmailAndInvalidateSessions")
	return b.UpdateEmailAndInvalidateSessionsReturn.Session, b.UpdateEmailAndInvalidateSessionsReturn.Err
}

func (b *MockBackend) UpdatePasswordAndInvalidateSessions(email string, oldPassword string, newPassword string) (*UserLoginSession, error) {
	b.MethodsCalled = append(b.MethodsCalled, "UpdatePasswordAndInvalidateSessions")
	return b.UpdatePasswordAndInvalidateSessionsReturn.Session, b.UpdatePasswordAndInvalidateSessionsReturn.Err
}

func (b *MockBackend) InvalidateUserSessions(userId int) error {
	b.MethodsCalled = append(b.MethodsCalled, "InvalidateUserSessions")
	return b.ErrReturn
}

func session(renewsAt, expiresAt time.Time) *SessionReturn {
	return &SessionReturn{&UserLoginSession{1, "sessionId", 2, renewsAt, expiresAt, false}, nil}
}

func sessionErr() *SessionReturn {
	return &SessionReturn{&UserLoginSession{}, errors.New("failed")}
}

func rememberMe(renewsAt, expiresAt time.Time) *RememberMeReturn { // hash of the word "token"
	return &RememberMeReturn{&UserLoginRememberMe{TokenHash: "PEaenWxYddN6Q_NT1PiOYfz4EsZu7jRXRlpAsNpBU-A=", ExpiresAt: expiresAt, RenewsAt: renewsAt}, nil}
}

func rememberErr() *RememberMeReturn {
	return &RememberMeReturn{&UserLoginRememberMe{}, errors.New("failed")}
}

func sessionRemember(renewsAt, expiresAt time.Time) *SessionRememberReturn {
	return &SessionRememberReturn{&UserLoginSession{1, "sessionId", 2, renewsAt, expiresAt, false}, &UserLoginRememberMe{TokenHash: "PEaenWxYddN6Q_NT1PiOYfz4EsZu7jRXRlpAsNpBU-A=", ExpiresAt: expiresAt, RenewsAt: renewsAt}, nil}
}

func sessionRememberErr() *SessionRememberReturn {
	return &SessionRememberReturn{nil, nil, errors.New("failed")}
}

func verifyEmail(renewsAt, expiresAt time.Time) *VerifyEmailReturn {
	return &VerifyEmailReturn{&UserLoginSession{1, "sessionId", 2, renewsAt, expiresAt, false}, "email", nil}
}
func verifyEmailErr() *VerifyEmailReturn {
	return &VerifyEmailReturn{nil, "", errors.New("failed")}
}
