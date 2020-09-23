package auth

import (
	"net/http"
)

// FakeStorer is a fake AuthStorer for testing and includes MethodsCalled to track what was called
type FakeStorer interface {
	AuthStorer
	MethodsCalled() []string
}

// NewFakeStorer returns a fake AuthStorer that can be used for testing
func NewFakeStorer(config FakeStorerConfig) FakeStorer {
	return &fakeAuthStore{FakeStorerConfig: config}
}

// FakeStorerConfig stores the config for a Fake AuthStorer
type FakeStorerConfig struct {
	GetSessionVal           *LoginSession
	GetSessionErr           error
	GetBasicAuthVal         *LoginSession
	GetBasicAuthErr         error
	OAuthLoginVal           string
	OAuthLoginErr           error
	LoginVal                *LoginSession
	LoginErr                error
	RegisterErr             error
	RequestPasswordResetErr error
	LogoutErr               error
	CreateProfileVal        *LoginSession
	CreateProfileErr        error
	VerifyEmailVal          string
	VerifyEmailVal2         *User
	VerifyEmailErr          error
	VerifyPasswordResetVal  string
	VerifyPasswordResetVal2 *User
	VerifyPasswordResetErr  error
	CreateSecondaryEmailErr error
	SetPrimaryEmailErr      error
	UpdatePasswordVal       *LoginSession
	UpdatePasswordErr       error
	UpdateInfoErr           error
}

type fakeAuthStore struct {
	AuthStorer
	FakeStorerConfig
	Called []string
}

func (a *fakeAuthStore) MethodsCalled() []string {
	return a.Called
}

func (a *fakeAuthStore) GetSession(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	a.Called = append(a.Called, "GetSession")
	return a.GetSessionVal, a.GetSessionErr
}

func (a *fakeAuthStore) GetBasicAuth(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	a.Called = append(a.Called, "GetBasicAuth")
	return a.GetBasicAuthVal, a.GetBasicAuthErr
}

func (a *fakeAuthStore) OAuthLogin(w http.ResponseWriter, r *http.Request) (string, error) {
	a.Called = append(a.Called, "OAuthLogin")
	return a.OAuthLoginVal, a.OAuthLoginErr
}

func (a *fakeAuthStore) Login(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	a.Called = append(a.Called, "Login")
	return a.LoginVal, a.LoginErr
}

func (a *fakeAuthStore) Register(w http.ResponseWriter, r *http.Request, params EmailSendParams, password string) error {
	a.Called = append(a.Called, "Register")
	return a.RegisterErr
}

func (a *fakeAuthStore) RequestPasswordReset(w http.ResponseWriter, r *http.Request, params EmailSendParams) error {
	a.Called = append(a.Called, "RequestPasswordReset")
	return a.RequestPasswordResetErr
}

func (a *fakeAuthStore) CreateProfile(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	a.Called = append(a.Called, "CreateProfile")
	return a.CreateProfileVal, a.CreateProfileErr
}

func (a *fakeAuthStore) VerifyEmail(w http.ResponseWriter, r *http.Request, params EmailSendParams) (string, *User, error) {
	a.Called = append(a.Called, "VerifyEmail")
	return a.VerifyEmailVal, a.VerifyEmailVal2, a.VerifyEmailErr
}

func (a *fakeAuthStore) VerifyPasswordReset(w http.ResponseWriter, r *http.Request, emailVerificationCode string) (string, *User, error) {
	a.Called = append(a.Called, "VerifyPasswordReset")
	return a.VerifyPasswordResetVal, a.VerifyPasswordResetVal2, a.VerifyPasswordResetErr
}

func (a *fakeAuthStore) CreateSecondaryEmail(w http.ResponseWriter, r *http.Request, templateName, emailSubject string) error {
	a.Called = append(a.Called, "CreateSecondaryEmail")
	return a.CreateSecondaryEmailErr
}

func (a *fakeAuthStore) SetPrimaryEmail(w http.ResponseWriter, r *http.Request, templateName, emailSubject string) error {
	a.Called = append(a.Called, "SetPrimaryEmail")
	return a.SetPrimaryEmailErr
}

func (a *fakeAuthStore) UpdatePassword(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	a.Called = append(a.Called, "UpdatePassword")
	return a.UpdatePasswordVal, a.UpdatePasswordErr
}

func (a *fakeAuthStore) Logout(w http.ResponseWriter, r *http.Request) error {
	a.Called = append(a.Called, "Logout")
	return a.LogoutErr
}

func (a *fakeAuthStore) UpdateInfo(userID string, info map[string]interface{}) error {
	a.Called = append(a.Called, "UpdateInfo")
	return a.UpdateInfoErr
}

var _ AuthStorer = &fakeAuthStore{}
