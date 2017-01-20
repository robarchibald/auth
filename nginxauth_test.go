package main

import (
	"errors"
	"net/http/httptest"
	"testing"
)

func TestNewRestServer(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	_, err := newNginxAuth()
	if err != nil { // will connect to the db and LDAP servers specified in auth.conf
		t.Error("expected success", err)
	}
}

func TestNewEmailer(t *testing.T) {
	n := authConf{
		VerifyEmailTemplate:     "testTemplates/verifyEmail.html",
		VerifyEmailSubject:      "verifyEmailSubject",
		WelcomeTemplate:         "testTemplates/welcomeEmail.html",
		WelcomeSubject:          "welcomeSubject",
		NewLoginTemplate:        "testTemplates/newLogin.html",
		NewLoginSubject:         "newLoginSubject",
		LockedOutTemplate:       "testTemplates/lockedOut.html",
		LockedOutSubject:        "lockedOutSubject",
		EmailChangedTemplate:    "testTemplates/emailChanged.html",
		EmailChangedSubject:     "emailChangedSubject",
		PasswordChangedTemplate: "testTemplates/passwordChanged.html",
		PasswordChangedSubject:  "passwordChangedSubject",
	}
	n.NewEmailer()
}

func TestAuth(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &mockAuthStorer{ErrReturn: errors.New("failed")}
	auth(storer, w, nil)
	if w.Body.String() != "Authentication required: failed\n" || storer.LastRun != "GetSession" {
		t.Error("expected auth to fail", w.Body.String(), storer.LastRun)
	}

	w = httptest.NewRecorder()
	storer = &mockAuthStorer{SessionReturn: &loginSession{Email: "test@test.com"}}
	auth(storer, w, nil)
	if w.Header().Get("X-User") != "test@test.com" || storer.LastRun != "GetSession" {
		t.Error("expected User header to be set", w.Header().Get("X-User"), storer.LastRun)
	}
}

func TestAuthBasic(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &mockAuthStorer{ErrReturn: errors.New("failed")}
	authBasic(storer, w, nil)
	if w.Body.String() != "Authentication required: failed\n" || storer.LastRun != "GetBasicAuth" {
		t.Error("expected auth to fail", w.Body.String(), storer.LastRun)
	}

	w = httptest.NewRecorder()
	storer = &mockAuthStorer{SessionReturn: &loginSession{Email: "test@test.com"}}
	authBasic(storer, w, nil)
	if w.Header().Get("X-User") != "test@test.com" || storer.LastRun != "GetBasicAuth" {
		t.Error("expected User header to be set", w.Header().Get("X-User"), storer.LastRun)
	}
}

func TestLogin(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &mockAuthStorer{ErrReturn: errors.New("failed")}
	login(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "Login" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}

	w = httptest.NewRecorder()
	storer = &mockAuthStorer{SessionReturn: &loginSession{}}
	login(storer, w, nil)
	if w.Body.String() != `{ "result": "Success" }` || storer.LastRun != "Login" {
		t.Error("expected success", w.Body.String(), storer.LastRun)
	}
}

func TestRegister(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &mockAuthStorer{ErrReturn: errors.New("failed")}
	register(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "Register" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}
}

func TestCreateProfile(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &mockAuthStorer{ErrReturn: errors.New("failed")}
	createProfile(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "CreateProfile" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}
}

func TestUpdateEmail(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &mockAuthStorer{ErrReturn: errors.New("failed")}
	updateEmail(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "UpdateEmail" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}
}

func TestUpdatePassword(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &mockAuthStorer{ErrReturn: errors.New("failed")}
	updatePassword(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "UpdatePassword" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}
}

func TestVerifyEmail(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &mockAuthStorer{ErrReturn: errors.New("failed")}
	verifyEmail(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "VerifyEmail" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}
}

func TestAddUserHeader(t *testing.T) {
	w := httptest.NewRecorder()
	addUserHeader(&loginSession{Email: "test@test.com"}, w)
	if w.Header().Get("X-User") != "test@test.com" {
		t.Error("expected halfauth header", w.Header())
	}
}

/*******************************************************/
type mockAuthStorer struct {
	SessionReturn *loginSession
	ErrReturn     error
	LastRun       string
}

func (s *mockAuthStorer) GetSession() (*loginSession, error) {
	s.LastRun = "GetSession"
	return s.SessionReturn, s.ErrReturn
}

func (s *mockAuthStorer) GetBasicAuth() (*loginSession, error) {
	s.LastRun = "GetBasicAuth"
	return s.SessionReturn, s.ErrReturn
}
func (s *mockAuthStorer) Login() error {
	s.LastRun = "Login"
	return s.ErrReturn
}
func (s *mockAuthStorer) Register() error {
	s.LastRun = "Register"
	return s.ErrReturn
}
func (s *mockAuthStorer) CreateProfile() error {
	s.LastRun = "CreateProfile"
	return s.ErrReturn
}
func (s *mockAuthStorer) VerifyEmail() error {
	s.LastRun = "VerifyEmail"
	return s.ErrReturn
}
func (s *mockAuthStorer) UpdateEmail() error {
	s.LastRun = "UpdateEmail"
	return s.ErrReturn
}
func (s *mockAuthStorer) UpdatePassword() error {
	s.LastRun = "UpdatePassword"
	return s.ErrReturn
}
