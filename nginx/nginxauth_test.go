package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/EndFirstCorp/auth"
	"github.com/pkg/errors"
)

type nilWriter struct{}

func (w *nilWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func TestNewRestServer(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	_, err := newNginxAuth("nginxauth.conf", "auth.log")
	if err != nil {
		t.Error("expected success", err)
	}
}

func TestNewEmailer(t *testing.T) {
	n := authConf{
		VerifyEmailTemplate:     "../testTemplates/verifyEmail.html",
		VerifyEmailSubject:      "verifyEmailSubject",
		WelcomeTemplate:         "../testTemplates/welcomeEmail.html",
		WelcomeSubject:          "welcomeSubject",
		NewLoginTemplate:        "../testTemplates/newLogin.html",
		NewLoginSubject:         "newLoginSubject",
		LockedOutTemplate:       "../testTemplates/lockedOut.html",
		LockedOutSubject:        "lockedOutSubject",
		EmailChangedTemplate:    "../testTemplates/emailChanged.html",
		EmailChangedSubject:     "emailChangedSubject",
		PasswordChangedTemplate: "../testTemplates/passwordChanged.html",
		PasswordChangedSubject:  "passwordChangedSubject",
	}
	n.NewEmailer()
}

func TestAuth(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	storer := &mockAuthStorer{ErrReturn: errors.New("failed")}
	authCookie(storer, w, nil)
	if w.Body.String() != "Authentication required: failed\n" || storer.LastRun != "GetSession" {
		t.Error("expected auth to fail", w.Body.String(), storer.LastRun)
	}

	w = httptest.NewRecorder()
	storer = &mockAuthStorer{SessionReturn: &auth.LoginSession{UserID: "1", Email: "test@test.com", FullName: "Name"}}
	authCookie(storer, w, nil)
	if w.Header().Get("X-User") != `{"UserID":"1","Email":"test@test.com","FullName":"Name"}` || storer.LastRun != "GetSession" {
		t.Error("expected User header to be set", w.Header().Get("X-User"), storer.LastRun)
	}
}

func TestAuthBasic(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	storer := &mockAuthStorer{ErrReturn: errors.New("failed")}
	authBasic(storer, w, nil)
	if w.Body.String() != "Authentication required: failed\n" || storer.LastRun != "GetBasicAuth" {
		t.Error("expected auth to fail", w.Body.String(), storer.LastRun)
	}

	w = httptest.NewRecorder()
	storer = &mockAuthStorer{SessionReturn: &auth.LoginSession{UserID: "0", Email: "test@test.com"}}
	authBasic(storer, w, nil)
	if w.Header().Get("X-User") != `{"UserID":"0","Email":"test@test.com","FullName":""}` || storer.LastRun != "GetBasicAuth" {
		t.Error("expected User header to be set", w.Header().Get("X-User"), storer.LastRun)
	}
}

func TestLogin(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	storer := &mockAuthStorer{ErrReturn: errors.New("failed")}
	login(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "Login" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}

	w = httptest.NewRecorder()
	storer = &mockAuthStorer{SessionReturn: &auth.LoginSession{}}
	login(storer, w, nil)
	if w.Body.String() != `{ "result": "Success" }` || storer.LastRun != "Login" {
		t.Error("expected success", w.Body.String(), storer.LastRun)
	}
}

func TestRegister(t *testing.T) {
	log.SetOutput(&nilWriter{})
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

func TestSetPrimaryEmail(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	storer := &mockAuthStorer{ErrReturn: errors.New("failed")}
	setPrimaryEmail(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "SetPrimaryEmail" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}
}

func TestCreateSecondaryEmail(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	storer := &mockAuthStorer{ErrReturn: errors.New("failed")}
	createSecondaryEmail(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "CreateSecondaryEmail" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}
}

func TestUpdatePassword(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	storer := &mockAuthStorer{ErrReturn: errors.New("failed")}
	updatePassword(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "UpdatePassword" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}
}

func TestVerifyEmail(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	storer := &mockAuthStorer{ErrReturn: errors.New("failed")}
	verifyEmail(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "VerifyEmail" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}
}

func TestAddUserHeader(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	addUserHeader(`{"name": "value"}`, w)
	if w.Header().Get("X-User") != `{"name": "value"}` {
		t.Error("expected halfauth header", w.Header())
	}
}

/*******************************************************/
type mockAuthStorer struct {
	SessionReturn        *auth.LoginSession
	DestinationURLReturn string
	ErrReturn            error
	LastRun              string
}

func (s *mockAuthStorer) GetSession(w http.ResponseWriter, r *http.Request) (*auth.LoginSession, error) {
	s.LastRun = "GetSession"
	return s.SessionReturn, s.ErrReturn
}

func (s *mockAuthStorer) GetBasicAuth(w http.ResponseWriter, r *http.Request) (*auth.LoginSession, error) {
	s.LastRun = "GetBasicAuth"
	return s.SessionReturn, s.ErrReturn
}
func (s *mockAuthStorer) OAuthLogin(w http.ResponseWriter, r *http.Request) error {
	s.LastRun = "OAuthLogin"
	return s.ErrReturn
}
func (s *mockAuthStorer) Login(w http.ResponseWriter, r *http.Request) error {
	s.LastRun = "Login"
	return s.ErrReturn
}
func (s *mockAuthStorer) Register(w http.ResponseWriter, r *http.Request) error {
	s.LastRun = "Register"
	return s.ErrReturn
}
func (s *mockAuthStorer) CreateProfile(w http.ResponseWriter, r *http.Request) error {
	s.LastRun = "CreateProfile"
	return s.ErrReturn
}
func (s *mockAuthStorer) VerifyEmail(w http.ResponseWriter, r *http.Request) (string, error) {
	s.LastRun = "VerifyEmail"
	return s.DestinationURLReturn, s.ErrReturn
}
func (s *mockAuthStorer) CreateSecondaryEmail(w http.ResponseWriter, r *http.Request) error {
	s.LastRun = "CreateSecondaryEmail"
	return s.ErrReturn
}
func (s *mockAuthStorer) SetPrimaryEmail(w http.ResponseWriter, r *http.Request) error {
	s.LastRun = "SetPrimaryEmail"
	return s.ErrReturn
}
func (s *mockAuthStorer) UpdatePassword(w http.ResponseWriter, r *http.Request) error {
	s.LastRun = "UpdatePassword"
	return s.ErrReturn
}
