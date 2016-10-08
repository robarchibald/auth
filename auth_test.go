package main

import (
	"errors"
	"net/http/httptest"
	"testing"
)

func TestAuth(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &MockAuthStorer{ErrReturn: errors.New("failed")}
	auth(storer, w, nil)
	if w.Body.String() != "Authentication required: failed\n" || storer.LastRun != "GetSession" {
		t.Error("expected auth to fail", w.Body.String(), storer.LastRun)
	}

	w = httptest.NewRecorder()
	storer = &MockAuthStorer{SessionReturn: &UserLoginSession{UserID: 12}}
	auth(storer, w, nil)
	if w.Header().Get("X-User-Id") != "12" || storer.LastRun != "GetSession" {
		t.Error("expected UserId header to be set", w.Header().Get("X-User-Id"), storer.LastRun)
	}
}

func TestAuthBasic(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &MockAuthStorer{ErrReturn: errors.New("failed")}
	authBasic(storer, w, nil)
	if w.Body.String() != "Authentication required: failed\n" || storer.LastRun != "GetBasicAuth" {
		t.Error("expected auth to fail", w.Body.String(), storer.LastRun)
	}

	w = httptest.NewRecorder()
	storer = &MockAuthStorer{SessionReturn: &UserLoginSession{UserID: 12}}
	authBasic(storer, w, nil)
	if w.Header().Get("X-User-Id") != "12" || storer.LastRun != "GetBasicAuth" {
		t.Error("expected UserId header to be set", w.Header().Get("X-User-Id"), storer.LastRun)
	}
}

func TestLogin(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &MockAuthStorer{ErrReturn: errors.New("failed")}
	login(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "Login" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}

	w = httptest.NewRecorder()
	storer = &MockAuthStorer{SessionReturn: &UserLoginSession{}}
	login(storer, w, nil)
	if w.Body.String() != `{ "result": "Success" }` || storer.LastRun != "Login" {
		t.Error("expected success", w.Body.String(), storer.LastRun)
	}
}

func TestRegister(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &MockAuthStorer{ErrReturn: errors.New("failed")}
	register(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "Register" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}
}

func TestCreateProfile(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &MockAuthStorer{ErrReturn: errors.New("failed")}
	createProfile(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "CreateProfile" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}
}

func TestUpdateEmail(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &MockAuthStorer{ErrReturn: errors.New("failed")}
	updateEmail(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "UpdateEmail" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}
}

func TestUpdatePassword(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &MockAuthStorer{ErrReturn: errors.New("failed")}
	updatePassword(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "UpdatePassword" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}
}

func TestVerifyEmail(t *testing.T) {
	w := httptest.NewRecorder()
	storer := &MockAuthStorer{ErrReturn: errors.New("failed")}
	verifyEmail(storer, w, nil)
	if w.Body.String() != "failed\n" || storer.LastRun != "VerifyEmail" {
		t.Error("expected to fail", w.Body.String(), storer.LastRun)
	}
}

func TestAddUserHeader(t *testing.T) {
	w := httptest.NewRecorder()
	addUserHeader(&UserLoginSession{UserID: 42}, w)
	if w.Header().Get("X-User-Id") != "42" {
		t.Error("expected halfauth header", w.Header())
	}
}

/*******************************************************/
type MockAuthStorer struct {
	SessionReturn *UserLoginSession
	ErrReturn     error
	LastRun       string
}

func (s *MockAuthStorer) GetSession() (*UserLoginSession, error) {
	s.LastRun = "GetSession"
	return s.SessionReturn, s.ErrReturn
}

func (s *MockAuthStorer) GetBasicAuth() (*UserLoginSession, error) {
	s.LastRun = "GetBasicAuth"
	return s.SessionReturn, s.ErrReturn
}
func (s *MockAuthStorer) Login() error {
	s.LastRun = "Login"
	return s.ErrReturn
}
func (s *MockAuthStorer) Register() error {
	s.LastRun = "Register"
	return s.ErrReturn
}
func (s *MockAuthStorer) CreateProfile() error {
	s.LastRun = "CreateProfile"
	return s.ErrReturn
}
func (s *MockAuthStorer) VerifyEmail() error {
	s.LastRun = "VerifyEmail"
	return s.ErrReturn
}
func (s *MockAuthStorer) UpdateEmail() error {
	s.LastRun = "UpdateEmail"
	return s.ErrReturn
}
func (s *MockAuthStorer) UpdatePassword() error {
	s.LastRun = "UpdatePassword"
	return s.ErrReturn
}
