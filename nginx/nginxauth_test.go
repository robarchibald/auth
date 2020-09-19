package main

import (
	"log"
	"net/http/httptest"
	"os"
	"reflect"
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
	_, err := newNginxAuth("testdata/nginxauth.conf", "testdata/auth.log")
	if err != nil {
		t.Error("expected success", err)
	}
	os.Remove("testdata/auth.log")
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
	storer := auth.NewFakeStorer(auth.FakeStorerConfig{GetSessionErr: errors.New("failed")})
	authCookie(storer, w, nil)
	checkBodyAndMethods(t, "Authentication required: failed\n", []string{"GetSession"}, w, storer)

	w = httptest.NewRecorder()
	storer = auth.NewFakeStorer(auth.FakeStorerConfig{GetSessionVal: &auth.LoginSession{UserID: "1", Email: "test@test.com", Info: map[string]interface{}{"fullName": "Name"}}})
	authCookie(storer, w, nil)
	checkHeaderAndMethods(t, `{"userID":"1","email":"test@test.com","isEmailVerified":false,"info":{"fullName":"Name"}}`, []string{"GetSession"}, w, storer)
}

func TestAuthBasic(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	storer := auth.NewFakeStorer(auth.FakeStorerConfig{GetBasicAuthErr: errors.New("failed")})
	authBasic(storer, w, nil)
	checkBodyAndMethods(t, "Authentication required: failed\n", []string{"GetBasicAuth"}, w, storer)

	w = httptest.NewRecorder()
	storer = auth.NewFakeStorer(auth.FakeStorerConfig{GetBasicAuthVal: &auth.LoginSession{UserID: "0", Email: "test@test.com"}})
	authBasic(storer, w, nil)
	checkHeaderAndMethods(t, `{"userID":"0","email":"test@test.com","isEmailVerified":false,"info":null}`, []string{"GetBasicAuth"}, w, storer)
}

func TestLogin(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	storer := auth.NewFakeStorer(auth.FakeStorerConfig{LoginErr: errors.New("failed")})
	login(storer, w, nil)
	checkBodyAndMethods(t, "Authentication required: failed\n", []string{"Login"}, w, storer)

	w = httptest.NewRecorder()
	storer = auth.NewFakeStorer(auth.FakeStorerConfig{LoginVal: &auth.LoginSession{}})
	login(storer, w, nil)
	checkBodyAndMethods(t, `{"userID":"","email":"","isEmailVerified":false,"info":null}`, []string{"Login"}, w, storer)
}

func TestRegister(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	storer := auth.NewFakeStorer(auth.FakeStorerConfig{RegisterErr: errors.New("failed")})
	register(storer, w, nil)
	checkBodyAndMethods(t, "failed\n", []string{"Register"}, w, storer)
}

func TestCreateProfile(t *testing.T) {
	w := httptest.NewRecorder()
	storer := auth.NewFakeStorer(auth.FakeStorerConfig{CreateProfileErr: errors.New("failed")})
	createProfile(storer, w, nil)
	checkBodyAndMethods(t, "Authentication required: failed\n", []string{"CreateProfile"}, w, storer)
}

func TestSetPrimaryEmail(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	storer := auth.NewFakeStorer(auth.FakeStorerConfig{SetPrimaryEmailErr: errors.New("failed")})
	setPrimaryEmail(storer, w, nil)
	checkBodyAndMethods(t, "failed\n", []string{"SetPrimaryEmail"}, w, storer)
}

func TestCreateSecondaryEmail(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	storer := auth.NewFakeStorer(auth.FakeStorerConfig{CreateSecondaryEmailErr: errors.New("failed")})
	createSecondaryEmail(storer, w, nil)
	checkBodyAndMethods(t, "failed\n", []string{"CreateSecondaryEmail"}, w, storer)
}

func TestUpdatePassword(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	storer := auth.NewFakeStorer(auth.FakeStorerConfig{UpdatePasswordErr: errors.New("failed")})
	updatePassword(storer, w, nil)
	checkBodyAndMethods(t, "failed\n", []string{"UpdatePassword"}, w, storer)
}

func TestVerifyEmail(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	storer := auth.NewFakeStorer(auth.FakeStorerConfig{VerifyEmailErr: errors.New("failed")})
	verifyEmail(storer, w, nil)
	checkBodyAndMethods(t, "failed\n", []string{"VerifyEmail"}, w, storer)
}

func TestAddUserHeader(t *testing.T) {
	log.SetOutput(&nilWriter{})
	w := httptest.NewRecorder()
	addUserHeader(`{"name": "value"}`, w)
	checkHeader(t, `{"name": "value"}`, w)
}

func checkBodyAndMethods(t *testing.T, expectedBody string, expectedMethodsCalled []string, w *httptest.ResponseRecorder, storer auth.FakeStorer) {
	checkBody(t, expectedBody, w)
	checkMethods(t, expectedMethodsCalled, storer)
}

func checkHeaderAndMethods(t *testing.T, expectedHeader string, expectedMethodsCalled []string, w *httptest.ResponseRecorder, storer auth.FakeStorer) {
	checkHeader(t, expectedHeader, w)
	checkMethods(t, expectedMethodsCalled, storer)
}

func checkBody(t *testing.T, expectedBody string, w *httptest.ResponseRecorder) {
	if actualBody := w.Body.String(); actualBody != expectedBody {
		t.Errorf("want body: %s, got %s", expectedBody, actualBody)
	}
}

func checkHeader(t *testing.T, expectedHeader string, w *httptest.ResponseRecorder) {
	if actualHeader := w.Header().Get("X-User"); actualHeader != expectedHeader {
		t.Errorf("want X-User Header: %s, got %s", expectedHeader, actualHeader)
	}
}

func checkMethods(t *testing.T, expectedMethodsCalled []string, storer auth.FakeStorer) {
	if methodsCalled := storer.MethodsCalled(); !reflect.DeepEqual(methodsCalled, expectedMethodsCalled) {
		t.Errorf("want methods: %v, got %v", expectedMethodsCalled, methodsCalled)
	}
}
