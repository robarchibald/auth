package auth

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
)

var futureTime = time.Now().Add(5 * time.Minute)
var pastTime = time.Now().Add(-5 * time.Minute)

func getAuthStore(emailCookie *emailCookie, sessionCookie *sessionCookie, rememberCookie *rememberMeCookie, hasCookieGetError, hasCookiePutError bool, mailErr error, backend *mockBackend) *authStore {
	cookieStore := NewMockCookieStore(map[string]interface{}{emailCookieName: emailCookie, sessionCookieName: sessionCookie, rememberMeCookieName: rememberCookie}, hasCookieGetError, hasCookiePutError)
	return &authStore{backend, &TextMailer{Err: mailErr}, cookieStore}
}

func TestNewAuthStore(t *testing.T) {
	b := &mockBackend{}
	m := &TextMailer{}
	actual := NewAuthStore(b, m, "prefix", cookieKey).(*authStore)
	if actual.backend != b || actual.cookieStore.(*cookieStore).s == nil {
		t.Fatal("expected correct init")
	}
}

var getSessionTests = []struct {
	Scenario            string
	HasCookieGetError   bool
	HasCookiePutError   bool
	SessionCookie       *sessionCookie
	GetSessionReturn    *SessionReturn
	RenewSessionReturn  *SessionReturn
	GetRememberMeReturn *RememberMeReturn
	CSRFToken           string
	MethodsCalled       []string
	ExpectedResult      *rememberMeSession
	ExpectedErr         string
}{
	{
		Scenario:         "Get Session Valid",
		CSRFToken:        "csrfToken",
		SessionCookie:    sessionCookieGood(futureTime, futureTime),
		GetSessionReturn: sessionSuccess(futureTime, futureTime),
		MethodsCalled:    []string{"GetSession"},
	},
	{
		Scenario:    "No CSRFToken",
		ExpectedErr: "Missing CSRF token",
	},
	{
		Scenario:          "Get Session Cookie Error",
		CSRFToken:         "token",
		HasCookieGetError: true,
		ExpectedErr:       "Session cookie not found",
	},
	{
		Scenario:      "Get Session Invalid Cookie Error",
		CSRFToken:     "token",
		SessionCookie: sessionCookieBogus(futureTime, futureTime),
		ExpectedErr:   "Unable to decode session cookie",
	},
	{
		Scenario:         "Get Session Error",
		CSRFToken:        "token",
		SessionCookie:    sessionCookieGood(futureTime, futureTime),
		GetSessionReturn: &SessionReturn{&LoginSession{}, errSessionNotFound},
		MethodsCalled:    []string{"GetSession"},
		ExpectedErr:      "Failed to verify session",
	},
	{
		Scenario:         "Get Session, invalid CSRF",
		CSRFToken:        "token",
		SessionCookie:    sessionCookieGood(futureTime, futureTime),
		GetSessionReturn: sessionSuccess(futureTime, futureTime),
		MethodsCalled:    []string{"GetSession"},
		ExpectedErr:      "Invalid CSRF token",
	},
	{
		Scenario:         "Get Session Renew",
		CSRFToken:        "csrfToken",
		SessionCookie:    sessionCookieGood(futureTime, futureTime),
		GetSessionReturn: sessionSuccess(futureTime, futureTime),
		MethodsCalled:    []string{"GetSession"},
	},
}

func TestGetSession(t *testing.T) {
	for i, test := range getSessionTests {
		backend := &mockBackend{GetSessionReturn: test.GetSessionReturn, RenewSessionReturn: test.RenewSessionReturn}
		store := getAuthStore(nil, test.SessionCookie, nil, false, false, nil, backend)
		//store := getSessionStore(nil, test.SessionCookie, nil, test.HasCookieGetError, test.HasCookiePutError, backend)
		h := http.Header{}
		if test.CSRFToken != "" {
			h.Add("X-CSRF-Token", test.CSRFToken)
		}
		val, err := store.GetSession(nil, &http.Request{Header: h})

		methods := store.backend.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected val:%v\tactual val:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.ExpectedResult, val, test.MethodsCalled, methods)
		}
	}
}

var renewSessionTests = []struct {
	Scenario            string
	RenewTimeUTC        time.Time
	ExpireTimeUTC       time.Time
	HasCookieGetError   bool
	HasCookiePutError   bool
	RememberCookie      *rememberMeCookie
	RenewSessionReturn  *SessionReturn
	GetRememberMeReturn *RememberMeReturn
	MethodsCalled       []string
	ExpectedResult      *rememberMeSession
	ExpectedErr         string
}{
	{
		Scenario:            "Successful renew With RememberMe",
		RenewTimeUTC:        pastTime,
		ExpireTimeUTC:       pastTime,
		RememberCookie:      rememberCookie(futureTime, futureTime),
		RenewSessionReturn:  sessionSuccess(futureTime, futureTime),
		GetRememberMeReturn: rememberMe(futureTime, futureTime),
		MethodsCalled:       []string{"GetRememberMe", "RenewSession"},
	},
	{
		Scenario:          "Renew With RememberMe Error",
		RenewTimeUTC:      pastTime,
		ExpireTimeUTC:     pastTime,
		RememberCookie:    rememberCookie(futureTime, futureTime),
		HasCookieGetError: true,
		ExpectedErr:       "Unable to renew session",
	},
	{
		Scenario:           "Renew Error",
		RenewTimeUTC:       pastTime,
		ExpireTimeUTC:      futureTime,
		RenewSessionReturn: &SessionReturn{nil, errSessionNotFound},
		MethodsCalled:      []string{"RenewSession"},
		ExpectedErr:        "Problem renewing session",
	},
	{
		Scenario:           "Renew Save cookie error",
		RenewTimeUTC:       pastTime,
		ExpireTimeUTC:      futureTime,
		HasCookiePutError:  true,
		RenewSessionReturn: sessionSuccess(futureTime, futureTime),
		MethodsCalled:      []string{"RenewSession"},
		ExpectedErr:        "Error saving session cookie",
	},
	{
		Scenario:            "Success with no rememberme",
		RenewTimeUTC:        pastTime,
		ExpireTimeUTC:       futureTime,
		RememberCookie:      rememberCookie(futureTime, futureTime),
		GetRememberMeReturn: rememberMe(futureTime, futureTime),
		RenewSessionReturn:  sessionSuccess(futureTime, futureTime),
		MethodsCalled:       []string{"RenewSession"},
	},
}

// NOTE - can't currently get coverage for the error at approx line 147 for the saveSessionCookie error
func TestRenewSession(t *testing.T) {
	for i, test := range renewSessionTests {
		backend := &mockBackend{RenewSessionReturn: test.RenewSessionReturn, GetRememberMeReturn: test.GetRememberMeReturn}
		store := getAuthStore(nil, nil, test.RememberCookie, test.HasCookieGetError, test.HasCookiePutError, nil, backend)
		val, err := store.renewSession(nil, &http.Request{}, "sessionId", "sessionHash", &test.RenewTimeUTC, &test.ExpireTimeUTC)
		methods := store.backend.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected val:%v\tactual val:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.ExpectedResult, val, test.MethodsCalled, methods)
		}
	}
}

var rememberMeTests = []struct {
	Scenario              string
	HasCookieGetError     bool
	HasCookiePutError     bool
	RememberCookie        *rememberMeCookie
	GetRememberMeReturn   *RememberMeReturn
	RenewRememberMeReturn *RememberMeReturn
	MethodsCalled         []string
	ExpectedResult        *rememberMeSession
	ExpectedErr           string
}{
	{
		Scenario:          "Get RememberMe Cookie err",
		HasCookieGetError: true,
		ExpectedErr:       "RememberMe cookie not found",
	},
	{
		Scenario:            "Renew RememberMe Expired",
		RememberCookie:      rememberCookie(pastTime, pastTime),
		GetRememberMeReturn: rememberMe(pastTime, pastTime),
		ExpectedErr:         "RememberMe cookie has expired",
	},
	{
		Scenario:            "Get RememberMe Error",
		RememberCookie:      rememberCookie(futureTime, futureTime),
		GetRememberMeReturn: &RememberMeReturn{&rememberMeSession{}, errRememberMeNotFound},
		MethodsCalled:       []string{"GetRememberMe"},
		ExpectedErr:         "Unable to find matching RememberMe in DB",
	},
	{
		Scenario:            "Get RememberMe Hash Isn't equal",
		RememberCookie:      &rememberMeCookie{"selector", "bogusToken", futureTime, futureTime},
		GetRememberMeReturn: rememberMe(futureTime, futureTime),
		MethodsCalled:       []string{"GetRememberMe"},
		ExpectedErr:         "RememberMe cookie doesn't match backend token",
	},
	{
		Scenario:              "Renew RememberMe Error",
		RememberCookie:        rememberCookie(pastTime, futureTime),
		GetRememberMeReturn:   rememberMe(pastTime, futureTime),
		RenewRememberMeReturn: &RememberMeReturn{&rememberMeSession{}, errRememberMeNotFound},
		MethodsCalled:         []string{"GetRememberMe", "RenewRememberMe"},
		ExpectedErr:           "Unable to renew RememberMe",
	},
	{
		Scenario:              "Renew RememberMe Success",
		RememberCookie:        rememberCookie(pastTime, futureTime),
		GetRememberMeReturn:   rememberMe(pastTime, futureTime),
		RenewRememberMeReturn: rememberMe(futureTime, futureTime),
		MethodsCalled:         []string{"GetRememberMe", "RenewRememberMe"},
	},
}

func TestRememberMe(t *testing.T) {
	for i, test := range rememberMeTests {
		backend := &mockBackend{GetRememberMeReturn: test.GetRememberMeReturn, RenewRememberMeReturn: test.RenewRememberMeReturn}
		store := getAuthStore(nil, nil, test.RememberCookie, test.HasCookieGetError, test.HasCookiePutError, nil, backend)
		val, err := store.getRememberMe(nil, &http.Request{})
		methods := store.backend.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected val:%v\tactual val:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.ExpectedResult, val, test.MethodsCalled, methods)
		}
	}
}

// Doesn't cover the crypto failures generating hashes
var createSessionTests = []struct {
	Scenario            string
	RememberMe          bool
	HasCookieGetError   bool
	HasCookiePutError   bool
	SessionCookie       *sessionCookie
	RememberMeCookie    *rememberMeCookie
	CreateSessionReturn *SessionRememberReturn
	MethodsCalled       []string
	ExpectedResult      *rememberMeSession
	ExpectedErr         string
}{
	{
		Scenario:            "New login session error",
		CreateSessionReturn: sessionRememberErr(),
		MethodsCalled:       []string{"CreateSession"},
		ExpectedErr:         "Unable to create new session",
	},
	{
		Scenario:            "Couldn't get session cookie",
		CreateSessionReturn: sessionRemember(futureTime, futureTime),
		HasCookieGetError:   true,
		MethodsCalled:       []string{"CreateSession"},
	},
	{
		Scenario:            "Valid old session and rememberme cookies.  delete in backend",
		SessionCookie:       sessionCookieGood(futureTime, futureTime),
		RememberMeCookie:    rememberCookie(futureTime, futureTime),
		CreateSessionReturn: sessionRemember(futureTime, futureTime),
		MethodsCalled:       []string{"CreateSession", "InvalidateSession", "InvalidateRememberMe"},
	},
	{
		Scenario:            "Set RememberMe",
		RememberMe:          true,
		HasCookieGetError:   true,
		CreateSessionReturn: sessionRemember(futureTime, futureTime),
		MethodsCalled:       []string{"CreateSession"},
	},
	{
		Scenario:            "Session Cookie save failure",
		HasCookieGetError:   true,
		HasCookiePutError:   true,
		CreateSessionReturn: sessionRemember(futureTime, futureTime),
		MethodsCalled:       []string{"CreateSession"},
		ExpectedErr:         "Error saving session cookie",
	},
	{
		Scenario:            "RememberMe Cookie save failure",
		RememberMe:          true,
		HasCookieGetError:   true,
		HasCookiePutError:   true,
		CreateSessionReturn: sessionRemember(futureTime, futureTime),
		MethodsCalled:       []string{"CreateSession"},
		ExpectedErr:         "Unable to save rememberMe cookie",
	},
}

func TestCreateSession(t *testing.T) {
	for i, test := range createSessionTests {
		backend := &mockBackend{CreateSessionReturn: test.CreateSessionReturn}
		store := getAuthStore(nil, test.SessionCookie, test.RememberMeCookie, test.HasCookieGetError, test.HasCookiePutError, nil, backend)
		val, err := store.createSession(nil, &http.Request{}, "test@test.com", "1", "fullname", test.RememberMe)
		methods := store.backend.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected val:%v\tactual val:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.ExpectedResult, val, test.MethodsCalled, methods)
		}
	}
}

func TestAuthGetBasicAuth(t *testing.T) {
	// found session
	store := getAuthStore(nil, sessionCookieGood(futureTime, futureTime), nil, false, false, nil, &mockBackend{GetSessionReturn: sessionSuccess(futureTime, futureTime)})
	r := &http.Request{Header: http.Header{}}
	r.Header.Add("X-CSRF-Token", "csrfToken")
	if _, err := store.GetBasicAuth(nil, r); err != nil {
		t.Error("expected success", err)
	}

	// Credential error
	store = getAuthStore(nil, nil, nil, true, false, nil, &mockBackend{LoginReturn: loginErr()})
	if _, err := store.GetBasicAuth(nil, &http.Request{}); err == nil || err.Error() != "Problem decoding credentials from basic auth" {
		t.Error("expected error")
	}

	// login error
	store = getAuthStore(nil, nil, nil, true, false, nil, &mockBackend{LoginReturn: loginErr(), GetSessionReturn: sessionSuccess(futureTime, futureTime)})
	if _, err := store.GetBasicAuth(nil, basicAuthRequest("test@test.com", "password")); err == nil || err.Error() != "Invalid username or password" {
		t.Error("expected error", err)
	}

	// login success
	store = getAuthStore(nil, nil, nil, true, false, nil, &mockBackend{LoginReturn: loginSuccess(), GetSessionReturn: sessionSuccess(futureTime, futureTime), CreateSessionReturn: sessionRemember(futureTime, futureTime)})
	if _, err := store.GetBasicAuth(nil, basicAuthRequest("test@test.com", "correctPassword")); err != nil {
		t.Error("expected success")
	}
}

func basicAuthRequest(username, password string) *http.Request {
	r, _ := http.NewRequest("GET", "bogus", nil)
	auth := username + ":" + password
	auth = base64.StdEncoding.EncodeToString([]byte(auth))
	r.Header.Add("Authorization", "Basic "+auth)
	return r
}

var registerTests = []struct {
	Scenario                 string
	Email                    string
	CreateEmailSessionReturn error
	GetUserReturn            *GetUserReturn
	MailErr                  error
	MethodsCalled            []string
	ExpectedErr              string
}{
	{
		Scenario:    "Invalid email",
		Email:       "invalid@bogus",
		ExpectedErr: "Invalid email",
	},
	{
		Scenario:      "User Already Exists",
		Email:         "validemail@test.com",
		GetUserReturn: getUserSuccess(),
		MethodsCalled: []string{"GetUser"},
		ExpectedErr:   "User already registered",
	},
	{
		Scenario: "Add User error",
		Email:    "validemail@test.com",
		CreateEmailSessionReturn: errors.New("failed"),
		GetUserReturn:            getUserErr(),
		MethodsCalled:            []string{"GetUser", "CreateEmailSession"},
		ExpectedErr:              "Unable to save user",
	},
	{
		Scenario:      "Can't send email",
		GetUserReturn: getUserErr(),
		Email:         "validemail@test.com",
		MailErr:       errors.New("fail"),
		MethodsCalled: []string{"GetUser", "CreateEmailSession"},
		ExpectedErr:   "Unable to send verification email",
	},
	{
		Scenario:      "Send verify email",
		GetUserReturn: getUserErr(),
		Email:         "validemail@test.com",
		MethodsCalled: []string{"GetUser", "CreateEmailSession"},
	},
}

func TestAuthRegister(t *testing.T) {
	for i, test := range registerTests {
		backend := &mockBackend{ErrReturn: test.CreateEmailSessionReturn, GetUserReturn: test.GetUserReturn}
		store := getAuthStore(nil, nil, nil, false, false, test.MailErr, backend)
		err := store.register(&http.Request{}, test.Email, "destinationURL")
		methods := store.backend.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.MethodsCalled, methods)
		}
	}
}

var createProfileTests = []struct {
	Scenario                 string
	HasCookieGetError        bool
	HasCookiePutError        bool
	getEmailSessionReturn    *getEmailSessionReturn
	EmailCookie              *emailCookie
	CSRFToken                string
	LoginReturn              *LoginReturn
	UpdateUserReturn         error
	DeleteEmailSessionReturn error
	CreateSessionReturn      *SessionRememberReturn
	MethodsCalled            []string
	ExpectedErr              string
}{
	{
		Scenario:          "Error Getting email cookie",
		HasCookieGetError: true,
		ExpectedErr:       "Unable to get email verification cookie",
	},
	{
		Scenario:    "Invalid verification code",
		EmailCookie: &emailCookie{EmailVerificationCode: "12345", ExpireTimeUTC: time.Now()},
		ExpectedErr: "Invalid email verification cookie",
	},
	{
		Scenario:              "Can't get EmailSession",
		EmailCookie:           &emailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		getEmailSessionReturn: getEmailSessionErr(),
		MethodsCalled:         []string{"GetEmailSession"},
		ExpectedErr:           "Invalid email verification",
	},
	{
		Scenario:              "Invalid CSRF token",
		CSRFToken:             "token",
		EmailCookie:           &emailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		getEmailSessionReturn: getEmailSessionSuccess(),
		MethodsCalled:         []string{"GetEmailSession"},
		ExpectedErr:           "Invalid CSRF token",
	},
	{
		Scenario:              "Error Updating user",
		CSRFToken:             "csrfToken",
		EmailCookie:           &emailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		getEmailSessionReturn: getEmailSessionSuccess(),
		UpdateUserReturn:      errors.New("failed"),
		LoginReturn:           loginErr(),
		MethodsCalled:         []string{"GetEmailSession", "UpdateUser"},
		ExpectedErr:           "Unable to update user",
	},
	{
		Scenario:                 "Error Deleting Email Session",
		CSRFToken:                "csrfToken",
		EmailCookie:              &emailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		getEmailSessionReturn:    getEmailSessionSuccess(),
		DeleteEmailSessionReturn: errors.New("failed"),
		LoginReturn:              loginErr(),
		MethodsCalled:            []string{"GetEmailSession", "UpdateUser", "DeleteEmailSession"},
		ExpectedErr:              "Error while creating profile",
	},
	{
		Scenario:              "Error Creating login",
		CSRFToken:             "csrfToken",
		EmailCookie:           &emailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		getEmailSessionReturn: getEmailSessionSuccess(),
		LoginReturn:           loginErr(),
		MethodsCalled:         []string{"GetEmailSession", "UpdateUser", "DeleteEmailSession", "CreateLogin"},
		ExpectedErr:           "Unable to create login",
	},
	{
		Scenario:              "Error creating session",
		CSRFToken:             "csrfToken",
		EmailCookie:           &emailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		getEmailSessionReturn: getEmailSessionSuccess(),
		LoginReturn:           loginSuccess(),
		CreateSessionReturn:   sessionRememberErr(),
		MethodsCalled:         []string{"GetEmailSession", "UpdateUser", "DeleteEmailSession", "CreateLogin", "CreateSession"},
		ExpectedErr:           "Unable to create new session",
	},
	{
		Scenario:              "Success",
		CSRFToken:             "csrfToken",
		EmailCookie:           &emailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		getEmailSessionReturn: getEmailSessionSuccess(),
		LoginReturn:           loginSuccess(),
		CreateSessionReturn:   sessionRemember(futureTime, futureTime),
		MethodsCalled:         []string{"GetEmailSession", "UpdateUser", "DeleteEmailSession", "CreateLogin", "CreateSession", "InvalidateSession", "InvalidateRememberMe"},
	},
}

func TestAuthCreateProfile(t *testing.T) {
	for i, test := range createProfileTests {
		backend := &mockBackend{ErrReturn: test.UpdateUserReturn, getEmailSessionReturn: test.getEmailSessionReturn, CreateLoginReturn: test.LoginReturn, CreateSessionReturn: test.CreateSessionReturn, DeleteEmailSessionReturn: test.DeleteEmailSessionReturn}
		store := getAuthStore(test.EmailCookie, nil, nil, test.HasCookieGetError, test.HasCookiePutError, nil, backend)
		_, err := store.createProfile(nil, &http.Request{}, test.CSRFToken, "name", "organization", "password", "path")
		methods := store.backend.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.MethodsCalled, methods)
		}
	}
}

var verifyEmailTests = []struct {
	Scenario                 string
	EmailVerificationCode    string
	HasCookiePutError        bool
	getEmailSessionReturn    *getEmailSessionReturn
	AddUserReturn            error
	UpdateEmailSessionReturn error
	MailErr                  error
	MethodsCalled            []string
	ExpectedErr              string
	DestinatinURL            string
}{
	{
		Scenario:              "Decode error",
		EmailVerificationCode: "code",
		getEmailSessionReturn: getEmailSessionErr(),
		ExpectedErr:           "Invalid verification code",
	},
	{
		Scenario:              "Verify Email Error",
		EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0",
		getEmailSessionReturn: getEmailSessionErr(),
		MethodsCalled:         []string{"GetEmailSession"},
		ExpectedErr:           "Failed to verify email",
	},
	{
		Scenario:              "Add User fail",
		EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0",
		getEmailSessionReturn: getEmailSessionSuccess(),
		AddUserReturn:         errors.New("fail"),
		MethodsCalled:         []string{"GetEmailSession", "AddUser", "GetUser"},
		ExpectedErr:           "Failed to get user in database",
	},
	{
		Scenario:                 "Email session update fail",
		EmailVerificationCode:    "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0",
		getEmailSessionReturn:    getEmailSessionSuccess(),
		UpdateEmailSessionReturn: errors.New("fail"),
		MethodsCalled:            []string{"GetEmailSession", "AddUser", "UpdateEmailSession"},
		ExpectedErr:              "Failed to update email session",
	},
	{
		Scenario:              "Cookie Save Error",
		EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0",
		getEmailSessionReturn: getEmailSessionSuccess(),
		HasCookiePutError:     true,
		MethodsCalled:         []string{"GetEmailSession", "AddUser", "UpdateEmailSession"},
		ExpectedErr:           "Failed to save email cookie",
	},
	{
		Scenario:              "Mail Error",
		EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0",
		getEmailSessionReturn: getEmailSessionSuccess(),
		MethodsCalled:         []string{"GetEmailSession", "AddUser", "UpdateEmailSession"},
		MailErr:               errors.New("test"),
		ExpectedErr:           "Failed to send welcome email",
	},
	{
		Scenario:              "Email sent",
		EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0",
		getEmailSessionReturn: getEmailSessionSuccess(),
		DestinatinURL:         "destinationURL",
		MethodsCalled:         []string{"GetEmailSession", "AddUser", "UpdateEmailSession"},
	},
}

func TestAuthVerifyEmail(t *testing.T) {
	for i, test := range verifyEmailTests {
		backend := &mockBackend{getEmailSessionReturn: test.getEmailSessionReturn, AddUserReturn: test.AddUserReturn, UpdateEmailSessionReturn: test.UpdateEmailSessionReturn}
		store := getAuthStore(nil, nil, nil, false, test.HasCookiePutError, test.MailErr, backend)
		_, destinationURL, err := store.verifyEmail(nil, &http.Request{}, test.EmailVerificationCode)
		methods := store.backend.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) || test.DestinatinURL != destinationURL {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected methods: %s\tactual methods: %s, destination: %s", i, test.Scenario, test.ExpectedErr, err, test.MethodsCalled, methods, destinationURL)
		}
	}
}

var loginTests = []struct {
	Scenario            string
	Email               string
	Password            string
	RememberMe          bool
	CreateSessionReturn *SessionRememberReturn
	LoginReturn         *LoginReturn
	ErrReturn           error
	MethodsCalled       []string
	ExpectedResult      *rememberMeSession
	ExpectedErr         string
}{
	{
		Scenario:    "Invalid email",
		Email:       "invalid@bogus",
		ExpectedErr: "Please enter a valid email address.",
	},
	{
		Scenario:    "Invalid password",
		Email:       "email@example.com",
		Password:    "short",
		ExpectedErr: passwordValidationMessage,
	},
	{
		Scenario:      "Can't get login",
		Email:         "email@example.com",
		Password:      "validPassword",
		LoginReturn:   loginErr(),
		MethodsCalled: []string{"Login"},
		ExpectedErr:   "Invalid username or password",
	},
	{
		Scenario:            "Got session",
		Email:               "email@example.com",
		Password:            "correctPassword",
		LoginReturn:         loginSuccess(),
		CreateSessionReturn: sessionRemember(futureTime, futureTime),
		MethodsCalled:       []string{"Login", "CreateSession", "InvalidateSession", "InvalidateRememberMe"},
	},
}

func TestAuthLogin(t *testing.T) {
	for i, test := range loginTests {
		backend := &mockBackend{LoginReturn: test.LoginReturn, ErrReturn: test.ErrReturn, CreateSessionReturn: test.CreateSessionReturn}
		store := getAuthStore(nil, nil, nil, false, false, nil, backend)
		val, err := store.login(nil, &http.Request{}, test.Email, test.Password, test.RememberMe)
		methods := store.backend.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected val:%v\tactual val:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.ExpectedResult, val, test.MethodsCalled, methods)
		}
	}
}

func TestGetRegistration(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"Email":"my.email@test.com"}`)
	r := &http.Request{Body: ioutil.NopCloser(&buf)}
	reg, _ := getRegistration(r)
	if reg.Email != "my.email@test.com" {
		t.Error("expected registration to be filled", reg)
	}
}

func TestRegisterPub(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"Email":"bogus"}`)
	r := &http.Request{Body: ioutil.NopCloser(&buf)}
	backend := &mockBackend{}
	store := getAuthStore(nil, nil, nil, true, false, nil, backend)
	err := store.Register(nil, r)
	if err == nil || err.Error() != "Invalid email" {
		t.Error("expected error from child register method", err)
	}

	buf.WriteString("b")
	err = store.Register(nil, r)
	if err == nil || !strings.HasPrefix(err.Error(), "Unable to get email") {
		t.Error("expected error from parent Register method", err)
	}
}

func TestGetVerificationCode(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"EmailVerificationCode":"code"}`)
	r := &http.Request{Body: ioutil.NopCloser(&buf)}
	verify, _ := getVerificationCode(r)
	if verify.EmailVerificationCode != "code" {
		t.Error("expected verify to be filled", verify)
	}
}

func TestVerifyEmailPub(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"EmailVerificationCode":"nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0"}`) // random valid base64 encoded data
	r := &http.Request{Body: ioutil.NopCloser(&buf), Header: http.Header{}}
	r.Header.Add("X-CSRF-Token", "token")
	backend := &mockBackend{getEmailSessionReturn: getEmailSessionErr()}
	store := getAuthStore(nil, nil, nil, true, false, nil, backend)
	_, _, err := store.VerifyEmail(nil, r)
	if err == nil || err.Error() != "Failed to verify email" {
		t.Error("expected error from child verifyEmail method", err)
	}

	buf.WriteString("b")
	_, _, err = store.VerifyEmail(nil, r)
	if err == nil || err.Error() != "Unable to get verification email from JSON" {
		t.Error("expected error from VerifyEmail method", err)
	}
}

func TestGetCredentials(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"Email":"email", "Password":"password", "RememberMe":true}`)
	r := &http.Request{Body: ioutil.NopCloser(&buf)}
	credentials, err := getCredentials(r)
	if err != nil || credentials.Email != "email" || credentials.Password != "password" || credentials.RememberMe != true {
		t.Error("expected credentials to be filled", credentials, err)
	}
}

func TestLoginJson(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"Email":"test@test.com", "Password":"password", "RememberMe":true}`)
	r := &http.Request{Body: ioutil.NopCloser(&buf)}
	backend := &mockBackend{LoginReturn: loginErr()}
	store := getAuthStore(nil, nil, nil, true, false, nil, backend)
	_, lErr := store.Login(nil, r)
	err := lErr.(*AuthError).innerError
	if err == nil || err.Error() != "failed" {
		t.Error("expected error from login method", err)
	}

	buf.WriteString("b")
	_, err = store.Login(nil, r)
	if err == nil || err.Error() != "Unable to get credentials" {
		t.Error("expected error from login method", err)
	}
}

func TestGetProfile(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("fullName", "name")
	w.WriteField("organization", "org")
	w.WriteField("password", "pass")
	w.WriteField("mailQuota", "1")
	w.WriteField("fileQuota", "1")
	file, _ := os.Open("cover.out")
	data, _ := ioutil.ReadAll(file)
	tmpFile, _ := ioutil.TempFile("", "profile")
	part, _ := w.CreateFormFile("file", tmpFile.Name())
	part.Write(data)
	w.Close()

	r, _ := http.NewRequest("PUT", "url", &buf)
	r.Header.Add("Content-Type", w.FormDataContentType())
	profile, err := getProfile(r)
	if err != nil || profile == nil || profile.FullName != "name" || profile.Organization != "org" || profile.Password != "pass" {
		t.Error("expected correct profile", profile, err)
	}
}

func TestCreateProfilePub(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	file, _ := os.Open("cover.out")
	data, _ := ioutil.ReadAll(file)
	tmpFile, _ := ioutil.TempFile("", "profile")
	part, _ := w.CreateFormFile("file", tmpFile.Name())
	part.Write(data)
	w.Close()

	r, _ := http.NewRequest("PUT", "url", &buf)
	r.Header.Add("Content-Type", w.FormDataContentType())
	r.Header.Add("X-CSRF-Token", "token")
	backend := &mockBackend{}
	store := getAuthStore(nil, nil, nil, true, false, nil, backend)
	_, err := store.CreateProfile(nil, r)
	if err == nil || err.Error() != "Unable to get email verification cookie" {
		t.Error("expected error from CreateProfile method", err)
	}

	r = &http.Request{Body: ioutil.NopCloser(&buf)}
	_, err = store.CreateProfile(nil, r)
	if err == nil || err.Error() != "Missing CSRF token" {
		t.Error("expected error from CreateProfile method", err)
	}
}

func TestGetBaseUrl(t *testing.T) {
	actual := getBaseURL("http://www.hello.com/anywhere/but/here.html")
	if actual != "http://www.hello.com" {
		t.Error("expected base url", actual)
	}

	actual = getBaseURL("http://www.hello.com")
	if actual != "http://www.hello.com" {
		t.Error("expected base url", actual)
	}

	actual = getBaseURL("anywhere/but/here.html")
	if actual != "https://endfirst.com" {
		t.Error("expected base url", actual)
	}
}

func collectionEqual(expected, actual []string) bool {
	if len(expected) != len(actual) {
		return false
	}
	for i, val := range expected {
		if actual[i] != val {
			return false
		}
	}
	return true
}
