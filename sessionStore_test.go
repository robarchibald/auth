package nginxauth

import (
	"bytes"
	"errors"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

var futureTime time.Time = time.Now().Add(5 * time.Minute)
var pastTime time.Time = time.Now().Add(-5 * time.Minute)

func getStore(emailCookieToReturn *EmailCookie, sessionCookieToReturn *SessionCookie, rememberMeCookieToReturn *RememberMeCookie, hasCookieGetError, hasCookiePutError bool, backend *MockBackend) *SessionStore {
	cookieStore := NewMockCookieStore(map[string]interface{}{emailCookieName: emailCookieToReturn, sessionCookieName: sessionCookieToReturn, rememberMeCookieName: rememberMeCookieToReturn}, hasCookieGetError, hasCookiePutError)
	return &SessionStore{backend, &TextMailer{}, cookieStore, &http.Request{}}
}

func TestNewSessionStore(t *testing.T) {
	w := httptest.NewRecorder()
	r := &http.Request{}
	b := &MockBackend{}
	m := &TextMailer{}
	actual := NewSessionStore(b, m, w, r, cookieKey, "prefix", false)
	if actual.backend != b || actual.cookieStore.(*CookieStore).w != w || actual.cookieStore.(*CookieStore).r != r {
		t.Fatal("expected correct init")
	}
}

var getSessionTests = []struct {
	Scenario            string
	HasCookieGetError   bool
	HasCookiePutError   bool
	SessionCookie       *SessionCookie
	GetSessionReturn    *SessionReturn
	RenewSessionReturn  *SessionReturn
	GetRememberMeReturn *RememberMeReturn
	MethodsCalled       []string
	ExpectedResult      *UserLoginRememberMe
	ExpectedErr         string
}{
	{
		Scenario:         "Get Session Valid",
		SessionCookie:    sessionCookie(futureTime, futureTime),
		GetSessionReturn: session(futureTime, futureTime),
		MethodsCalled:    []string{"GetSession"},
	},
	{
		Scenario:          "Get Session Cookie Error",
		HasCookieGetError: true,
		ExpectedErr:       "Session cookie not found",
	},
	{
		Scenario:         "Get Session Error",
		SessionCookie:    sessionCookie(futureTime, futureTime),
		GetSessionReturn: &SessionReturn{&UserLoginSession{}, ErrSessionNotFound},
		MethodsCalled:    []string{"GetSession"},
		ExpectedErr:      "Failed to verify session",
	},
	{
		Scenario:           "Get Session Renew",
		SessionCookie:      sessionCookie(pastTime, futureTime),
		RenewSessionReturn: session(futureTime, futureTime),
		MethodsCalled:      []string{"RenewSession"},
	},
}

func TestGetSession(t *testing.T) {
	for i, test := range getSessionTests {
		backend := &MockBackend{GetSessionReturn: test.GetSessionReturn, RenewSessionReturn: test.RenewSessionReturn}
		store := getStore(nil, test.SessionCookie, nil, test.HasCookieGetError, test.HasCookiePutError, backend)
		val, err := store.GetSession()
		methods := store.backend.(*MockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected val:%v\tactual val:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.ExpectedResult, val, test.MethodsCalled, methods)
		}
	}
}

var renewSessionTests = []struct {
	Scenario            string
	RenewsAt            time.Time
	ExpiresAt           time.Time
	HasCookieGetError   bool
	HasCookiePutError   bool
	RememberCookie      *RememberMeCookie
	RenewSessionReturn  *SessionReturn
	GetRememberMeReturn *RememberMeReturn
	MethodsCalled       []string
	ExpectedResult      *UserLoginRememberMe
	ExpectedErr         string
}{
	{
		Scenario:           "Renew Error",
		RenewsAt:           pastTime,
		ExpiresAt:          futureTime,
		RenewSessionReturn: sessionErr(),
		MethodsCalled:      []string{"RenewSession"},
		ExpectedErr:        "Unable to renew session",
	},
	{
		Scenario:           "Renew Save cookie error",
		RenewsAt:           pastTime,
		ExpiresAt:          futureTime,
		HasCookiePutError:  true,
		RenewSessionReturn: session(futureTime, futureTime),
		MethodsCalled:      []string{"RenewSession"},
		ExpectedErr:        "Error saving session cookie",
	},
	{
		Scenario:          "Error Getting RememberMe",
		RenewsAt:          pastTime,
		ExpiresAt:         pastTime,
		HasCookieGetError: true,
		ExpectedErr:       "Unable to renew session",
	},
	{
		Scenario:            "Renew With RememberMe",
		RenewsAt:            pastTime,
		ExpiresAt:           pastTime,
		RememberCookie:      rememberCookie(futureTime, futureTime),
		RenewSessionReturn:  session(futureTime, futureTime),
		GetRememberMeReturn: rememberMe(futureTime, futureTime),
		MethodsCalled:       []string{"GetRememberMe", "RenewSession"},
	},
	{
		Scenario:            "Renew With RememberMe Error",
		RenewsAt:            pastTime,
		ExpiresAt:           pastTime,
		RememberCookie:      rememberCookie(futureTime, futureTime),
		GetRememberMeReturn: rememberMe(futureTime, futureTime),
		RenewSessionReturn:  &SessionReturn{nil, ErrSessionNotFound},
		MethodsCalled:       []string{"GetRememberMe", "RenewSession"},
		ExpectedErr:         "Problem renewing session",
	},
	{
		Scenario:            "Save cookie error",
		RenewsAt:            pastTime,
		ExpiresAt:           pastTime,
		RememberCookie:      rememberCookie(futureTime, futureTime),
		GetRememberMeReturn: rememberMe(futureTime, futureTime),
		RenewSessionReturn:  session(futureTime, futureTime),
		MethodsCalled:       []string{"GetRememberMe", "RenewSession"},
		HasCookiePutError:   true,
		ExpectedErr:         "Error saving session cookie",
	},
}

// NOTE - can't currently get coverage for the error at approx line 147 for the saveSessionCookie error
func TestRenewSession(t *testing.T) {
	for i, test := range renewSessionTests {
		backend := &MockBackend{RenewSessionReturn: test.RenewSessionReturn, GetRememberMeReturn: test.GetRememberMeReturn}
		store := getStore(nil, nil, test.RememberCookie, test.HasCookieGetError, test.HasCookiePutError, backend)
		val, err := store.renewSession("sessionId", &test.RenewsAt, &test.ExpiresAt)
		methods := store.backend.(*MockBackend).MethodsCalled
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
	RememberCookie        *RememberMeCookie
	GetRememberMeReturn   *RememberMeReturn
	RenewRememberMeReturn *RememberMeReturn
	MethodsCalled         []string
	ExpectedResult        *UserLoginRememberMe
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
		GetRememberMeReturn: &RememberMeReturn{&UserLoginRememberMe{}, ErrRememberMeNotFound},
		MethodsCalled:       []string{"GetRememberMe"},
		ExpectedErr:         "Unable to find matching RememberMe in DB",
	},
	{
		Scenario:            "Get RememberMe Hash Isn't equal",
		RememberCookie:      &RememberMeCookie{"selector", "bogusToken", futureTime, futureTime},
		GetRememberMeReturn: rememberMe(futureTime, futureTime),
		MethodsCalled:       []string{"GetRememberMe"},
		ExpectedErr:         "RememberMe cookie doesn't match backend token",
	},
	{
		Scenario:              "Renew RememberMe Error",
		RememberCookie:        rememberCookie(pastTime, futureTime),
		GetRememberMeReturn:   rememberMe(pastTime, futureTime),
		RenewRememberMeReturn: &RememberMeReturn{&UserLoginRememberMe{}, ErrRememberMeNotFound},
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
		backend := &MockBackend{GetRememberMeReturn: test.GetRememberMeReturn, RenewRememberMeReturn: test.RenewRememberMeReturn}
		store := getStore(nil, nil, test.RememberCookie, test.HasCookieGetError, test.HasCookiePutError, backend)
		val, err := store.getRememberMe()
		methods := store.backend.(*MockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected val:%v\tactual val:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.ExpectedResult, val, test.MethodsCalled, methods)
		}
	}
}

var loginTests = []struct {
	Scenario         string
	Email            string
	Password         string
	RememberMe       bool
	NewSessionReturn *SessionRememberReturn
	LoginReturn      *UserLogin
	ErrReturn        error
	MethodsCalled    []string
	ExpectedResult   *UserLoginRememberMe
	ExpectedErr      string
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
		Scenario:         "Can't get login",
		Email:            "email@example.com",
		Password:         "validPassword",
		ErrReturn:        errors.New("failed"),
		NewSessionReturn: sessionRemember(futureTime, futureTime),
		MethodsCalled:    []string{"GetUserLogin"},
		ExpectedErr:      "Invalid username or password",
	},
	{
		Scenario:      "Incorrect password",
		Email:         "email@example.com",
		Password:      "wrongPassword",
		LoginReturn:   &UserLogin{LoginId: 1},
		MethodsCalled: []string{"GetUserLogin"},
		ExpectedErr:   "Invalid username or password",
	},
	{
		Scenario:         "Got session",
		Email:            "email@example.com",
		Password:         "correctPassword",
		LoginReturn:      &UserLogin{LoginId: 1, ProviderKey: "zVNfmBbTwQZwyMsAizV1Guh_j7kcFbyG7-LRJeeJfXc="}, // hash of "correctPassword"
		NewSessionReturn: sessionRemember(futureTime, futureTime),
		MethodsCalled:    []string{"GetUserLogin", "NewSession"},
	},
}

func TestLogin(t *testing.T) {
	for i, test := range loginTests {
		backend := &MockBackend{LoginReturn: test.LoginReturn, ErrReturn: test.ErrReturn, NewSessionReturn: test.NewSessionReturn}
		store := getStore(nil, nil, nil, false, false, backend)
		val, err := store.login(test.Email, test.Password, test.RememberMe)
		methods := store.backend.(*MockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected val:%v\tactual val:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.ExpectedResult, val, test.MethodsCalled, methods)
		}
	}
}

var createSessionTests = []struct {
	Scenario          string
	RememberMe        bool
	HasCookieGetError bool
	HasCookiePutError bool
	SessionCookie     *SessionCookie
	NewSessionReturn  *SessionRememberReturn
	MethodsCalled     []string
	ExpectedResult    *UserLoginRememberMe
	ExpectedErr       string
}{
	{
		Scenario:         "New login session error",
		NewSessionReturn: sessionRememberErr(),
		MethodsCalled:    []string{"NewSession"},
		ExpectedErr:      "Unable to create new session",
	},
	{
		Scenario:         "Got session",
		NewSessionReturn: sessionRemember(futureTime, futureTime),
		MethodsCalled:    []string{"NewSession"},
	},
	{
		Scenario:         "Valid cookie.  delete in backend",
		SessionCookie:    sessionCookie(futureTime, futureTime),
		NewSessionReturn: sessionRemember(futureTime, futureTime),
		MethodsCalled:    []string{"NewSession"},
	},
	{
		Scenario:         "Set RememberMe",
		RememberMe:       true,
		NewSessionReturn: sessionRemember(futureTime, futureTime),
		MethodsCalled:    []string{"NewSession"},
	},
	{
		Scenario:          "Session Cookie save failure",
		HasCookiePutError: true,
		NewSessionReturn:  sessionRemember(futureTime, futureTime),
		MethodsCalled:     []string{"NewSession"},
		ExpectedErr:       "Error saving session cookie",
	},
	{
		Scenario:          "RememberMe Cookie save failure",
		RememberMe:        true,
		HasCookiePutError: true,
		NewSessionReturn:  sessionRemember(futureTime, futureTime),
		MethodsCalled:     []string{"NewSession"},
		ExpectedErr:       "Unable to save rememberMe cookie",
	},
}

func TestCreateSession(t *testing.T) {
	for i, test := range createSessionTests {
		backend := &MockBackend{NewSessionReturn: test.NewSessionReturn}
		store := getStore(nil, test.SessionCookie, nil, test.HasCookieGetError, test.HasCookiePutError, backend)
		val, err := store.createSession(1, test.RememberMe)
		methods := store.backend.(*MockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected val:%v\tactual val:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.ExpectedResult, val, test.MethodsCalled, methods)
		}
	}
}

var registerTests = []struct {
	Scenario      string
	Email         string
	AddUserReturn error
	MethodsCalled []string
	ExpectedErr   string
}{
	{
		Scenario:    "Invalid email",
		Email:       "invalid@bogus",
		ExpectedErr: "Invalid email",
	},
	{
		Scenario:      "Add User error",
		Email:         "validemail@test.com",
		AddUserReturn: errors.New("failed"),
		MethodsCalled: []string{"AddUser"},
		ExpectedErr:   "Unable to save user",
	},
	{
		Scenario:      "Send verify email",
		Email:         "validemail@test.com",
		MethodsCalled: []string{"AddUser"},
	},
}

func TestRegister(t *testing.T) {
	for i, test := range registerTests {
		backend := &MockBackend{AddUserReturn: test.AddUserReturn}
		store := getStore(nil, nil, nil, false, false, backend)
		err := store.register(test.Email)
		methods := store.backend.(*MockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.MethodsCalled, methods)
		}
	}
}

var createProfileTests = []struct {
	Scenario          string
	HasCookieGetError bool
	HasCookiePutError bool
	EmailCookie       *EmailCookie
	CreateLoginReturn *SessionReturn
	MethodsCalled     []string
	ExpectedErr       string
}{
	{
		Scenario:          "Error Getting email cookie",
		HasCookieGetError: true,
		ExpectedErr:       "Unable to get email verification cookie",
	},
	{
		Scenario:    "Invalid verification code",
		EmailCookie: &EmailCookie{EmailVerificationCode: "12345", ExpireTimeUTC: time.Now()},
		ExpectedErr: "Invalid email verification cookie",
	},
	{
		Scenario:          "Error Creating profile",
		EmailCookie:       &EmailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		CreateLoginReturn: sessionErr(),
		MethodsCalled:     []string{"CreateLogin"},
		ExpectedErr:       "Unable to create profile",
	},
	{
		Scenario:          "Error saving session cookie",
		EmailCookie:       &EmailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		HasCookiePutError: true,
		CreateLoginReturn: session(futureTime, futureTime),
		MethodsCalled:     []string{"CreateLogin"},
		ExpectedErr:       "Error saving session cookie",
	},
	{
		Scenario:          "Success",
		EmailCookie:       &EmailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		CreateLoginReturn: session(futureTime, futureTime),
		MethodsCalled:     []string{"CreateLogin"},
	},
}

func TestCreateProfile(t *testing.T) {
	for i, test := range createProfileTests {
		backend := &MockBackend{CreateLoginReturn: test.CreateLoginReturn}
		store := getStore(test.EmailCookie, nil, nil, test.HasCookieGetError, test.HasCookiePutError, backend)
		err := store.createProfile("name", "organization", "password", "path")
		methods := store.backend.(*MockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.MethodsCalled, methods)
		}
	}
}

var verifyEmailTests = []struct {
	Scenario          string
	EmailVerifyCode   string
	SessionCookie     *SessionCookie
	VerifyEmailReturn *VerifyEmailReturn
	MethodsCalled     []string
	ExpectedErr       string
}{
	{
		Scenario:          "Decode error",
		EmailVerifyCode:   "code",
		VerifyEmailReturn: verifyEmailErr(),
		ExpectedErr:       "Invalid verification code",
	},
	{
		Scenario:          "Verify Email Error",
		EmailVerifyCode:   "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0",
		VerifyEmailReturn: verifyEmailErr(),
		MethodsCalled:     []string{"VerifyEmail"},
		ExpectedErr:       "Failed to verify email",
	},
	{
		Scenario:          "Email sent",
		EmailVerifyCode:   "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0",
		VerifyEmailReturn: verifyEmail(),
		MethodsCalled:     []string{"VerifyEmail"},
	},
}

func TestVerifyEmail(t *testing.T) {
	for i, test := range verifyEmailTests {
		backend := &MockBackend{VerifyEmailReturn: test.VerifyEmailReturn}
		store := getStore(nil, test.SessionCookie, nil, false, false, backend)
		err := store.verifyEmail(test.EmailVerifyCode)
		methods := store.backend.(*MockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.MethodsCalled, methods)
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
	backend := &MockBackend{}
	store := getStore(nil, nil, nil, true, false, backend)
	store.r = r
	err := store.Register()
	if err == nil || err.Error() != "Invalid email" {
		t.Error("expected error from child register method", err)
	}

	buf.WriteString("b")
	err = store.Register()
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
	r := &http.Request{Body: ioutil.NopCloser(&buf)}
	backend := &MockBackend{VerifyEmailReturn: verifyEmailErr()}
	store := getStore(nil, nil, nil, true, false, backend)
	store.r = r
	err := store.VerifyEmail()
	if err == nil || err.Error() != "Failed to verify email" {
		t.Error("expected error from child verifyEmail method", err)
	}

	buf.WriteString("b")
	err = store.VerifyEmail()
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
	buf.WriteString(`{"Email":"email", "Password":"password", "RememberMe":true}`)
	r := &http.Request{Body: ioutil.NopCloser(&buf)}
	backend := &MockBackend{}
	store := getStore(nil, nil, nil, true, false, backend)
	store.r = r
	err := store.Login()
	if err == nil || err.Error() != "Please enter a valid email address." {
		t.Error("expected error from login method", err)
	}

	buf.WriteString("b")
	err = store.Login()
	if err == nil || err.Error() != "Unable to get credentials" {
		t.Error("expected error from login method", err)
	}

}

func TestGetProfile(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("fullName", "name")
	w.WriteField("Organization", "org")
	w.WriteField("password", "pass")
	file, _ := os.Open("cover.out")
	data, _ := ioutil.ReadAll(file)
	tmpFile, _ := ioutil.TempFile("", "profile")
	part, _ := w.CreateFormFile("file", tmpFile.Name())
	part.Write(data)
	w.Close()

	r, _ := http.NewRequest("PUT", "url", &buf)
	r.Header.Add("Content-Type", w.FormDataContentType())
	profile, _ := getProfile(r)
	if profile.FullName != "name" || profile.Organization != "org" || profile.Password != "pass" {
		t.Error("expected correct profile", profile)
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
	backend := &MockBackend{}
	store := getStore(nil, nil, nil, true, false, backend)
	store.r = r
	err := store.CreateProfile()
	if err == nil || err.Error() != "Unable to get email verification cookie" {
		t.Error("expected error from CreateProfile method", err)
	}

	store.r = &http.Request{Body: ioutil.NopCloser(&buf)}
	err = store.CreateProfile()
	if err == nil || err.Error() != "Unable to get profile information from form" {
		t.Error("expected error from CreateProfile method", err)
	}
}

func TestGetBaseUrl(t *testing.T) {
	actual := getBaseUrl("http://www.hello.com/anywhere/but/here.html")
	if actual != "http://www.hello.com" {
		t.Error("expected base url", actual)
	}

	actual = getBaseUrl("http://www.hello.com")
	if actual != "http://www.hello.com" {
		t.Error("expected base url", actual)
	}

	actual = getBaseUrl("anywhere/but/here.html")
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

/****************************************************************************/
type MockSessionStore struct {
}

func NewMockSessionStore() *MockSessionStore {
	return &MockSessionStore{}
}

func (s *MockSessionStore) Get() (*UserLoginSession, error) {
	return nil, nil
}
func (s *MockSessionStore) GetRememberMe() (*UserLoginRememberMe, error) {
	return nil, nil
}
func (s *MockSessionStore) Login(email, password, returnUrl string) (*UserLoginSession, error) {
	return nil, nil
}
