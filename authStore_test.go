package main

import (
	"bytes"
	"errors"
	"github.com/robarchibald/substring"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

var futureTime = time.Now().Add(5 * time.Minute)
var pastTime = time.Now().Add(-5 * time.Minute)

func getAuthStore(sessionReturn *SessionReturn, loginReturn *LoginReturn, emailCookieToReturn *emailCookie, hasCookieGetError, hasCookiePutError bool, mailErr error, backend *mockBackend) *authStore {
	r := &http.Request{}
	cookieStore := NewMockCookieStore(map[string]interface{}{emailCookieName: emailCookieToReturn}, hasCookieGetError, hasCookiePutError)
	sessionStore := mockSessionStore{SessionReturn: sessionReturn}
	return &authStore{backend, &sessionStore, &TextMailer{Err: mailErr}, cookieStore, r}
}

func TestNewAuthStore(t *testing.T) {
	w := httptest.NewRecorder()
	r := &http.Request{}
	b := &mockBackend{}
	m := &TextMailer{}
	actual := newAuthStore(b, m, w, r, "prefix", cookieKey, false).(*authStore)
	if actual.backend != b || actual.cookieStore.(*cookieStore).w != w || actual.cookieStore.(*cookieStore).r != r {
		t.Fatal("expected correct init")
	}
}

func TestAuthGetSession(t *testing.T) {
	store := getAuthStore(sessionErr(), nil, nil, false, false, nil, &mockBackend{})
	if _, err := store.GetSession(); err == nil {
		t.Error("expected error")
	}
}

func TestAuthGetBasicAuth(t *testing.T) {
	// loginStore.LoginBasic error
	store := getAuthStore(sessionErr(), loginErr(), nil, false, false, nil, &mockBackend{})
	if _, err := store.GetBasicAuth(); err == nil {
		t.Error("expected error")
	}

	// createSession error
	store = getAuthStore(sessionErr(), loginSuccess(), nil, false, false, nil, &mockBackend{})
	if _, err := store.GetBasicAuth(); err == nil {
		t.Error("expected error")
	}

	// found session
	store = getAuthStore(sessionSuccess(futureTime, futureTime), nil, nil, false, false, nil, &mockBackend{})
	if _, err := store.GetBasicAuth(); err != nil {
		t.Error("expected success")
	}
}

func TestAuthStoreEndToEnd(t *testing.T) {
	w := httptest.NewRecorder()
	r := &http.Request{Header: http.Header{}}
	b := newBackendMemory().(*backendMemory)
	m := &TextMailer{}
	s := newAuthStore(b, m, w, r, "prefix", cookieKey, false).(*authStore)

	// register new user
	// adds to users, logins and sessions
	err := s.register("test@test.com")
	if err != nil || len(b.EmailSessions) != 1 || b.EmailSessions[0].Email != "test@test.com" || len(b.Sessions) != 0 {
		t.Fatal("expected to be able to add user", err, len(b.EmailSessions), b.EmailSessions[0], len(b.Sessions))
	}

	// get code from "email"
	data := m.MessageData.(*sendVerifyParams)

	// verify email
	err = s.verifyEmail(data.VerificationCode)

	// decode email cookie
	value := substring.Between(w.HeaderMap["Set-Cookie"][0], "prefixEmail=", ";")
	emailCookie := emailCookie{}
	cookieStoreInstance.Decode("prefixEmail", value, &emailCookie)
	emailVerifyHash, _ := decodeStringToHash(emailCookie.EmailVerificationCode)
	if len(b.EmailSessions) != 1 || b.EmailSessions[0].EmailVerifyHash != emailVerifyHash {
		t.Fatal("expected emailVerifyHash to be saved", b.EmailSessions[0], emailVerifyHash)
	}

	// add email cookie to the next request
	r.AddCookie(newCookie("prefixEmail", value, false, emailExpireMins))

	// create profile
	err = s.createProfile("fullName", "company", "password", "picturePath", 1, 1)
	hashErr := cryptoHashEquals("password", b.Logins[0].ProviderKey)
	if err != nil || len(b.Users) != 1 || len(b.Sessions) != 1 || len(b.Logins) != 1 || b.Logins[0].Email != "test@test.com" || len(b.EmailSessions) != 0 || hashErr != nil {
		t.Fatal("expected valid user, login and session", b.Logins[0], b.Logins[0].ProviderKey, hashErr)
	}

	// decode session cookie
	value = substring.Between(w.HeaderMap["Set-Cookie"][1], "prefixSession=", ";")
	sessionCookie := sessionCookie{}
	cookieStoreInstance.Decode("prefixSession", value, &sessionCookie)
	sessionHash, _ := decodeStringToHash(sessionCookie.SessionID)

	// add session cookie to the next request
	r.AddCookie(newCookie("prefixSession", value, false, emailExpireMins))

	if err != nil || len(b.Sessions) != 1 || b.Sessions[0].SessionHash != sessionHash || len(b.Logins) != 1 || b.Logins[0].Email != "test@test.com" ||
		b.Users[0].FullName != "fullName" || b.Users[0].PrimaryEmail != "test@test.com" {
		t.Fatal("expected profile to be created", err, len(b.Sessions), b.Sessions[0].SessionHash != sessionHash, len(b.Logins) != 1, b.Logins[0].Email, b.Users[0].FullName, b.Users[0].PrimaryEmail)
	}

	// login on same browser with same existing session
	session, err := s.login("test@test.com", "password", true)
	if err != nil || len(b.Logins) != 1 || len(b.Sessions) != 1 || len(b.Users) != 1 || session.SessionHash != b.Sessions[0].SessionHash || session.Email != "test@test.com" {
		t.Fatal("expected to login to existing session", err, len(b.Logins), len(b.Sessions), len(b.Users), session, b.Sessions[0].SessionHash)
	}

	// now login with different browser with new session ID. Create new session
	//session, rememberMe, err = b.NewLoginSession(login.LoginId, "newSessionHash", time.Now().UTC().AddDate(0, 0, 1), time.Now().UTC().AddDate(0, 0, 5), false, "", "", time.Time{}, time.Time{})
	//if err != nil || login == nil || rememberMe != nil || len(b.Sessions) != 2 {
	//	t.Fatal("expected new User Login to be created")
	//}
}

var registerTests = []struct {
	Scenario                 string
	Email                    string
	CreateEmailSessionReturn error
	GetUserReturn            *GetUserReturn
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
		Scenario:      "Send verify email",
		GetUserReturn: getUserErr(),
		Email:         "validemail@test.com",
		MethodsCalled: []string{"GetUser", "CreateEmailSession"},
	},
}

func TestAuthRegister(t *testing.T) {
	for i, test := range registerTests {
		backend := &mockBackend{ErrReturn: test.CreateEmailSessionReturn, GetUserReturn: test.GetUserReturn}
		store := getAuthStore(nil, nil, nil, false, false, nil, backend)
		err := store.register(test.Email)
		methods := store.backend.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.MethodsCalled, methods)
		}
	}
}

var createProfileTests = []struct {
	Scenario              string
	HasCookieGetError     bool
	HasCookiePutError     bool
	getEmailSessionReturn *getEmailSessionReturn
	EmailCookie           *emailCookie
	LoginReturn           *LoginReturn
	UpdateUserReturn      error
	CreateSessionReturn   *SessionReturn
	MethodsCalled         []string
	ExpectedErr           string
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
		Scenario:              "Error Updating user",
		EmailCookie:           &emailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		getEmailSessionReturn: getEmailSessionSuccess(),
		UpdateUserReturn:      errors.New("failed"),
		LoginReturn:           loginErr(),
		MethodsCalled:         []string{"GetEmailSession", "UpdateUser"},
		ExpectedErr:           "Unable to update user",
	},
	{
		Scenario:              "Error Creating login",
		EmailCookie:           &emailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		getEmailSessionReturn: getEmailSessionSuccess(),
		LoginReturn:           loginErr(),
		MethodsCalled:         []string{"GetEmailSession", "UpdateUser", "DeleteEmailSession", "CreateLogin"},
		ExpectedErr:           "Unable to create login",
	},
	{
		Scenario:              "Error creating session",
		EmailCookie:           &emailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		getEmailSessionReturn: getEmailSessionSuccess(),
		LoginReturn:           loginSuccess(),
		CreateSessionReturn:   sessionErr(),
		MethodsCalled:         []string{"GetEmailSession", "UpdateUser", "DeleteEmailSession", "CreateLogin"},
		ExpectedErr:           "failed",
	},
	{
		Scenario:              "Success",
		EmailCookie:           &emailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		getEmailSessionReturn: getEmailSessionSuccess(),
		LoginReturn:           loginSuccess(),
		CreateSessionReturn:   sessionSuccess(futureTime, futureTime),
		MethodsCalled:         []string{"GetEmailSession", "UpdateUser", "DeleteEmailSession", "CreateLogin"},
	},
}

func TestAuthCreateProfile(t *testing.T) {
	for i, test := range createProfileTests {
		backend := &mockBackend{ErrReturn: test.UpdateUserReturn, getEmailSessionReturn: test.getEmailSessionReturn, CreateLoginReturn: test.LoginReturn}
		store := getAuthStore(test.CreateSessionReturn, test.LoginReturn, test.EmailCookie, test.HasCookieGetError, test.HasCookiePutError, nil, backend)
		err := store.createProfile("name", "organization", "password", "path", 1, 1)
		methods := store.backend.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.MethodsCalled, methods)
		}
	}
}

var verifyEmailTests = []struct {
	Scenario              string
	EmailVerificationCode string
	HasCookiePutError     bool
	getEmailSessionReturn *getEmailSessionReturn
	MailErr               error
	MethodsCalled         []string
	ExpectedErr           string
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
		Scenario:              "Cookie Save Error",
		EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0",
		getEmailSessionReturn: getEmailSessionSuccess(),
		HasCookiePutError:     true,
		MethodsCalled:         []string{"GetEmailSession", "AddUser"},
		ExpectedErr:           "Failed to save email cookie",
	},
	{
		Scenario:              "Mail Error",
		EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0",
		getEmailSessionReturn: getEmailSessionSuccess(),
		MethodsCalled:         []string{"GetEmailSession", "AddUser"},
		MailErr:               errors.New("test"),
		ExpectedErr:           "Failed to send welcome email",
	},
	{
		Scenario:              "Email sent",
		EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0",
		getEmailSessionReturn: getEmailSessionSuccess(),
		MethodsCalled:         []string{"GetEmailSession", "AddUser"},
	},
}

func TestAuthVerifyEmail(t *testing.T) {
	for i, test := range verifyEmailTests {
		backend := &mockBackend{getEmailSessionReturn: test.getEmailSessionReturn}
		store := getAuthStore(nil, nil, nil, false, test.HasCookiePutError, test.MailErr, backend)
		err := store.verifyEmail(test.EmailVerificationCode)
		methods := store.backend.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.MethodsCalled, methods)
		}
	}
}

var loginTests = []struct {
	Scenario            string
	Email               string
	Password            string
	RememberMe          bool
	CreateSessionReturn *SessionReturn
	GetUserLoginReturn  *LoginReturn
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
		Scenario:           "Can't get login",
		Email:              "email@example.com",
		Password:           "validPassword",
		GetUserLoginReturn: loginErr(),
		MethodsCalled:      []string{"GetLogin"},
		ExpectedErr:        "Invalid username or password",
	},
	{
		Scenario:           "Incorrect password",
		Email:              "email@example.com",
		Password:           "wrongPassword",
		GetUserLoginReturn: &LoginReturn{Login: &userLogin{Email: "test@test.com", ProviderKey: "1234"}},
		MethodsCalled:      []string{"GetLogin"},
		ExpectedErr:        "Invalid username or password",
	},
	{
		Scenario:            "Got session",
		Email:               "email@example.com",
		Password:            "correctPassword",
		GetUserLoginReturn:  loginSuccess(),
		CreateSessionReturn: sessionSuccess(futureTime, futureTime),
		MethodsCalled:       []string{"GetLogin"},
	},
}

func TestAuthLogin(t *testing.T) {
	for i, test := range loginTests {
		backend := &mockBackend{GetUserLoginReturn: test.GetUserLoginReturn, ErrReturn: test.ErrReturn}
		store := getAuthStore(sessionSuccess(futureTime, futureTime), nil, nil, false, false, nil, backend)
		val, err := store.login(test.Email, test.Password, test.RememberMe)
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
	backend := &mockBackend{getEmailSessionReturn: getEmailSessionErr()}
	store := getAuthStore(nil, nil, nil, true, false, nil, backend)
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
	buf.WriteString(`{"Email":"test@test.com", "Password":"password", "RememberMe":true}`)
	r := &http.Request{Body: ioutil.NopCloser(&buf)}
	backend := &mockBackend{GetUserLoginReturn: loginErr()}
	store := getAuthStore(nil, nil, nil, true, false, nil, backend)
	store.r = r
	err := store.Login().(*authError).innerError
	if err == nil || err.Error() != "failed" {
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
	if err != nil || profile == nil || profile.FullName != "name" || profile.Organization != "org" || profile.Password != "pass" || profile.MailQuota != 1 || profile.FileQuota != 1 {
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
	backend := &mockBackend{}
	store := getAuthStore(nil, nil, nil, true, false, nil, backend)
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

/****************************************************************************/
type mockAuthStore struct {
}

func newMockAuthStore() *mockAuthStore {
	return &mockAuthStore{}
}

func (s *mockAuthStore) Get() (*loginSession, error) {
	return nil, nil
}
func (s *mockAuthStore) GetRememberMe() (*rememberMeSession, error) {
	return nil, nil
}
func (s *mockAuthStore) Login(email, password, returnURL string) (*loginSession, error) {
	return nil, nil
}
