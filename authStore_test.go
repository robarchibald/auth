package auth

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/pkg/errors"
)

var futureTime = time.Now().UTC().Add(5 * time.Minute)
var pastTime = time.Now().UTC().Add(-5 * time.Minute)

func getAuthStore(emailCookie *emailCookie, sessionCookie *sessionCookie, rememberCookie *rememberMeCookie, hasCookieGetError, hasCookiePutError bool, mailErr error, backend *mockBackend) *authStore {
	cookieStore := NewMockCookieStore(map[string]interface{}{emailCookieName: emailCookie, sessionCookieName: sessionCookie, rememberMeCookieName: rememberCookie}, hasCookieGetError, hasCookiePutError)
	return &authStore{backend, &TextMailer{Err: mailErr}, cookieStore}
}

func TestNewAuthStore(t *testing.T) {
	b := &mockBackend{}
	m := &TextMailer{}
	actual := NewAuthStore(b, m, "prefix", "", cookieKey).(*authStore)
	if actual.b != b || actual.cookieStore.(*cookieStore).s == nil {
		t.Fatal("expected correct init")
	}
}

var getSessionTests = []struct {
	Scenario            string
	HasCookieGetError   bool
	HasCookiePutError   bool
	SessionCookie       *sessionCookie
	GetSessionReturn    *SessionReturn
	UpdateSessionErr    error
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
		MethodsCalled:    []string{"GetSession", "Close"},
	},
	{
		Scenario:      "No CSRFToken",
		ExpectedErr:   "Missing CSRF token",
		MethodsCalled: []string{"Close"},
	},
	{
		Scenario:          "Get Session Cookie Error",
		CSRFToken:         "token",
		HasCookieGetError: true,
		ExpectedErr:       "Session cookie not found",
		MethodsCalled:     []string{"Close"},
	},
	{
		Scenario:      "Get Session Invalid Cookie Error",
		CSRFToken:     "token",
		SessionCookie: sessionCookieBogus(futureTime, futureTime),
		ExpectedErr:   "Unable to decode session cookie",
		MethodsCalled: []string{"Close"},
	},
	{
		Scenario:         "Get Session Error",
		CSRFToken:        "token",
		SessionCookie:    sessionCookieGood(futureTime, futureTime),
		GetSessionReturn: &SessionReturn{&LoginSession{}, errSessionNotFound},
		MethodsCalled:    []string{"GetSession", "Close"},
		ExpectedErr:      "Failed to verify session",
	},
	{
		Scenario:         "Get Session, invalid CSRF",
		CSRFToken:        "token",
		SessionCookie:    sessionCookieGood(futureTime, futureTime),
		GetSessionReturn: sessionSuccess(futureTime, futureTime),
		MethodsCalled:    []string{"GetSession", "Close"},
		ExpectedErr:      "Invalid CSRF token",
	},
	{
		Scenario:         "Get Session Renew",
		CSRFToken:        "csrfToken",
		SessionCookie:    sessionCookieGood(futureTime, futureTime),
		GetSessionReturn: sessionSuccess(futureTime, futureTime),
		MethodsCalled:    []string{"GetSession", "Close"},
	},
}

func TestGetSession(t *testing.T) {
	for i, test := range getSessionTests {
		backend := &mockBackend{GetSessionReturn: test.GetSessionReturn, UpdateSessionErr: test.UpdateSessionErr}
		store := getAuthStore(nil, test.SessionCookie, nil, false, false, nil, backend)
		//store := getSessionStore(nil, test.SessionCookie, nil, test.HasCookieGetError, test.HasCookiePutError, backend)
		h := http.Header{}
		if test.CSRFToken != "" {
			h.Add("X-CSRF-Token", test.CSRFToken)
		}
		val, err := store.GetSession(nil, &http.Request{Header: h})

		methods := store.b.(*mockBackend).MethodsCalled
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
	UpdateSessionErr    error
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
		GetRememberMeReturn: rememberMe(futureTime, futureTime),
		MethodsCalled:       []string{"GetRememberMe", "UpdateSession"},
	},
	{
		Scenario:          "RememberMe Error",
		RenewTimeUTC:      pastTime,
		ExpireTimeUTC:     pastTime,
		HasCookieGetError: true,
		ExpectedErr:       "Unable to renew session",
	},
	{
		Scenario:         "Update Error",
		RenewTimeUTC:     pastTime,
		ExpireTimeUTC:    futureTime,
		UpdateSessionErr: errors.New("failed"),
		MethodsCalled:    []string{"UpdateSession"},
		ExpectedErr:      "Problem updating session",
	},
	{
		Scenario:      "Success with no rememberme",
		RenewTimeUTC:  pastTime,
		ExpireTimeUTC: futureTime,
		MethodsCalled: []string{"UpdateSession"},
	},
}

func TestRenewSession(t *testing.T) {
	for i, test := range renewSessionTests {
		backend := &mockBackend{UpdateSessionErr: test.UpdateSessionErr, GetRememberMeReturn: test.GetRememberMeReturn}
		store := getAuthStore(nil, nil, test.RememberCookie, test.HasCookieGetError, test.HasCookiePutError, nil, backend)
		err := store.renewSession(nil, &http.Request{}, backend, "sessionID", &LoginSession{SessionHash: "sessionHash", RenewTimeUTC: test.RenewTimeUTC, ExpireTimeUTC: test.ExpireTimeUTC})
		methods := store.b.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected val:%v\texpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.ExpectedResult, test.MethodsCalled, methods)
		}
	}
}

func TestRenewSessionCorrectDates(t *testing.T) {
	// renew and expire will adjust to rememberMe expire since rememberMe is only valid for 5 minutes
	backend := &mockBackend{GetRememberMeReturn: rememberMe(futureTime, futureTime)}
	store := getAuthStore(nil, nil, rememberCookie(futureTime, futureTime), false, false, nil, backend)
	session := &LoginSession{SessionHash: "sessionHash", RenewTimeUTC: pastTime, ExpireTimeUTC: pastTime}
	err := store.renewSession(nil, &http.Request{}, backend, "sessionID", session)
	if err != nil || session.ExpireTimeUTC != futureTime || session.RenewTimeUTC != futureTime {
		t.Fatal("expected to be limited to expire time since that is less than next session expire", session.ExpireTimeUTC != futureTime, session.RenewTimeUTC != futureTime, err)
	}

	// expire will adjust to rememberMe expire since rememberMe is only valid for 20 minutes
	now := time.Now().UTC()
	backend = &mockBackend{GetRememberMeReturn: rememberMe(futureTime, now.Add(20*time.Minute))}
	store = getAuthStore(nil, nil, rememberCookie(futureTime, futureTime), false, false, nil, backend)
	session = &LoginSession{SessionHash: "sessionHash", RenewTimeUTC: pastTime, ExpireTimeUTC: pastTime}
	err = store.renewSession(nil, &http.Request{}, backend, "sessionID", session)
	if err != nil || session.ExpireTimeUTC != now.Add(20*time.Minute) || now.Add(sessionRenewDuration).Sub(session.RenewTimeUTC) > 1*time.Millisecond {
		t.Fatal("expected to limit expire time and have normal renew time", session.ExpireTimeUTC != now.Add(20*time.Minute), now.Add(sessionRenewDuration).Sub(session.RenewTimeUTC) > 1*time.Millisecond, err)
	}

	// normal renew & expire
	backend = &mockBackend{GetRememberMeReturn: rememberMe(futureTime, now.AddDate(0, 1, 0))}
	store = getAuthStore(nil, nil, rememberCookie(futureTime, futureTime), false, false, nil, backend)
	session = &LoginSession{SessionHash: "sessionHash", RenewTimeUTC: pastTime, ExpireTimeUTC: pastTime}
	err = store.renewSession(nil, &http.Request{}, backend, "sessionID", session)
	if err != nil || now.Add(sessionExpireDuration).Sub(session.ExpireTimeUTC) > 1*time.Millisecond || now.Add(sessionRenewDuration).Sub(session.RenewTimeUTC) > 1*time.Millisecond {
		t.Fatal("expected normal renew and expire", now.Add(sessionExpireDuration).Sub(session.ExpireTimeUTC) > 1*time.Millisecond, now.Add(sessionRenewDuration).Sub(session.RenewTimeUTC) > 1*time.Millisecond, err)
	}

	// renew without rememberMe, limited to expireTime
	store = getAuthStore(nil, nil, nil, false, false, nil, &mockBackend{})
	session = &LoginSession{SessionHash: "sessionHash", RenewTimeUTC: pastTime, ExpireTimeUTC: futureTime}
	err = store.renewSession(nil, &http.Request{}, backend, "sessionID", session)
	if err != nil || session.RenewTimeUTC != futureTime || session.ExpireTimeUTC != futureTime {
		t.Fatal("expected renew limited to expiration time", session.RenewTimeUTC, session.ExpireTimeUTC, err)
	}

	// normal renew without rememberMe
	store = getAuthStore(nil, nil, nil, false, false, nil, &mockBackend{})
	session = &LoginSession{SessionHash: "sessionHash", RenewTimeUTC: pastTime, ExpireTimeUTC: now.Add(30 * time.Minute)}
	err = store.renewSession(nil, &http.Request{}, backend, "sessionID", session)
	if err != nil || now.Add(sessionRenewDuration).Sub(session.RenewTimeUTC) > 1*time.Millisecond || session.ExpireTimeUTC != now.Add(30*time.Minute) {
		t.Fatal("expected renew limited to expiration time", session.RenewTimeUTC, session.ExpireTimeUTC, err)
	}
}

var rememberMeTests = []struct {
	Scenario            string
	HasCookieGetError   bool
	HasCookiePutError   bool
	RememberCookie      *rememberMeCookie
	GetRememberMeReturn *RememberMeReturn
	UpdateRememberMeErr error
	MethodsCalled       []string
	ExpectedResult      *rememberMeSession
	ExpectedErr         string
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
		Scenario:            "Update RememberMe Error",
		RememberCookie:      rememberCookie(pastTime, futureTime),
		GetRememberMeReturn: rememberMe(pastTime, futureTime),
		UpdateRememberMeErr: errRememberMeNotFound,
		MethodsCalled:       []string{"GetRememberMe", "UpdateRememberMe"},
		ExpectedErr:         "Unable to renew RememberMe",
	},
	{
		Scenario:            "Update RememberMe Success",
		RememberCookie:      rememberCookie(pastTime, futureTime),
		GetRememberMeReturn: rememberMe(pastTime, futureTime),
		UpdateRememberMeErr: nil,
		MethodsCalled:       []string{"GetRememberMe", "UpdateRememberMe"},
	},
}

func TestRememberMe(t *testing.T) {
	for i, test := range rememberMeTests {
		backend := &mockBackend{GetRememberMeReturn: test.GetRememberMeReturn, UpdateRememberMeErr: test.UpdateRememberMeErr}
		store := getAuthStore(nil, nil, test.RememberCookie, test.HasCookieGetError, test.HasCookiePutError, nil, backend)
		val, err := store.getRememberMe(nil, &http.Request{}, backend)
		methods := store.b.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected val:%v\tactual val:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.ExpectedResult, val, test.MethodsCalled, methods)
		}
	}
}

// Doesn't cover the crypto failures generating hashes
var createSessionTests = []struct {
	Scenario               string
	RememberMe             bool
	HasCookieGetError      bool
	HasCookiePutError      bool
	SessionCookie          *sessionCookie
	RememberMeCookie       *rememberMeCookie
	CreateSessionReturn    *SessionReturn
	CreateRememberMeReturn *RememberMeReturn
	MethodsCalled          []string
	ExpectedResult         *rememberMeSession
	ExpectedErr            string
}{
	{
		Scenario:            "Login session error",
		CreateSessionReturn: sessionErr(),
		MethodsCalled:       []string{"CreateSession"},
		ExpectedErr:         "Unable to create new session",
	},
	{
		Scenario:               "RememberMe session error",
		RememberMe:             true,
		CreateSessionReturn:    sessionSuccess(futureTime, futureTime),
		CreateRememberMeReturn: rememberErr(),
		MethodsCalled:          []string{"CreateSession", "CreateRememberMe"},
		ExpectedErr:            "Unable to create rememberMe session",
	},
	{
		Scenario:            "Couldn't get session cookie",
		CreateSessionReturn: sessionSuccess(futureTime, futureTime),
		HasCookieGetError:   true,
		MethodsCalled:       []string{"CreateSession"},
	},
	{
		Scenario:            "Valid old session and rememberme cookies.  delete in backend",
		SessionCookie:       sessionCookieGood(futureTime, futureTime),
		RememberMeCookie:    rememberCookie(futureTime, futureTime),
		CreateSessionReturn: sessionSuccess(futureTime, futureTime),
		MethodsCalled:       []string{"CreateSession", "DeleteSession", "DeleteRememberMe"},
	},
	{
		Scenario:            "Session Cookie save failure",
		HasCookieGetError:   true,
		HasCookiePutError:   true,
		CreateSessionReturn: sessionSuccess(futureTime, futureTime),
		MethodsCalled:       []string{"CreateSession"},
		ExpectedErr:         "Error saving session cookie",
	},
	{
		Scenario:               "RememberMe Cookie save failure",
		RememberMe:             true,
		HasCookieGetError:      true,
		HasCookiePutError:      true,
		CreateSessionReturn:    sessionSuccess(futureTime, futureTime),
		CreateRememberMeReturn: rememberMe(futureTime, futureTime),
		MethodsCalled:          []string{"CreateSession", "CreateRememberMe"},
		ExpectedErr:            "Unable to save rememberMe cookie",
	},
}

func TestCreateSession(t *testing.T) {
	for i, test := range createSessionTests {
		backend := &mockBackend{CreateSessionReturn: test.CreateSessionReturn, CreateRememberMeReturn: test.CreateRememberMeReturn}
		store := getAuthStore(nil, test.SessionCookie, test.RememberMeCookie, test.HasCookieGetError, test.HasCookiePutError, nil, backend)
		val, err := store.createSession(nil, &http.Request{}, backend, "test@test.com", "1", map[string]interface{}{"key": "value"}, test.RememberMe)
		methods := store.b.(*mockBackend).MethodsCalled
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
	store = getAuthStore(nil, nil, nil, true, false, nil, &mockBackend{})
	if _, err := store.GetBasicAuth(nil, &http.Request{}); err == nil || err.Error() != "Problem decoding credentials from basic auth" {
		t.Error("expected error")
	}

	// login error
	store = getAuthStore(nil, nil, nil, true, false, nil, &mockBackend{LoginAndGetUserReturn: userErr(), GetSessionReturn: sessionSuccess(futureTime, futureTime)})
	if _, err := store.GetBasicAuth(nil, basicAuthRequest("test@test.com", "password")); err == nil || err.Error() != "Invalid username or password" {
		t.Error("expected error", err)
	}

	// login success
	store = getAuthStore(nil, nil, nil, true, false, nil, &mockBackend{LoginAndGetUserReturn: userSuccess(), GetSessionReturn: sessionSuccess(futureTime, futureTime), CreateSessionReturn: sessionSuccess(futureTime, futureTime)})
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
	GetUserReturn            *UserReturn
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
		GetUserReturn: userSuccess(),
		MethodsCalled: []string{"GetUser"},
		ExpectedErr:   "User already registered",
	},
	{
		Scenario:                 "Add User error",
		Email:                    "validemail@test.com",
		CreateEmailSessionReturn: errors.New("failed"),
		GetUserReturn:            userErr(),
		MethodsCalled:            []string{"GetUser", "CreateEmailSession"},
		ExpectedErr:              "Unable to save user",
	},
	{
		Scenario:      "Can't send email",
		GetUserReturn: userErr(),
		Email:         "validemail@test.com",
		MailErr:       errors.New("fail"),
		MethodsCalled: []string{"GetUser", "CreateEmailSession"},
		ExpectedErr:   "Unable to send verification email",
	},
	{
		Scenario:      "Send verify email",
		GetUserReturn: userErr(),
		Email:         "validemail@test.com",
		MethodsCalled: []string{"GetUser", "CreateEmailSession"},
	},
}

func TestAuthRegister(t *testing.T) {
	for i, test := range registerTests {
		backend := &mockBackend{ErrReturn: test.CreateEmailSessionReturn, GetUserReturn: test.GetUserReturn}
		store := getAuthStore(nil, nil, nil, false, false, test.MailErr, backend)
		err := store.register(&http.Request{}, backend, test.Email, TemplateNames{Success: "templateName"}, "emailSubject", map[string]interface{}{"key": "value"})
		methods := store.b.(*mockBackend).MethodsCalled
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
	getEmailSessionReturn *EmailSessionReturn
	EmailCookie           *emailCookie
	CSRFToken             string
	LoginReturn           *UserReturn
	UpdateUserErr         error
	DeleteEmailSessionErr error
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
		UpdateUserErr:         errors.New("failed"),
		LoginReturn:           userErr(),
		MethodsCalled:         []string{"GetEmailSession", "UpdateUser"},
		ExpectedErr:           "Unable to update user",
	},
	{
		Scenario:              "Error Deleting Email Session",
		CSRFToken:             "csrfToken",
		EmailCookie:           &emailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		getEmailSessionReturn: getEmailSessionSuccess(),
		DeleteEmailSessionErr: errors.New("failed"),
		LoginReturn:           userErr(),
		MethodsCalled:         []string{"GetEmailSession", "UpdateUser", "DeleteEmailSession"},
		ExpectedErr:           "Error while creating profile",
	},
	{
		Scenario:              "Error creating session",
		CSRFToken:             "csrfToken",
		EmailCookie:           &emailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		getEmailSessionReturn: getEmailSessionSuccess(),
		LoginReturn:           userSuccess(),
		CreateSessionReturn:   sessionErr(),
		MethodsCalled:         []string{"GetEmailSession", "UpdateUser", "DeleteEmailSession", "CreateSession"},
		ExpectedErr:           "Unable to create new session",
	},
	{
		Scenario:              "Success",
		CSRFToken:             "csrfToken",
		EmailCookie:           &emailCookie{EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0=", ExpireTimeUTC: time.Now()},
		getEmailSessionReturn: getEmailSessionSuccess(),
		LoginReturn:           userSuccess(),
		CreateSessionReturn:   sessionSuccess(futureTime, futureTime),
		MethodsCalled:         []string{"GetEmailSession", "UpdateUser", "DeleteEmailSession", "CreateSession"},
	},
}

func TestAuthCreateProfile(t *testing.T) {
	for i, test := range createProfileTests {
		backend := &mockBackend{UpdateUserErr: test.UpdateUserErr, getEmailSessionReturn: test.getEmailSessionReturn, CreateSessionReturn: test.CreateSessionReturn, DeleteEmailSessionErr: test.DeleteEmailSessionErr}
		store := getAuthStore(test.EmailCookie, nil, nil, test.HasCookieGetError, test.HasCookiePutError, nil, backend)
		_, err := store.createProfile(nil, &http.Request{}, backend, test.CSRFToken, "password")
		methods := store.b.(*mockBackend).MethodsCalled
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
	getEmailSessionReturn *EmailSessionReturn
	AddUserErr            error
	UpdateEmailSessionErr error
	MailErr               error
	MethodsCalled         []string
	ExpectedErr           string
	InfoValue             string
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
		AddUserErr:            errors.New("fail"),
		MethodsCalled:         []string{"GetEmailSession", "AddUser", "GetUser"},
		ExpectedErr:           "Failed to get user in database",
	},
	{
		Scenario:              "Email session update fail",
		EmailVerificationCode: "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0",
		getEmailSessionReturn: getEmailSessionSuccess(),
		UpdateEmailSessionErr: errors.New("fail"),
		MethodsCalled:         []string{"GetEmailSession", "AddUser", "UpdateEmailSession"},
		ExpectedErr:           "Failed to update email session",
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
		InfoValue:             "value",
		MethodsCalled:         []string{"GetEmailSession", "AddUser", "UpdateEmailSession"},
	},
}

func TestAuthVerifyEmail(t *testing.T) {
	for i, test := range verifyEmailTests {
		backend := &mockBackend{getEmailSessionReturn: test.getEmailSessionReturn, AddUserErr: test.AddUserErr, UpdateEmailSessionErr: test.UpdateEmailSessionErr}
		store := getAuthStore(nil, nil, nil, false, test.HasCookiePutError, test.MailErr, backend)
		_, user, err := store.verifyEmail(nil, &http.Request{}, backend, test.EmailVerificationCode, "templateName", "emailSubject")
		methods := store.b.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) || test.InfoValue != "" && (user == nil || user.Info == nil || user.Info["key"] != test.InfoValue) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected methods: %s\tactual methods: %s, info: %v", i, test.Scenario, test.ExpectedErr, err, test.MethodsCalled, methods, user)
		}
	}
}

var loginTests = []struct {
	Scenario              string
	Email                 string
	Password              string
	RememberMe            bool
	CreateSessionReturn   *SessionReturn
	LoginAndGetUserReturn *UserReturn
	ErrReturn             error
	MethodsCalled         []string
	ExpectedResult        *rememberMeSession
	ExpectedErr           string
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
		Scenario:              "Can't get login",
		Email:                 "email@example.com",
		Password:              "validPassword",
		LoginAndGetUserReturn: userErr(),
		MethodsCalled:         []string{"LoginAndGetUser"},
		ExpectedErr:           "Invalid username or password",
	},
	{
		Scenario:              "Got session",
		Email:                 "email@example.com",
		Password:              "correctPassword",
		LoginAndGetUserReturn: userSuccess(),
		CreateSessionReturn:   sessionSuccess(futureTime, futureTime),
		MethodsCalled:         []string{"LoginAndGetUser", "CreateSession"},
	},
}

func TestAuthLogin(t *testing.T) {
	for i, test := range loginTests {
		backend := &mockBackend{LoginAndGetUserReturn: test.LoginAndGetUserReturn, ErrReturn: test.ErrReturn, CreateSessionReturn: test.CreateSessionReturn}
		store := getAuthStore(nil, nil, nil, false, false, nil, backend)
		val, err := store.login(nil, &http.Request{}, backend, test.Email, test.Password, test.RememberMe)
		methods := store.b.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected val:%v\tactual val:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.ExpectedResult, val, test.MethodsCalled, methods)
		}
	}
}

func TestRegisterPub(t *testing.T) {
	r := &http.Request{}
	backend := &mockBackend{}
	store := getAuthStore(nil, nil, nil, true, false, nil, backend)
	err := store.Register(nil, r, "bogus", TemplateNames{Success: "templateName"}, "emailSubjet", nil)
	if err == nil || err.Error() != "Invalid email" {
		t.Error("expected error from child register method", err)
	}
}

func TestVerifyEmailPub(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.Header.Add("X-CSRF-Token", "token")
	backend := &mockBackend{getEmailSessionReturn: getEmailSessionErr()}
	store := getAuthStore(nil, nil, nil, true, false, nil, backend)
	emailVerificationCode := "nfwRDzfxxJj2_HY-_mLz6jWyWU7bF0zUlIUUVkQgbZ0" // random valid base64 encoded data
	_, _, err := store.VerifyEmail(nil, r, emailVerificationCode, "templateName", "emailSubject")
	if err == nil || err.Error() != "Failed to verify email" {
		t.Error("expected error from child verifyEmail method", err)
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
	backend := &mockBackend{LoginAndGetUserReturn: userErr()}
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
	if err != nil || profile == nil || profile.Password != "pass" || profile.Info == nil || profile.Info["fullName"] != "name" || profile.Info["organization"] != "org" || profile.Info["mailQuota"] != "1" || profile.Info["fileQuota"] != "1" {
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
