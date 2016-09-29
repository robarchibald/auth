package nginxauth

import (
	"testing"
	"time"
)

var in5Minutes time.Time = time.Now().UTC().Add(5 * time.Minute)
var in1Hour time.Time = time.Now().UTC().Add(time.Hour)

func TestBackendGetUserLogin(t *testing.T) {
	backend := NewBackendMemory()
	if _, err := backend.GetUserLogin("email", LoginProviderDefaultName); err != ErrUserNotFound {
		t.Error("expected no login since nothing added yet", err)
	}
	backend.Users = append(backend.Users, &User{PrimaryEmail: "email", UserId: 1})
	if _, err := backend.GetUserLogin("email", LoginProviderDefaultName); err != ErrLoginNotFound {
		t.Error("expected no login since login not added yet", err)
	}
	expected := &UserLogin{UserId: 1, LoginProviderId: 1}
	backend.Logins = append(backend.Logins, expected)
	if actual, _ := backend.GetUserLogin("email", LoginProviderDefaultName); expected != actual {
		t.Error("expected no login since login not added yet")
	}
}

func TestBackendEndToEnd(t *testing.T) {
	backend := NewBackendMemory()
	// register new user
	// adds to users, logins and sessions
	err := backend.AddUser("test@test.com", "emailVerifyHash")
	if err != nil || len(backend.Users) != 1 || backend.Users[0].EmailVerified || len(backend.Sessions) != 0 {
		t.Fatal("expected to be able to add user")
	}

	// verify email
	email, err := backend.VerifyEmail("emailVerifyHash")
	if err != nil || len(backend.Users) != 1 || !backend.Users[0].EmailVerified || email != "test@test.com" {
		t.Fatal("expected email to be verified", session, email, err, backend.Users)
	}

	// create profile
	session, err := backend.CreateLogin("emailVerifyHash", "passwordHash", "fullName", "company", "pictureUrl", "sessionId", time.Now().UTC().AddDate(0, 0, 1), time.Now().UTC().AddDate(0, 0, 5))
	if err != nil || session.SessionId != "sessionId" || len(backend.Logins) != 1 || backend.Logins[0].UserId != session.UserId || len(backend.Sessions) != 1 {
		t.Fatal("expected profile to be created", err)
	}

	// login on same browser with same session ID
	login, err := backend.GetUserLogin("test@test.com", LoginProviderDefaultName)
	if err != nil {
		t.Fatal("expected to be able to get the login info") // used to figure out if I have right password
	}
	session, rememberMe, err := backend.NewLoginSession(login.LoginId, "sessionId", time.Now().UTC().AddDate(0, 0, 1), time.Now().UTC().AddDate(0, 0, 5), false, "", "", time.Time{}, time.Time{})
	if err != nil || login == nil || rememberMe != nil || len(backend.Sessions) != 1 {
		t.Fatal("expected new User Login to be created")
	}

	// now login with different browser with new session ID. Create new session
	session, rememberMe, err = backend.NewLoginSession(login.LoginId, "newSessionId", time.Now().UTC().AddDate(0, 0, 1), time.Now().UTC().AddDate(0, 0, 5), false, "", "", time.Time{}, time.Time{})
	if err != nil || login == nil || rememberMe != nil || len(backend.Sessions) != 2 {
		t.Fatal("expected new User Login to be created")
	}
}

func TestBackendNewLoginSession(t *testing.T) {
	backend := NewBackendMemory()
	if _, _, err := backend.NewLoginSession(1, "sessionId", in5Minutes, in1Hour, false, "", "", time.Time{}, time.Time{}); err != ErrLoginNotFound {
		t.Error("expected error since login doesn't exist")
	}
	backend.Logins = append(backend.Logins, &UserLogin{UserId: 1, LoginId: 1})
	if session, _, _ := backend.NewLoginSession(1, "sessionId", in5Minutes, in1Hour, false, "", "", time.Time{}, time.Time{}); session.SessionId != "sessionId" || session.LoginId != 1 || session.UserId != 1 {
		t.Error("expected matching session", session)
	}
	// create again, shouldn't create new Session, just update
	if session, _, _ := backend.NewLoginSession(1, "sessionId", in5Minutes, in1Hour, false, "", "", time.Time{}, time.Time{}); session.SessionId != "sessionId" || session.LoginId != 1 || session.UserId != 1 || len(backend.Sessions) != 1 {
		t.Error("expected matching session", session)
	}
	// new session ID since it was generated when no cookie was found
	if session, _, _ := backend.NewLoginSession(1, "newSessionId", in5Minutes, in1Hour, false, "", "", time.Time{}, time.Time{}); session.SessionId != "newSessionId" || len(backend.Sessions) != 2 {
		t.Error("expected matching session", session)
	}

	// existing remember already exists
	backend.RememberMes = append(backend.RememberMes, &UserLoginRememberMe{LoginId: 1, Selector: "selector"})
	if session, rememberMe, err := backend.NewLoginSession(1, "sessionId", in5Minutes, in1Hour, true, "selector", "hash", time.Time{}, time.Time{}); session.SessionId != "sessionId" || session.LoginId != 1 || session.UserId != 1 ||
		rememberMe.LoginId != 1 || rememberMe.Selector != "selector" || rememberMe.TokenHash != "hash" {
		t.Error("expected RememberMe to be created", session, rememberMe, err)
	}

	// create new rememberMe
	if session, rememberMe, err := backend.NewLoginSession(1, "sessionId", in5Minutes, in1Hour, true, "newselector", "hash", time.Time{}, time.Time{}); session.SessionId != "sessionId" || session.LoginId != 1 || session.UserId != 1 ||
		rememberMe.LoginId != 1 || rememberMe.Selector != "newselector" || rememberMe.TokenHash != "hash" {
		t.Error("expected RememberMe to be created", session, rememberMe, err)
	}

	// existing remember is for different login... error
	backend.RememberMes = append(backend.RememberMes, &UserLoginRememberMe{LoginId: 2, Selector: "otherselector"})
	if _, _, err := backend.NewLoginSession(1, "sessionId", in5Minutes, in1Hour, true, "otherselector", "hash", time.Time{}, time.Time{}); err != ErrRememberMeSelectorExists {
		t.Error("expected error", err)
	}
}

func TestBackendGetSession(t *testing.T) {
	backend := NewBackendMemory()
	if _, err := backend.GetSession("sessionId"); err != ErrSessionNotFound {
		t.Error("expected err", err)
	}

	// add session now and try again... should be returned
	backend.Sessions = append(backend.Sessions, &UserLoginSession{SessionId: "sessionId"})
	if session, _ := backend.GetSession("sessionId"); session.SessionId != "sessionId" {
		t.Error("expected session to be returned", session)
	}
}

func TestBackendRenewSession(t *testing.T) {
	backend := NewBackendMemory()
	renews := time.Now()
	if _, err := backend.RenewSession("sessionId", renews); err != ErrSessionNotFound {
		t.Error("expected err", err)
	}

	// add session now and try again... should be renewed
	backend.Sessions = append(backend.Sessions, &UserLoginSession{SessionId: "sessionId"})
	if session, _ := backend.RenewSession("sessionId", renews); session.SessionId != "sessionId" || session.RenewTimeUTC != renews {
		t.Error("expected session to be renewed", session)
	}
}

func TestBackendGetRememberMe(t *testing.T) {
	backend := NewBackendMemory()
	if _, err := backend.GetRememberMe("selector"); err != ErrRememberMeNotFound {
		t.Error("expected err", err)
	}

	// add rememberMe now and try again... should be returned
	backend.RememberMes = append(backend.RememberMes, &UserLoginRememberMe{Selector: "selector"})
	if rememberMe, _ := backend.GetRememberMe("selector"); rememberMe.Selector != "selector" {
		t.Error("expected rememberMe to be found", rememberMe)
	}
}

func TestBackendRenewRememberMe(t *testing.T) {
	backend := NewBackendMemory()
	renews := time.Now().UTC().Add(5 * time.Minute)
	if _, err := backend.RenewRememberMe("selector", renews); err != ErrRememberMeNotFound {
		t.Error("expected err", err)
	}

	backend.RememberMes = append(backend.RememberMes, &UserLoginRememberMe{Selector: "expired", ExpireTimeUTC: time.Now().UTC().Add(-1 * time.Hour)})
	if _, err := backend.RenewRememberMe("expired", renews); err != ErrRememberMeExpired {
		t.Error("expected expired", err)
	}

	backend.RememberMes = append(backend.RememberMes, &UserLoginRememberMe{Selector: "selector", ExpireTimeUTC: time.Now().UTC().Add(time.Hour)})
	if _, err := backend.RenewRememberMe("selector", time.Now().UTC().Add(2*time.Hour)); err != ErrInvalidRenewsAtTime {
		t.Error("expected invalid renew time", err)
	}
	if _, err := backend.RenewRememberMe("selector", time.Now().UTC().Add(-1*time.Hour)); err != ErrInvalidRenewsAtTime {
		t.Error("expected invalid renew time", err)
	}
	if rememberMe, _ := backend.RenewRememberMe("selector", renews); rememberMe.RenewTimeUTC != renews {
		t.Error("expected valid rememberMe", rememberMe)
	}
}

func TestBackendAddUser(t *testing.T) {
	backend := NewBackendMemory()
	if err := backend.AddUser("email", "emailVerifyHash"); err != nil || len(backend.Users) != 1 {
		t.Error("expected valid session", session)
	}

	if err := backend.AddUser("email", "emailVerifyHash"); err != ErrUserAlreadyExists {
		t.Error("expected user to already exist", err)
	}

	if err := backend.AddUser("email1", "emailVerifyHash"); err != ErrEmailVerifyCodeExists {
		t.Error("expected failure due to existing email verify code", err)
	}
}

func TestBackendVerifyEmail(t *testing.T) {
	backend := NewBackendMemory()
	if _, err := backend.VerifyEmail("verifyHash"); err != ErrInvalidEmailVerifyCode {
		t.Error("expected login not found err", err)
	}

	// success
	backend.Users = append(backend.Users, &User{EmailVerifyHash: "verifyHash", UserId: 1, PrimaryEmail: "email"})
	if email, _ := backend.VerifyEmail("verifyHash"); email != "email" {
		t.Error("expected valid session", email)
	}
}

func TestBackendUpdateUser(t *testing.T) {
	backend := NewBackendMemory()
	backend.UpdateUser(nil, "fullname", "company", "pictureUrl")
}

func TestBackendCreateLogin(t *testing.T) {
	renews := time.Now().UTC()
	expires := time.Now().UTC().Add(time.Hour)
	backend := NewBackendMemory()
	if _, err := backend.CreateLogin("emailVerifyHash", "passwordHash", "fullName", "company", "pictureUrl", "sessionId", expires, renews); err != ErrUserNotFound {
		t.Error("expected login not found err", err)
	}

	backend.Users = append(backend.Users, &User{EmailVerifyHash: "emailVerifyHash", UserId: 1, PrimaryEmail: "email"})
	if session, err := backend.CreateLogin("emailVerifyHash", "passwordHash", "fullName", "company", "pictureUrl", "sessionId", expires, renews); err != nil || session.SessionId != "sessionId" || session.ExpireTimeUTC != expires || session.RenewTimeUTC != renews || session.LoginId != 1 || session.UserId != 1 {
		t.Error("expected valid session", session)
	}
}

func TestToString(t *testing.T) {
	backend := NewBackendMemory()
	backend.Users = append(backend.Users, &User{})
	backend.Logins = append(backend.Logins, &UserLogin{})
	backend.Sessions = append(backend.Sessions, &UserLoginSession{})
	backend.RememberMes = append(backend.RememberMes, &UserLoginRememberMe{})

	actual := backend.ToString()
	expected := "Users:\n     {0    false <nil> 0}\nLogins:\n     {0 0 0 }\nSessions:\n     {0  0 0001-01-01 00:00:00 +0000 UTC 0001-01-01 00:00:00 +0000 UTC}\nRememberMe:\n     {0   0001-01-01 00:00:00 +0000 UTC 0001-01-01 00:00:00 +0000 UTC}\n"
	if actual != expected {
		t.Error("expected different value", actual)
	}
}

func TestGetLoginProvider(t *testing.T) {
	backend := NewBackendMemory()
	if backend.getLoginProvider("bogus") != nil {
		t.Error("expected no provider")
	}
}

func TestGetLoginByUser(t *testing.T) {
	backend := NewBackendMemory()
	if backend.getLoginByUser(1, "bogus") != nil {
		t.Error("expected no login")
	}
}
