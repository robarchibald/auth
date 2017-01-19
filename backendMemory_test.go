package main

import (
	"testing"
	"time"
)

var in5Minutes = time.Now().UTC().Add(5 * time.Minute)
var in1Hour = time.Now().UTC().Add(time.Hour)

func TestMemoryGetLogin(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	if _, err := backend.GetLogin("email", loginProviderDefaultName); err != errLoginNotFound {
		t.Error("expected no login since login not added yet", err)
	}
	expected := &UserLogin{Email: "email", LoginProviderID: 1}
	backend.Logins = append(backend.Logins, expected)
	if actual, _ := backend.GetLogin("email", loginProviderDefaultName); expected != actual {
		t.Error("expected no login since login not added yet")
	}
}

func TestMemoryCreateSession(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	if session, _, _ := backend.CreateSession("test@test.com", "sessionHash", in5Minutes, in1Hour, false, "", "", time.Time{}, time.Time{}); session.SessionHash != "sessionHash" || session.Email != "test@test.com" {
		t.Error("expected matching session", session)
	}
	// create again, should error
	if _, _, err := backend.CreateSession("test@test.com", "sessionHash", in5Minutes, in1Hour, false, "", "", time.Time{}, time.Time{}); err == nil {
		t.Error("expected error since session exists", err)
	}
	// new session ID since it was generated when no cookie was found (e.g. on another computer or browser)
	if session, _, _ := backend.CreateSession("test@test.com", "newSessionHash", in5Minutes, in1Hour, false, "", "", time.Time{}, time.Time{}); session.SessionHash != "newSessionHash" || len(backend.Sessions) != 2 {
		t.Error("expected matching session", session)
	}

	// new rememberMe
	backend.Sessions = nil
	backend.RememberMes = nil
	if session, rememberMe, err := backend.CreateSession("test@test.com", "sessionHash", in5Minutes, in1Hour, true, "selector", "hash", time.Time{}, time.Time{}); session == nil || session.SessionHash != "sessionHash" || session.Email != "test@test.com" ||
		rememberMe == nil || rememberMe.Selector != "selector" || rememberMe.TokenHash != "hash" {
		t.Error("expected RememberMe to be created", session, rememberMe, err)
	}

	// existing rememberMe. Error
	backend.Sessions = nil
	if _, _, err := backend.CreateSession("test@test.com", "sessionHash", in5Minutes, in1Hour, true, "selector", "hash", time.Time{}, time.Time{}); err != errRememberMeSelectorExists {
		t.Error("expected error", err)
	}
}

func TestMemoryGetSession(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	if _, err := backend.GetSession("sessionHash"); err != errSessionNotFound {
		t.Error("expected err", err)
	}

	// add session now and try again... should be returned
	backend.Sessions = append(backend.Sessions, &UserLoginSession{SessionHash: "sessionHash"})
	if session, _ := backend.GetSession("sessionHash"); session.SessionHash != "sessionHash" {
		t.Error("expected session to be returned", session)
	}
}

func TestMemoryRenewSession(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	renews := time.Now()
	if _, err := backend.RenewSession("sessionHash", renews); err != errSessionNotFound {
		t.Error("expected err", err)
	}

	// add session now and try again... should be renewed
	backend.Sessions = append(backend.Sessions, &UserLoginSession{SessionHash: "sessionHash"})
	if session, _ := backend.RenewSession("sessionHash", renews); session.SessionHash != "sessionHash" || session.RenewTimeUTC != renews {
		t.Error("expected session to be renewed", session)
	}
}

func TestMemoryGetRememberMe(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	if _, err := backend.GetRememberMe("selector"); err != errRememberMeNotFound {
		t.Error("expected err", err)
	}

	// add rememberMe now and try again... should be returned
	backend.RememberMes = append(backend.RememberMes, &UserLoginRememberMe{Selector: "selector"})
	if rememberMe, _ := backend.GetRememberMe("selector"); rememberMe.Selector != "selector" {
		t.Error("expected rememberMe to be found", rememberMe)
	}
}

func TestMemoryRenewRememberMe(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	renews := time.Now().UTC().Add(5 * time.Minute)
	if _, err := backend.RenewRememberMe("selector", renews); err != errRememberMeNotFound {
		t.Error("expected err", err)
	}

	backend.RememberMes = append(backend.RememberMes, &UserLoginRememberMe{Selector: "expired", ExpireTimeUTC: time.Now().UTC().Add(-1 * time.Hour)})
	if _, err := backend.RenewRememberMe("expired", renews); err != errRememberMeExpired {
		t.Error("expected expired", err)
	}

	backend.RememberMes = append(backend.RememberMes, &UserLoginRememberMe{Selector: "selector", ExpireTimeUTC: time.Now().UTC().Add(time.Hour)})
	if _, err := backend.RenewRememberMe("selector", time.Now().UTC().Add(2*time.Hour)); err != errInvalidRenewTimeUTC {
		t.Error("expected invalid renew time", err)
	}
	if _, err := backend.RenewRememberMe("selector", time.Now().UTC().Add(-1*time.Hour)); err != errInvalidRenewTimeUTC {
		t.Error("expected invalid renew time", err)
	}
	if rememberMe, _ := backend.RenewRememberMe("selector", renews); rememberMe.RenewTimeUTC != renews {
		t.Error("expected valid rememberMe", rememberMe)
	}
}

func TestMemoryAddUser(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	if err := backend.AddUser("email"); err != nil || len(backend.Users) != 1 {
		t.Error("expected valid session", err, backend.Users)
	}

	if err := backend.AddUser("email"); err != errUserAlreadyExists {
		t.Error("expected user to already exist", err)
	}
}

func TestMemoryGetEmailSession(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	if _, err := backend.GetEmailSession("verifyHash"); err != errInvalidEmailVerifyHash {
		t.Error("expected login not found err", err)
	}

	// success
	backend.EmailSessions = append(backend.EmailSessions, &emailSession{Email: "email", EmailVerifyHash: "verifyHash"})
	if email, _ := backend.GetEmailSession("verifyHash"); email.Email != "email" {
		t.Error("expected valid session", email)
	}
}

func TestMemoryUpdateUser(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	err := backend.UpdateUser("email", "fullname", "company", "pictureUrl")
	if err != errUserNotFound {
		t.Error("expected to be unable to update non-existant user")
	}

	backend = NewBackendMemory().(*backendMemory)
	backend.Users = append(backend.Users, &User{PrimaryEmail: "email"})
	err = backend.UpdateUser("email", "fullname", "company", "pictureUrl")
	if err != nil {
		t.Error("expected success", err)
	}
}

func TestMemoryCreateLogin(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	if login, err := backend.CreateLogin("email", "passwordHash", "fullName", "homeDirectory", 1, 1, "mailQuota", "fileQuota"); err != nil || login.Email != "email" {
		t.Error("expected valid login", login)
	}
}

func TestMemoryUpdateEmail(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	backend.UpdateEmail("email", "password", "newEmail")
}

func TestMemoryUpdatePassword(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	backend.UpdatePassword("email", "oldPassword", "newPassword")
}

func TestMemoryInvalidateSession(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	backend.Sessions = append(backend.Sessions, &UserLoginSession{SessionHash: "hash"})
	backend.InvalidateSession("hash")
	if len(backend.Sessions) != 0 {
		t.Error("Expected to remove session")
	}
}

func TestMemoryInvalidateSessions(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	backend.InvalidateSessions("email")
}

func TestMemoryInvalidateRememberMe(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	backend.RememberMes = append(backend.RememberMes, &UserLoginRememberMe{Selector: "selector"})
	backend.InvalidateRememberMe("selector")
	if len(backend.RememberMes) != 0 {
		t.Error("Expected to remove remember me")
	}
}

func TestMemoryClose(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	backend.Close()
}

func TestToString(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	backend.Users = append(backend.Users, &User{})
	backend.Logins = append(backend.Logins, &UserLogin{})
	backend.Sessions = append(backend.Sessions, &UserLoginSession{})
	backend.RememberMes = append(backend.RememberMes, &UserLoginRememberMe{})

	actual := backend.ToString()
	expected := "Users:\n     {  <nil> 0}\nLogins:\n     { 0 }\nSessions:\n     {  0001-01-01 00:00:00 +0000 UTC 0001-01-01 00:00:00 +0000 UTC}\nRememberMe:\n     {   0001-01-01 00:00:00 +0000 UTC 0001-01-01 00:00:00 +0000 UTC}\n"
	if actual != expected {
		t.Error("expected different value", actual)
	}
}

func TestGetLoginProvider(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	if backend.getLoginProvider("bogus") != nil {
		t.Error("expected no provider")
	}
}

func TestGetLoginByUser(t *testing.T) {
	backend := NewBackendMemory().(*backendMemory)
	if backend.getLoginByUser("email", "bogus") != nil {
		t.Error("expected no login")
	}
}
