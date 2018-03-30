package auth

import (
	"testing"
	"time"
)

var in5Minutes = time.Now().UTC().Add(5 * time.Minute)
var in1Hour = time.Now().UTC().Add(time.Hour)

func TestMemoryLogin(t *testing.T) {
	// can't get login
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	if _, err := backend.Login("email", "password"); err != errLoginNotFound {
		t.Error("expected no login since login not added yet", err)
	}

	// invalid credentials
	expected := &userLoginMemory{Email: "email", UserID: "1", FullName: "name", PasswordHash: "zVNfmBbTwQZwyMsAizV1Guh_j7kcFbyG7-LRJeeJfXc="}
	backend.Logins = []*userLoginMemory{expected}
	if _, err := backend.Login("email", "wrongPassword"); err != nil && err.Error() != "supplied token and tokenHash do not match" {
		t.Error("expected error", err)
	}

	// success
	expected = &userLoginMemory{Email: "email", UserID: "1", FullName: "name", PasswordHash: "zVNfmBbTwQZwyMsAizV1Guh_j7kcFbyG7-LRJeeJfXc="} // hash of "correctPassword""
	backend.Logins = []*userLoginMemory{expected}
	if actual, err := backend.Login("email", "correctPassword"); err != nil || expected == nil || expected.Email != actual.Email || expected.FullName != actual.FullName || expected.UserID != actual.UserID {
		t.Error("expected success", expected, actual, err)
	}
}

func TestMemoryCreateSession(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	if session, _ := backend.CreateSession("1", "test@test.com", "fullname", "sessionHash", "csrfToken", in5Minutes, in1Hour); session.SessionHash != "sessionHash" || session.Email != "test@test.com" {
		t.Error("expected matching session", session)
	}
	// create again, should error
	if _, err := backend.CreateSession("1", "test@test.com", "fullname", "sessionHash", "csrfToken", in5Minutes, in1Hour); err == nil {
		t.Error("expected error since session exists", err)
	}
	// new session ID since it was generated when no cookie was found (e.g. on another computer or browser)
	if session, _ := backend.CreateSession("1", "test@test.com", "fullname", "newSessionHash", "csrfToken", in5Minutes, in1Hour); session.SessionHash != "newSessionHash" || len(backend.Sessions) != 2 {
		t.Error("expected matching session", session)
	}
}

func TestMemoryCreateRememberMe(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	// new rememberMe
	backend.Sessions = nil
	backend.RememberMes = nil
	if rememberMe, err := backend.CreateRememberMe("1", "test@test.com", "selector", "hash", time.Time{}, time.Time{}); rememberMe == nil || rememberMe.Selector != "selector" || rememberMe.TokenHash != "hash" {
		t.Error("expected RememberMe to be created", rememberMe, err)
	}

	// existing rememberMe. Error
	backend.Sessions = nil
	if _, err := backend.CreateRememberMe("1", "test@test.com", "selector", "hash", time.Time{}, time.Time{}); err != errRememberMeSelectorExists {
		t.Error("expected error", err)
	}
}

func TestMemoryGetSession(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	if _, err := backend.GetSession("sessionHash"); err != errSessionNotFound {
		t.Error("expected err", err)
	}

	// add session now and try again... should be returned
	backend.Sessions = append(backend.Sessions, &LoginSession{SessionHash: "sessionHash"})
	if session, _ := backend.GetSession("sessionHash"); session.SessionHash != "sessionHash" {
		t.Error("expected session to be returned", session)
	}
}

func TestMemoryRenewSession(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	renews := time.Now()
	if err := backend.UpdateSession("sessionHash", renews, futureTime); err != errSessionNotFound {
		t.Error("expected err", err)
	}

	// add session now and try again... should be renewed
	backend.Sessions = append(backend.Sessions, &LoginSession{SessionHash: "sessionHash"})
	if err := backend.UpdateSession("sessionHash", renews, futureTime); err != nil {
		t.Error("expected session to be renewed", err)
	}
}

func TestMemoryGetRememberMe(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	if _, err := backend.GetRememberMe("selector"); err != errRememberMeNotFound {
		t.Error("expected err", err)
	}

	// add rememberMe now and try again... should be returned
	backend.RememberMes = append(backend.RememberMes, &rememberMeSession{Selector: "selector"})
	if rememberMe, _ := backend.GetRememberMe("selector"); rememberMe.Selector != "selector" {
		t.Error("expected rememberMe to be found", rememberMe)
	}
}

func TestMemoryRenewRememberMe(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	renews := time.Now().UTC().Add(5 * time.Minute)
	if err := backend.UpdateRememberMe("selector", renews); err != errRememberMeNotFound {
		t.Error("expected err", err)
	}

	backend.RememberMes = append(backend.RememberMes, &rememberMeSession{Selector: "selector", ExpireTimeUTC: time.Now().UTC().Add(time.Hour)})
	if err := backend.UpdateRememberMe("selector", renews); err != nil {
		t.Error("expected success", err)
	}
}

func TestMemoryAddUser(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	if userID, err := backend.AddUser("email"); err != nil || len(backend.Users) != 1 || userID != "1" {
		t.Error("expected valid session", err, backend.Users)
	}

	if userID, err := backend.AddUser("email"); err != errUserAlreadyExists || userID != "" {
		t.Error("expected user to already exist", err)
	}
}

func TestMemoryGetEmailSession(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
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
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	err := backend.UpdateUser("1", "fullname", "company", "pictureUrl")
	if err != errUserNotFound {
		t.Error("expected to be unable to update non-existant user")
	}

	backend = NewBackendMemory(&hashStore{}).(*backendMemory)
	backend.Users = append(backend.Users, &user{UserID: "1", PrimaryEmail: "email"})
	err = backend.UpdateUser("1", "fullname", "company", "pictureUrl")
	if err != nil {
		t.Error("expected success", err)
	}
}

func TestMemoryCreateSecondaryEmail(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	backend.CreateSecondaryEmail("userID", "secondaryEmail")
}

func TestMemorySetPrimaryEmail(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	backend.SetPrimaryEmail("userID", "newPrimaryEmail")
}

func TestMemoryUpdatePassword(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	backend.UpdatePassword("userID", "newPassword")
}

func TestMemoryDeleteSession(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	backend.Sessions = append(backend.Sessions, &LoginSession{SessionHash: "hash"})
	backend.DeleteSession("hash")
	if len(backend.Sessions) != 0 {
		t.Error("Expected to remove session")
	}
}

func TestMemoryInvalidateSessions(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	backend.InvalidateSessions("email")
}

func TestMemoryDeleteRememberMe(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	backend.RememberMes = append(backend.RememberMes, &rememberMeSession{Selector: "selector"})
	backend.DeleteRememberMe("selector")
	if len(backend.RememberMes) != 0 {
		t.Error("Expected to remove remember me")
	}
}

func TestMemoryClose(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	backend.Close()
}

func TestToString(t *testing.T) {
	backend := NewBackendMemory(&hashStore{}).(*backendMemory)
	backend.Users = append(backend.Users, &user{})
	backend.Logins = append(backend.Logins, &userLoginMemory{})
	backend.Sessions = append(backend.Sessions, &LoginSession{})
	backend.RememberMes = append(backend.RememberMes, &rememberMeSession{})

	actual := backend.ToString()
	expected := "Users:\n     {   <nil> 0 []}\nLogins:\n     {   }\nSessions:\n     {     0001-01-01 00:00:00 +0000 UTC 0001-01-01 00:00:00 +0000 UTC}\nRememberMe:\n     {    0001-01-01 00:00:00 +0000 UTC 0001-01-01 00:00:00 +0000 UTC}\n"
	if actual != expected {
		t.Error("expected different value", actual)
	}
}
