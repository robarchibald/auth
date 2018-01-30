package auth

import (
	"testing"
	"time"

	"github.com/EndFirstCorp/onedb"
)

func TestNewBackendRedisSession(t *testing.T) {

}

func TestRedisCreateSession(t *testing.T) {
	// expired session error
	m := onedb.NewMock(nil, nil, nil)
	r := backendRedisSession{db: m, prefix: "test"}
	_, err := r.CreateSession("1", "test@test.com", "fullname", "hash", "csrfToken", time.Now(), time.Now())
	if err == nil || len(m.QueriesRun()) != 0 {
		t.Error("expected error")
	}

	// success
	session, err := r.CreateSession("1", "test@test.com", "fullname", "hash", "csrfToken", time.Now(), time.Now().AddDate(1, 0, 0))
	if q := m.QueriesRun(); err != nil || len(q) != 1 || q[0].(*onedb.RedisCommand).Command != "SETEX" || len(q[0].(*onedb.RedisCommand).Args) != 3 || q[0].(*onedb.RedisCommand).Args[0] != "test/session/hash" {
		t.Error("expected success", len(q), q[0].(*onedb.RedisCommand))
	}
	if session.SessionHash != "hash" {
		t.Error("expected valid session")
	}
}

func TestRedisCreateRememberMe(t *testing.T) {
	// expired rememberMe
	m := onedb.NewMock(nil, nil, nil)
	r := backendRedisSession{db: m, prefix: "test"}
	_, err := r.CreateRememberMe("1", "test@test.com", "selector", "token", time.Now(), time.Now())
	if err == nil || len(m.QueriesRun()) != 0 {
		t.Error("expected error")
	}

	// success
	rememberMe, err := r.CreateRememberMe("1", "test@test.com", "selector", "token", time.Now(), time.Now().AddDate(1, 0, 0))
	if q := m.QueriesRun(); err != nil || len(q) != 1 || q[0].(*onedb.RedisCommand).Command != "SETEX" || len(q[0].(*onedb.RedisCommand).Args) != 3 || q[0].(*onedb.RedisCommand).Args[0] != "test/rememberMe/selector" {
		t.Error("expected success")
	}
	if rememberMe.Selector != "selector" || rememberMe.TokenHash != "token" {
		t.Error("expected valid rememberMe")
	}
}

func TestRedisGetSession(t *testing.T) {
	data := LoginSession{Email: "test@test.com", SessionHash: "hash"}
	m := onedb.NewMock(nil, nil, data)
	r := backendRedisSession{db: m, prefix: "test"}
	s, err := r.GetSession("hash")
	if err != nil || s.Email != "test@test.com" || s.SessionHash != "hash" {
		t.Error("expected error")
	}
}

func TestRedisUpdateSession(t *testing.T) {
	// success
	data := LoginSession{Email: "test@test.com", SessionHash: "hash", ExpireTimeUTC: time.Now().AddDate(1, 0, 0)}
	m := onedb.NewMock(nil, nil, data)
	r := backendRedisSession{db: m, prefix: "test"}
	err := r.UpdateSession("hash", futureTime, futureTime)
	if err != nil {
		t.Error("expected success", err)
	}

	// error. No data
	m = onedb.NewMock(nil, nil, nil)
	r = backendRedisSession{db: m, prefix: "test"}
	err = r.UpdateSession("hash", futureTime, futureTime)
	if err == nil {
		t.Error("expected success")
	}
}

func TestRedisDeleteSession(t *testing.T) {
	// success
	data := LoginSession{Email: "test@test.com", SessionHash: "hash", ExpireTimeUTC: time.Now().AddDate(1, 0, 0)}
	m := onedb.NewMock(nil, nil, data)
	r := backendRedisSession{db: m, prefix: "test"}
	if err := r.DeleteSession("hash"); err != nil {
		t.Error("expected success")
	}
}

func TestRedisGetRememberMe(t *testing.T) {
	// success
	data := rememberMeSession{Selector: "selector"}
	m := onedb.NewMock(nil, nil, data)
	r := backendRedisSession{db: m, prefix: "test"}
	rememberMe, err := r.GetRememberMe("selector")
	if err != nil || rememberMe.Selector != "selector" {
		t.Error("expected to find rememberMe", err, rememberMe)
	}
}

func TestRedisUpdateRememberMe(t *testing.T) {
	// success
	data := rememberMeSession{Selector: "selector", ExpireTimeUTC: time.Now().AddDate(1, 0, 0)}
	m := onedb.NewMock(nil, nil, data)
	r := backendRedisSession{db: m, prefix: "test"}
	err := r.UpdateRememberMe("selector", futureTime)
	if err != nil {
		t.Error("expected success", err)
	}

	// nothing to renew
	m = onedb.NewMock(nil, nil, nil)
	r = backendRedisSession{db: m, prefix: "test"}
	err = r.UpdateRememberMe("selector", time.Now())
	if err == nil {
		t.Error("expected error", err)
	}

	// expired
	data = rememberMeSession{Selector: "selector", ExpireTimeUTC: time.Now().AddDate(0, 0, -1)}
	m = onedb.NewMock(nil, nil, data)
	r = backendRedisSession{db: m, prefix: "test"}
	err = r.UpdateRememberMe("selector", time.Now())
	if err == nil || err.Error() != "Unable to save expired rememberMe" {
		t.Error("expected error", err)
	}
}

func TestRedisDeleteRememberMe(t *testing.T) {
	data := rememberMeSession{Selector: "selector", ExpireTimeUTC: time.Now().AddDate(1, 0, 0)}
	m := onedb.NewMock(nil, nil, data)
	r := backendRedisSession{db: m, prefix: "test"}
	if err := r.DeleteRememberMe("selector"); err != nil {
		t.Error("expected success")
	}
}
