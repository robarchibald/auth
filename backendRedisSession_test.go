package main

import (
	"github.com/robarchibald/onedb"
	"testing"
	"time"
)

func TestNewBackendRedisSession(t *testing.T) {

}

func TestRedisCreateSession(t *testing.T) {
	// expired session error
	m := onedb.NewMock(nil, nil, nil)
	r := backendRedisSession{db: m, prefix: "test"}
	_, _, err := r.CreateSession(1, "test@test.com", "fullname", "hash", time.Now(), time.Now(), false, "selector", "token", time.Now(), time.Now())
	if err == nil || len(m.QueriesRun()) != 0 {
		t.Error("expected error")
	}

	// expired rememberMe, but session should save.
	_, _, err = r.CreateSession(1, "test@test.com", "fullname", "hash", time.Now(), time.Now().AddDate(1, 0, 0), true, "selector", "token", time.Now(), time.Now())
	if q := m.QueriesRun(); err == nil || len(q) != 1 || q[0].(*onedb.RedisCommand).Command != "SETEX" || len(q[0].(*onedb.RedisCommand).Args) != 3 || q[0].(*onedb.RedisCommand).Args[0] != "test/session/hash" {
		t.Error("expected error")
	}

	// success
	m = onedb.NewMock(nil, nil, nil)
	r = backendRedisSession{db: m, prefix: "test"}
	session, rememberMe, err := r.CreateSession(1, "test@test.com", "fullname", "hash", time.Now(), time.Now().AddDate(1, 0, 0), true, "selector", "token", time.Now(), time.Now().AddDate(1, 0, 0))
	if q := m.QueriesRun(); err != nil || len(q) != 2 || q[1].(*onedb.RedisCommand).Command != "SETEX" || len(q[1].(*onedb.RedisCommand).Args) != 3 || q[1].(*onedb.RedisCommand).Args[0] != "test/rememberMe/selector" {
		t.Error("expected success")
	}
	if session.SessionHash != "hash" || rememberMe.Selector != "selector" || rememberMe.TokenHash != "token" {
		t.Error("expected valid session and rememberMe")
	}
}

func TestRedisGetSession(t *testing.T) {
	data := loginSession{Email: "test@test.com", SessionHash: "hash"}
	m := onedb.NewMock(nil, nil, data)
	r := backendRedisSession{db: m, prefix: "test"}
	s, err := r.GetSession("hash")
	if err != nil || s.Email != "test@test.com" || s.SessionHash != "hash" {
		t.Error("expected error")
	}
}

func TestRedisRenewSession(t *testing.T) {
	// success
	data := loginSession{Email: "test@test.com", SessionHash: "hash", ExpireTimeUTC: time.Now().AddDate(1, 0, 0)}
	m := onedb.NewMock(nil, nil, data)
	r := backendRedisSession{db: m, prefix: "test"}
	s, err := r.RenewSession("hash", time.Now().AddDate(1, 0, 0))
	if err != nil || s == nil {
		t.Error("expected success")
	}

	// error. No data
	m = onedb.NewMock(nil, nil, nil)
	r = backendRedisSession{db: m, prefix: "test"}
	s, err = r.RenewSession("hash", time.Now().AddDate(1, 0, 0))
	if err == nil || s != nil {
		t.Error("expected success")
	}
}

func TestRedisInvalidateSession(t *testing.T) {
	// success
	data := loginSession{Email: "test@test.com", SessionHash: "hash", ExpireTimeUTC: time.Now().AddDate(1, 0, 0)}
	m := onedb.NewMock(nil, nil, data)
	r := backendRedisSession{db: m, prefix: "test"}
	if err := r.InvalidateSession("hash"); err != nil {
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

func TestRedisRenewRememberMe(t *testing.T) {
	// success
	data := rememberMeSession{Selector: "selector", ExpireTimeUTC: time.Now().AddDate(1, 0, 0)}
	m := onedb.NewMock(nil, nil, data)
	r := backendRedisSession{db: m, prefix: "test"}
	renew := time.Now().AddDate(0, 1, 0)
	remember, err := r.RenewRememberMe("selector", renew)
	if err != nil || remember == nil || remember.RenewTimeUTC != renew {
		t.Error("expected success", remember, err)
	}

	// nothing to renew
	m = onedb.NewMock(nil, nil, nil)
	r = backendRedisSession{db: m, prefix: "test"}
	remember, err = r.RenewRememberMe("selector", time.Now())
	if err == nil || remember != nil {
		t.Error("expected error", remember, err)
	}

	// expired
	data = rememberMeSession{Selector: "selector", ExpireTimeUTC: time.Now().AddDate(0, 0, -1)}
	m = onedb.NewMock(nil, nil, data)
	r = backendRedisSession{db: m, prefix: "test"}
	remember, err = r.RenewRememberMe("selector", time.Now())
	if err == nil || err.Error() != "Unable to save expired rememberMe" || remember != nil {
		t.Error("expected error", remember, err)
	}
}

func TestRedisInvalidateRememberMe(t *testing.T) {
	data := rememberMeSession{Selector: "selector", ExpireTimeUTC: time.Now().AddDate(1, 0, 0)}
	m := onedb.NewMock(nil, nil, data)
	r := backendRedisSession{db: m, prefix: "test"}
	if err := r.InvalidateRememberMe("selector"); err != nil {
		t.Error("expected success")
	}
}
