package main

import (
	"github.com/pkg/errors"
	"github.com/robarchibald/configReader"
	"github.com/robarchibald/onedb"
	"gopkg.in/ldap.v2"
	"testing"
)

func TestNewBackendLDAPLogin(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	config := &authConf{}
	err := configReader.ReadFile("nginxauth.conf", config)
	if err != nil {
		t.Fatal("unable to load config file", err)
	}

	l, err := newBackendLDAPLogin(config.LdapServer, config.LdapPort, config.LdapBindDn, config.LdapPassword, config.LdapBaseDn, config.LdapUserFilter)
	if err != nil {
		t.Fatal("unable to login", err)
	}

	_, err = l.Login("test@test.com", "")
	if err == nil {
		t.Fatal("Expected no results", err)
	}
}

func TestLdapLogin(t *testing.T) {
	// success
	data := ldapData{UID: "email", DbUserId: "1234"}
	m := onedb.NewMock(nil, nil, data)
	l := backendLDAPLogin{db: m, userLoginFilter: "%s"}
	login, err := l.Login("email", "password")
	if err != nil || login.Email != "email" {
		t.Error("expected to find data", login, err)
	}

	queries := m.QueriesRun()
	if _, ok := queries[0].(*ldap.SimpleBindRequest); !ok {
		t.Error("expected ldap bind request first")
	}
	if _, ok := queries[1].(*ldap.SearchRequest); !ok {
		t.Error("expected ldap searc request next")
	}

	// error
	m = onedb.NewMock(nil, nil, nil)
	l = backendLDAPLogin{db: m, userLoginFilter: "%s"}
	_, err = l.Login("email", "password")
	if err == nil {
		t.Error("expected error")
	}
}

func TestLdapCreateSubscriber(t *testing.T) {
	m := onedb.NewMock(nil, nil, nil)
	l := backendLDAPLogin{db: m}
	_, err := l.CreateSubscriber(1, 1, "email", "hash", "name", "homeDir", 1, 1, "mailQuota", "fileQuota")
	if err != nil {
		t.Error("expected success")
	}

	queries := m.QueriesRun()
	if _, ok := queries[0].(*ldap.AddRequest); !ok {
		t.Error("expected ldap add request")
	}
}

// replace with test that does something when code does something
func TestLdapUpdateEmail(t *testing.T) {
	m := onedb.NewMock(nil, nil, nil)
	l := backendLDAPLogin{db: m}
	l.UpdateEmail("email", "password", "newEmail")
}

// replace with test that does something when code does something
func TestLdapUpdatePassword(t *testing.T) {
	m := onedb.NewMock(nil, nil, nil)
	l := backendLDAPLogin{db: m}
	l.UpdatePassword("email", "oldPassword", "newPassword")
}

func TestLdapClose(t *testing.T) {
	m := onedb.NewMock(errors.New("failed"), nil, nil)
	l := backendLDAPLogin{db: m}
	if err := l.Close(); err == nil {
		t.Error("expected close to error out")
	}
}
