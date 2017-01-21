package main

import (
	"errors"
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

	_, err = l.GetLogin("test@test.com", "")
	if err == nil {
		t.Fatal("Expected no results", err)
	}
}

func TestLdapGetLogin(t *testing.T) {
	// success
	data := ldapData{UserPassword: []string{"password"}}
	m := onedb.NewMock(nil, nil, data)
	l := backendLDAPLogin{db: m, userLoginFilter: "%s"}
	login, err := l.GetLogin("email", "provider")
	if err != nil || login.ProviderKey != "password" {
		t.Error("expected to find data", login)
	}

	queries := m.QueriesRun()
	if _, ok := queries[0].(*ldap.SearchRequest); !ok {
		t.Error("expected ldap search request")
	}

	// error
	m = onedb.NewMock(nil, nil, nil)
	l = backendLDAPLogin{db: m, userLoginFilter: "%s"}
	_, err = l.GetLogin("email", "provider")
	if err == nil {
		t.Error("expected error")
	}
}

func TestLdapCreateLogin(t *testing.T) {
	m := onedb.NewMock(nil, nil, nil)
	l := backendLDAPLogin{db: m}
	_, err := l.CreateLogin(1, "email", "hash", "name", "homeDir", 1, 1, "mailQuota", "fileQuota")
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
