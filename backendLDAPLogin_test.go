package main

import (
	"github.com/robarchibald/configReader"
	"github.com/robarchibald/onedb"
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

	l, err := NewBackendLDAPLogin(config.LdapServer, config.LdapPort, config.LdapBindDn, config.LdapPassword, config.LdapBaseDn, config.LdapUserFilter)
	if err != nil {
		t.Fatal("unable to login", err)
	}

	_, err = l.GetLogin("test@test.com", "")
	if err == nil {
		t.Fatal("Expected no results", err)
	}
}

func TestLdapCreateLogin(t *testing.T) {
	m := onedb.NewMock(nil, nil, nil)
	l := backendLDAPLogin{db: m}
	_, err := l.CreateLogin("email", "hash", "name", "homeDir", 1, 1, "mailQuota", "fileQuota")
	if err != nil {
		t.Error("expected success")
	}
}
