package main

import (
	"github.com/robarchibald/configReader"
	"testing"
)

func TestNewBackendLDAPLogin(t *testing.T) {
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
