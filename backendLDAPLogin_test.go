package auth

import (
	"testing"

	"github.com/EndFirstCorp/onedb"
	"github.com/pkg/errors"
	"gopkg.in/ldap.v2"
)

func TestNewBackendLDAPLogin(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	ldapServer := "ldap"
	ldapPort := 389
	ldapBindDn := "uid=admin,ou=SystemAccounts,dc=example,dc=com"
	ldapPassword := "secret"
	ldapBaseDn := "ou=Users,dc=example,dc=com"

	l, err := NewBackendLDAPLogin(ldapServer, ldapPort, ldapBindDn, ldapPassword, ldapBaseDn, nil)
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
	l := backendLDAPLogin{db: m, userBackend: &backendMemory{Users: []*user{&user{UserID: "1234", PrimaryEmail: "email"}}}}
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
	l = backendLDAPLogin{db: m}
	_, err = l.Login("email", "password")
	if err == nil {
		t.Error("expected error")
	}
}

// replace with test that does something when code does something
func TestLdapCreateSecondaryEmail(t *testing.T) {
	m := onedb.NewMock(nil, nil, nil)
	l := backendLDAPLogin{db: m}
	l.CreateSecondaryEmail("userID", "secondaryEmail")
}

func TestLdapSetPrimaryEmail(t *testing.T) {
	m := onedb.NewMock(nil, nil, nil)
	l := backendLDAPLogin{db: m}
	l.SetPrimaryEmail("userID", "newPrimaryEmail")
}

// replace with test that does something when code does something
func TestLdapUpdatePassword(t *testing.T) {
	m := onedb.NewMock(nil, nil, nil)
	l := backendLDAPLogin{db: m}
	l.UpdatePassword("userID", "newPassword")
}

func TestLdapClose(t *testing.T) {
	m := onedb.NewMock(errors.New("failed"), nil, nil)
	l := backendLDAPLogin{db: m}
	if err := l.Close(); err == nil {
		t.Error("expected close to error out")
	}
}
