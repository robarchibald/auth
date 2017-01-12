package main

import (
	"github.com/robarchibald/onedb"
	"gopkg.in/ldap.v2"
)

type ldapLoginStore struct {
	db     onedb.DBer
	auth   onedb.DBer
	baseDn string
}

func NewLdapLoginStore(server string, port int, bindDn, password, baseDn string) (LoginStorer, error) {
	db, err := onedb.NewLdap(server, port, bindDn, password)
	if err != nil {
		return nil, err
	}
	auth, err := onedb.NewLdap(server, port, bindDn, password)
	if err != nil {
		return nil, err
	}
	return &ldapLoginStore{db, auth, baseDn}, nil
}

func (l *ldapLoginStore) Login(email, password string, rememberMe bool) (*UserLogin, error) {
	if !isValidEmail(email) {
		return nil, newAuthError("Please enter a valid email address.", nil)
	}
	if !isValidPassword(password) {
		return nil, newAuthError(passwordValidationMessage, nil)
	}

	// add in check for DDOS attack. Slow down or lock out checks for same account
	// or same IP with multiple failed attempts
	login, err := l.getUser(email)
	if err != nil {
		return nil, newLoggedError("Invalid username or password", err)
	}

	if err := cryptoHashEquals(password, login.UserPassword[0]); err != nil {
		return nil, newLoggedError("Invalid username or password", nil)
	}

	return &UserLogin{}, nil
}

func (l *ldapLoginStore) CreateLogin(email, fullName, password string) (*UserLogin, error) {
	passwordHash, err := cryptoHash(password)
	if err != nil {
		return nil, newLoggedError("Unable to create login", err)
	}
	uidNumber := "0"
	gidNumber := "0"
	homeDirectory := "/home"
	err = l.newUser(email, fullName, passwordHash, uidNumber, gidNumber, homeDirectory)
	if err != nil {
		return nil, newLoggedError("Unable to create login", err)
	}
	return &UserLogin{}, err
}

func (l *ldapLoginStore) UpdateEmail() error { return nil }

func (l *ldapLoginStore) UpdatePassword() error {
	return nil
}

type ldapData struct {
	UID           []string
	UserPassword  []string
	UIDNumber     []string
	GIDNumber     []string
	HomeDirectory []string
}

func (l *ldapLoginStore) getUser(email string) (*ldapData, error) {
	req := ldap.NewSearchRequest(l.baseDn, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, "uid="+email, []string{"uid", "userPassword", "uidNumber", "gidNumber", "homeDirectory"}, nil)
	data := &ldapData{}
	return data, l.db.QueryStructRow(req, data)
}

func (l *ldapLoginStore) newUser(email, fullname, password, uidNumber, gidNumber, homeDirectory string) error {
	req := ldap.NewAddRequest("uid=" + email + ",ou=Users,dc=endfirst,dc=com")
	req.Attribute("objectClass", []string{"posixAccount", "account"})
	req.Attribute("uid", []string{email})
	req.Attribute("cn", []string{fullname})
	req.Attribute("userPassword", []string{password})
	req.Attribute("uidNumber", []string{uidNumber})
	req.Attribute("gidNumber", []string{gidNumber})
	req.Attribute("homeDirectory", []string{homeDirectory})
	return l.db.Execute(req)
}

func (l *ldapLoginStore) authenticate(username, password string) error {
	return l.auth.Execute(ldap.NewSimpleBindRequest(username, password, nil))
}
