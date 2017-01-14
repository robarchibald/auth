package main

import (
	"github.com/robarchibald/onedb"
	"gopkg.in/ldap.v2"
	"strconv"
)

type backendLDAP struct {
	db     onedb.DBer
	baseDn string
}

func NewBackendLDAP(server string, port int, bindDn, password, baseDn string) (LoginBackender, error) {
	db, err := onedb.NewLdap(server, port, bindDn, password)
	if err != nil {
		return nil, err
	}
	return &backendLDAP{db, baseDn}, nil
}

type ldapData struct {
	UID           []string
	UserPassword  []string
	UIDNumber     []string
	GIDNumber     []string
	HomeDirectory []string
}

func (l *backendLDAP) GetLogin(email, loginProvider string) (*UserLogin, error) {
	req := ldap.NewSearchRequest(l.baseDn, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, "uid="+email, []string{"uid", "userPassword", "uidNumber", "gidNumber", "homeDirectory"}, nil)
	data := &ldapData{}
	err := l.db.QueryStructRow(req, data)
	if err != nil {
		return nil, err
	}
	return &UserLogin{ProviderKey: data.UserPassword[0]}, nil
}

func (l *backendLDAP) CreateLogin(email, passwordHash, fullName, homeDirectory string, uidNumber, gidNumber int) (*UserLogin, error) {
	req := ldap.NewAddRequest("uid=" + email + ",ou=Users,dc=endfirst,dc=com")
	req.Attribute("objectClass", []string{"posixAccount", "account"})
	req.Attribute("uid", []string{email})
	req.Attribute("cn", []string{fullName})
	req.Attribute("userPassword", []string{passwordHash})
	req.Attribute("uidNumber", []string{strconv.Itoa(uidNumber)})
	req.Attribute("gidNumber", []string{strconv.Itoa(gidNumber)})
	req.Attribute("homeDirectory", []string{homeDirectory})
	err := l.db.Execute(req)
	return &UserLogin{}, err
}

func (l *backendLDAP) UpdateEmail(email string, password string, newEmail string) (*UserLoginSession, error) {
	return nil, nil
}

func (l *backendLDAP) UpdatePassword(email string, oldPassword string, newPassword string) (*UserLoginSession, error) {
	return nil, nil
}

func (l *backendLDAP) Close() error {
	return l.db.Close()
}
