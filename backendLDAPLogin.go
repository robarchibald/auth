package main

import (
	"fmt"
	"github.com/robarchibald/onedb"
	"gopkg.in/ldap.v2"
	"strconv"
)

type backendLDAPLogin struct {
	db              onedb.DBer
	baseDn          string
	userLoginFilter string
}

func NewBackendLDAPLogin(server string, port int, bindDn, password, baseDn, userLoginFilter string) (LoginBackender, error) {
	db, err := onedb.NewLdap(server, port, bindDn, password)
	if err != nil {
		return nil, err
	}
	return &backendLDAPLogin{db, baseDn, userLoginFilter}, nil
}

type ldapData struct {
	UID           []string
	UserPassword  []string
	UIDNumber     []string
	GIDNumber     []string
	HomeDirectory []string
}

func (l *backendLDAPLogin) GetLogin(email, loginProvider string) (*UserLogin, error) {
	req := ldap.NewSearchRequest(l.baseDn, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, fmt.Sprintf(l.userLoginFilter, email), []string{"uid", "userPassword", "uidNumber", "gidNumber", "homeDirectory"}, nil)
	data := &ldapData{}
	err := l.db.QueryStructRow(req, data)
	if err != nil {
		return nil, err
	}
	var password string
	if len(data.UserPassword) != 0 {
		password = data.UserPassword[0]
	}
	return &UserLogin{ProviderKey: password}, nil
}

/****************  TODO: create different type of user if not using file and mail quotas  **********************/
func (l *backendLDAPLogin) CreateLogin(email, passwordHash, fullName, homeDirectory string, uidNumber, gidNumber int, mailQuota, fileQuota string) (*UserLogin, error) {
	req := ldap.NewAddRequest("uid=" + email + ",ou=Users,dc=endfirst,dc=com")
	req.Attribute("objectClass", []string{"posixAccount", "account", "ownCloud", "systemQuotas"})
	req.Attribute("uid", []string{email})
	req.Attribute("cn", []string{fullName})
	req.Attribute("userPassword", []string{passwordHash})
	req.Attribute("uidNumber", []string{strconv.Itoa(uidNumber)})
	req.Attribute("gidNumber", []string{strconv.Itoa(gidNumber)})
	req.Attribute("homeDirectory", []string{homeDirectory})
	req.Attribute("quota", []string{mailQuota})
	req.Attribute("ownCloudQuota", []string{fileQuota})
	err := l.db.Execute(req)
	return &UserLogin{}, err
}

func (l *backendLDAPLogin) UpdateEmail(email string, password string, newEmail string) (*UserLoginSession, error) {
	return nil, nil
}

func (l *backendLDAPLogin) UpdatePassword(email string, oldPassword string, newPassword string) (*UserLoginSession, error) {
	return nil, nil
}

func (l *backendLDAPLogin) Close() error {
	return l.db.Close()
}
