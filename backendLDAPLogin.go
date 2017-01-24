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

func newBackendLDAPLogin(server string, port int, bindDn, password, baseDn, userLoginFilter string) (loginBackender, error) {
	db, err := onedb.NewLdap(server, port, bindDn, password)
	if err != nil {
		return nil, err
	}
	return &backendLDAPLogin{db, baseDn, userLoginFilter}, nil
}

type ldapData struct {
	UID      string
	DbUserId string
	Cn       string
}

func (l *backendLDAPLogin) Login(email, password string) (*userLogin, error) {
	// check credentials
	err := l.db.Execute(ldap.NewSimpleBindRequest(email, password, nil))
	if err != nil {
		return nil, err
	}
	// get login info
	req := ldap.NewSearchRequest(l.baseDn, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, fmt.Sprintf(l.userLoginFilter, email), []string{"uid", "dbUserId", "cn"}, nil)
	data := &ldapData{}
	err = l.db.QueryStructRow(req, data)
	if err != nil {
		return nil, err
	}
	dbUserID, err := strconv.Atoi(data.DbUserId)
	if err != nil {
		return nil, err
	}
	return &userLogin{UserID: dbUserID, Email: data.UID, FullName: data.Cn}, nil
}

/****************  TODO: create different type of user if not using file and mail quotas  **********************/
func (l *backendLDAPLogin) CreateLogin(userID int, email, passwordHash, fullName, homeDirectory string, uidNumber, gidNumber int, mailQuota, fileQuota string) (*userLogin, error) {
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
	return &userLogin{}, err
}

func (l *backendLDAPLogin) UpdateEmail(email string, password string, newEmail string) (*loginSession, error) {
	return nil, nil
}

func (l *backendLDAPLogin) UpdatePassword(email string, oldPassword string, newPassword string) (*loginSession, error) {
	return nil, nil
}

func (l *backendLDAPLogin) Close() error {
	return l.db.Close()
}
