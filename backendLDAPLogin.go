package auth

import (
	"fmt"

	"github.com/EndFirstCorp/onedb"
	"gopkg.in/ldap.v2"
)

type backendLDAPLogin struct {
	db          onedb.DBer
	baseDn      string
	userBackend UserBackender
}

// NewBackendLDAPLogin creates a LoginBackender using OpenLDAP
func NewBackendLDAPLogin(server string, port int, bindDn, password, baseDn string, userBackend UserBackender) (loginBackender, error) {
	db, err := onedb.NewLdap(server, port, bindDn, password)
	if err != nil {
		return nil, err
	}
	return &backendLDAPLogin{db, baseDn, userBackend}, nil
}

type ldapData struct {
	UID      string
	DbUserId string
	Cn       string
}

func (l *backendLDAPLogin) Login(email, password string) (*User, error) {
	// check credentials
	err := l.db.Execute(ldap.NewSimpleBindRequest(fmt.Sprintf("uid=%s,%s", email, l.baseDn), password, nil))
	if err != nil {
		return nil, err
	}
	return l.userBackend.GetUser(email)
}

/****************  TODO: create different type of user if not using file and mail quotas  **********************/
func (l *backendLDAPLogin) CreateLogin(userID, email, password, fullName string) (*User, error) {
	req := ldap.NewAddRequest("uid=" + email + "," + l.baseDn)
	req.Attribute("objectClass", []string{"endfirstAccount"})
	req.Attribute("uid", []string{email})
	req.Attribute("userPassword", []string{password})
	err := l.db.Execute(req)
	return &User{}, err
}

func (l *backendLDAPLogin) CreateSecondaryEmail(userID, secondaryEmail string) error {
	return nil
}

func (l *backendLDAPLogin) SetPrimaryEmail(userID, newPrimaryEmail string) error {
	return nil
}
func (l *backendLDAPLogin) UpdatePassword(userID, newPassword string) error {
	return nil
}

func (l *backendLDAPLogin) Close() error {
	return l.db.Close()
}
