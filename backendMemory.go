package main

import (
	"bytes"
	"fmt"
	"time"
)

type backendMemory struct {
	Backender
	Users          []*User
	Logins         []*UserLogin
	Sessions       []*UserLoginSession
	RememberMes    []*UserLoginRememberMe
	LoginProviders []*UserLoginProvider
	LastUserID     int
	LastLoginID    int
}

const loginProviderDefaultName string = "Default"

func NewBackendMemory() Backender {
	return &backendMemory{LoginProviders: []*UserLoginProvider{&UserLoginProvider{LoginProviderID: 1, Name: loginProviderDefaultName}}}
}

func (m *backendMemory) GetLogin(email, loginProvider string) (*UserLogin, error) {
	user := m.getUserByEmail(email)
	if user == nil {
		return nil, errUserNotFound
	}
	login := m.getLoginByUser(user.UserID, loginProvider)
	if login == nil {
		return nil, errLoginNotFound
	}
	return login, nil
}

func (m *backendMemory) CreateSession(loginID, userID int, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*UserLoginSession, *UserLoginRememberMe, error) {
	login := m.getLoginByLoginID(loginID)
	if login == nil {
		return nil, nil, errLoginNotFound
	}
	session := m.getSessionByHash(sessionHash)
	if session != nil {
		session.SessionHash = sessionHash // update sessionHash
		session.ExpireTimeUTC = sessionExpireTimeUTC
		session.RenewTimeUTC = sessionRenewTimeUTC
	} else {
		session = &UserLoginSession{loginID, sessionHash, login.UserID, sessionRenewTimeUTC, sessionExpireTimeUTC}
		m.Sessions = append(m.Sessions, session)
	}
	var rememberItem *UserLoginRememberMe
	if rememberMe {
		rememberItem = m.getRememberMe(rememberMeSelector)
		if rememberItem != nil && rememberItem.LoginID != login.LoginID { // existing is for different login, so can't continue
			return nil, nil, errRememberMeSelectorExists
		} else if rememberItem != nil { // update the existing rememberMe
			rememberItem.Selector = rememberMeSelector
			rememberItem.TokenHash = rememberMeTokenHash
			rememberItem.ExpireTimeUTC = rememberMeExpireTimeUTC
			rememberItem.RenewTimeUTC = rememberMeRenewTimeUTC
		} else {
			rememberItem = &UserLoginRememberMe{login.LoginID, rememberMeSelector, rememberMeTokenHash, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC}
			m.RememberMes = append(m.RememberMes, rememberItem)
		}
	}
	return session, rememberItem, nil
}

func (m *backendMemory) GetSession(sessionHash string) (*UserLoginSession, error) {
	session := m.getSessionByHash(sessionHash)
	if session == nil {
		return nil, errSessionNotFound
	}
	return session, nil
}

func (m *backendMemory) RenewSession(sessionHash string, renewTimeUTC time.Time) (*UserLoginSession, error) {
	session := m.getSessionByHash(sessionHash)
	if session == nil {
		return nil, errSessionNotFound
	}
	session.RenewTimeUTC = renewTimeUTC
	return session, nil
}

func (m *backendMemory) GetRememberMe(selector string) (*UserLoginRememberMe, error) {
	rememberMe := m.getRememberMe(selector)
	if rememberMe == nil {
		return nil, errRememberMeNotFound
	}
	return rememberMe, nil
}

func (m *backendMemory) RenewRememberMe(selector string, renewTimeUTC time.Time) (*UserLoginRememberMe, error) {
	rememberMe := m.getRememberMe(selector)
	if rememberMe == nil {
		return nil, errRememberMeNotFound
	} else if rememberMe.ExpireTimeUTC.Before(time.Now().UTC()) {
		return nil, errRememberMeExpired
	} else if rememberMe.ExpireTimeUTC.Before(renewTimeUTC) || renewTimeUTC.Before(time.Now().UTC()) {
		return nil, errInvalidRenewTimeUTC
	}
	rememberMe.RenewTimeUTC = renewTimeUTC
	return rememberMe, nil
}

func (m *backendMemory) AddUser(email, emailVerifyHash string) error {
	if m.getUserByEmail(email) != nil {
		return errUserAlreadyExists
	}
	if m.getUserByEmailVerifyHash(emailVerifyHash) != nil {
		return errEmailVerifyHashExists
	}
	m.LastUserID = m.LastUserID + 1
	user := &User{m.LastUserID, "", email, emailVerifyHash, false, nil, 0}
	m.Users = append(m.Users, user)

	return nil
}

func (m *backendMemory) VerifyEmail(emailVerifyHash string) (string, error) {
	user := m.getUserByEmailVerifyHash(emailVerifyHash)
	if user == nil {
		return "", errInvalidEmailVerifyHash
	}

	user.EmailVerified = true
	return user.PrimaryEmail, nil
}

func (m *backendMemory) UpdateUser(emailVerifyHash, fullname string, company string, pictureURL string) (string, error) {
	user := m.getUserByEmailVerifyHash(emailVerifyHash)
	if user == nil {
		return "", errUserNotFound
	}
	user.FullName = fullname
	// need to be able to create company and set pictureURL
	return user.PrimaryEmail, nil
}

// This method needs to be fixed to work with the new data model using LDAP
func (m *backendMemory) CreateLogin(email, passwordHash, fullName, homeDirectory string, uidNumber, gidNumber int, mailQuota, fileQuota string) (*UserLogin, error) {
	user := m.getUserByEmail(email)
	if user == nil {
		return nil, errUserNotFound
	}
	user.FullName = fullName

	m.LastLoginID = m.LastLoginID + 1
	login := UserLogin{m.LastLoginID, user.UserID, 1, passwordHash}
	m.Logins = append(m.Logins, &login)

	return &login, nil
}

func (m *backendMemory) UpdateEmail(email string, password string, newEmail string) (*UserLoginSession, error) {
	return nil, nil
}

func (m *backendMemory) UpdatePassword(email string, oldPassword string, newPassword string) (*UserLoginSession, error) {
	return nil, nil
}

func (m *backendMemory) InvalidateSession(sessionHash string) error {
	m.removeSession(sessionHash)
	return nil
}

func (m *backendMemory) InvalidateSessions(email string) error {
	return nil
}

func (m *backendMemory) InvalidateRememberMe(selector string) error {
	m.removeRememberMe(selector)
	return nil
}

func (m *backendMemory) ToString() string {
	var buf bytes.Buffer
	buf.WriteString("Users:\n")
	for _, user := range m.Users {
		buf.WriteString(fmt.Sprintln("    ", *user))
	}
	buf.WriteString("Logins:\n")
	for _, login := range m.Logins {
		buf.WriteString(fmt.Sprintln("    ", *login))
	}
	buf.WriteString("Sessions:\n")
	for _, session := range m.Sessions {
		buf.WriteString(fmt.Sprintln("    ", *session))
	}
	buf.WriteString("RememberMe:\n")
	for _, rememberMe := range m.RememberMes {
		buf.WriteString(fmt.Sprintln("    ", *rememberMe))
	}
	return buf.String()
}

func (m *backendMemory) Close() error {
	return nil
}

func (m *backendMemory) removeRememberMe(selector string) {
	for i := 0; i < len(m.RememberMes); i++ {
		rememberMe := m.RememberMes[i]
		if rememberMe.Selector == selector {
			m.RememberMes = append(m.RememberMes[:i], m.RememberMes[i+1:]...) // remove item
			break
		}
	}
}

func (m *backendMemory) removeSession(sessionHash string) {
	for i := 0; i < len(m.Sessions); i++ {
		session := m.Sessions[i]
		if session.SessionHash == sessionHash {
			m.Sessions = append(m.Sessions[:i], m.Sessions[i+1:]...) // remove item
			break
		}
	}
}

func (m *backendMemory) getLoginProvider(name string) *UserLoginProvider {
	for _, provider := range m.LoginProviders {
		if provider.Name == name {
			return provider
		}
	}
	return nil
}

func (m *backendMemory) getLoginByUser(userID int, loginProvider string) *UserLogin {
	provider := m.getLoginProvider(loginProvider)
	if provider == nil {
		return nil
	}
	for _, login := range m.Logins {
		if login.UserID == userID && login.LoginProviderID == provider.LoginProviderID {
			return login
		}
	}
	return nil
}

func (m *backendMemory) getLoginByLoginID(loginID int) *UserLogin {
	for _, login := range m.Logins {
		if login.LoginID == loginID {
			return login
		}
	}
	return nil
}

func (m *backendMemory) getUserByEmail(email string) *User {
	for _, user := range m.Users {
		if user.PrimaryEmail == email {
			return user
		}
	}
	return nil
}

func (m *backendMemory) getUserByEmailVerifyHash(hash string) *User {
	for _, user := range m.Users {
		if user.EmailVerifyHash == hash {
			return user
		}
	}
	return nil
}

func (m *backendMemory) getSessionByHash(sessionHash string) *UserLoginSession {
	for _, session := range m.Sessions {
		if session.SessionHash == sessionHash {
			return session
		}
	}
	return nil
}

func (m *backendMemory) getRememberMe(selector string) *UserLoginRememberMe {
	for _, rememberMe := range m.RememberMes {
		if rememberMe.Selector == selector {
			return rememberMe
		}
	}
	return nil
}
