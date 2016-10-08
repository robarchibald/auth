package main

import (
	"bytes"
	"fmt"
	"time"
)

type BackendMemory struct {
	BackendQuerier
	Users          []*User
	Logins         []*UserLogin
	Sessions       []*UserLoginSession
	RememberMes    []*UserLoginRememberMe
	LoginProviders []*UserLoginProvider
	LastUserId     int
	LastLoginId    int
}

const LoginProviderDefaultName string = "Default"

func NewBackendMemory() *BackendMemory {
	return &BackendMemory{LoginProviders: []*UserLoginProvider{&UserLoginProvider{LoginProviderId: 1, Name: LoginProviderDefaultName}}}
}

func (m *BackendMemory) GetUserLogin(email, loginProvider string) (*UserLogin, error) {
	user := m.getUserByEmail(email)
	if user == nil {
		return nil, ErrUserNotFound
	}
	login := m.getLoginByUser(user.UserId, loginProvider)
	if login == nil {
		return nil, ErrLoginNotFound
	}
	return login, nil
}

func (m *BackendMemory) NewLoginSession(loginId, userId int, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*UserLoginSession, *UserLoginRememberMe, error) {
	login := m.getLoginByLoginId(loginId)
	if login == nil {
		return nil, nil, ErrLoginNotFound
	}
	session := m.getSessionByHash(sessionHash)
	if session != nil {
		session.SessionHash = sessionHash // update sessionHash
		session.ExpireTimeUTC = sessionExpireTimeUTC
		session.RenewTimeUTC = sessionRenewTimeUTC
	} else {
		session = &UserLoginSession{loginId, sessionHash, login.UserId, sessionRenewTimeUTC, sessionExpireTimeUTC}
		m.Sessions = append(m.Sessions, session)
	}
	var rememberItem *UserLoginRememberMe
	if rememberMe {
		rememberItem = m.getRememberMe(rememberMeSelector)
		if rememberItem != nil && rememberItem.LoginId != login.LoginId { // existing is for different login, so can't continue
			return nil, nil, ErrRememberMeSelectorExists
		} else if rememberItem != nil { // update the existing rememberMe
			rememberItem.Selector = rememberMeSelector
			rememberItem.TokenHash = rememberMeTokenHash
			rememberItem.ExpireTimeUTC = rememberMeExpireTimeUTC
			rememberItem.RenewTimeUTC = rememberMeRenewTimeUTC
		} else {
			rememberItem = &UserLoginRememberMe{login.LoginId, rememberMeSelector, rememberMeTokenHash, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC}
			m.RememberMes = append(m.RememberMes, rememberItem)
		}
	}
	return session, rememberItem, nil
}
func (m *BackendMemory) GetSession(sessionHash string) (*UserLoginSession, error) {
	session := m.getSessionByHash(sessionHash)
	if session == nil {
		return nil, ErrSessionNotFound
	}
	return session, nil
}
func (m *BackendMemory) RenewSession(sessionHash string, renewTimeUTC time.Time) (*UserLoginSession, error) {
	session := m.getSessionByHash(sessionHash)
	if session == nil {
		return nil, ErrSessionNotFound
	}
	session.RenewTimeUTC = renewTimeUTC
	return session, nil
}
func (m *BackendMemory) GetRememberMe(selector string) (*UserLoginRememberMe, error) {
	rememberMe := m.getRememberMe(selector)
	if rememberMe == nil {
		return nil, ErrRememberMeNotFound
	}
	return rememberMe, nil
}
func (m *BackendMemory) RenewRememberMe(selector string, renewTimeUTC time.Time) (*UserLoginRememberMe, error) {
	rememberMe := m.getRememberMe(selector)
	if rememberMe == nil {
		return nil, ErrRememberMeNotFound
	} else if rememberMe.ExpireTimeUTC.Before(time.Now().UTC()) {
		return nil, ErrRememberMeExpired
	} else if rememberMe.ExpireTimeUTC.Before(renewTimeUTC) || renewTimeUTC.Before(time.Now().UTC()) {
		return nil, ErrInvalidRenewTimeUTC
	}
	rememberMe.RenewTimeUTC = renewTimeUTC
	return rememberMe, nil
}
func (m *BackendMemory) AddUser(email, emailVerifyHash string) error {
	if m.getUserByEmail(email) != nil {
		return ErrUserAlreadyExists
	}
	if m.getUserByEmailVerifyHash(emailVerifyHash) != nil {
		return ErrEmailVerifyHashExists
	}
	m.LastUserId = m.LastUserId + 1
	user := &User{m.LastUserId, "", email, emailVerifyHash, false, nil, 0}
	m.Users = append(m.Users, user)

	return nil
}

func (m *BackendMemory) VerifyEmail(emailVerifyHash string) (string, error) {
	user := m.getUserByEmailVerifyHash(emailVerifyHash)
	if user == nil {
		return "", ErrInvalidEmailVerifyHash
	}

	user.EmailVerified = true
	return user.PrimaryEmail, nil
}

func (m *BackendMemory) UpdateUser(session *UserLoginSession, fullname string, company string, pictureUrl string) error {
	return nil
}

// This function isn't right yet. Not creating company. Not sure if anything else is missing
func (m *BackendMemory) CreateLogin(emailVerifyHash, passwordHash string, fullName string, company string, pictureUrl string, sessionHash string, sessionExpireTimeUTC, sessionRenewTimeUTC time.Time) (*UserLoginSession, error) {
	user := m.getUserByEmailVerifyHash(emailVerifyHash)
	if user == nil {
		return nil, ErrUserNotFound
	}
	user.FullName = fullName
	//user.CompanyId = ???

	m.LastLoginId = m.LastLoginId + 1
	login := UserLogin{m.LastLoginId, user.UserId, 1, passwordHash}
	m.Logins = append(m.Logins, &login)

	// don't set remember me
	session, _, err := m.NewLoginSession(login.LoginId, login.UserId, sessionHash, sessionRenewTimeUTC, sessionExpireTimeUTC, false, "", "", time.Time{}, time.Time{})
	return session, err
}

func (m *BackendMemory) UpdateEmailAndInvalidateSessions(email string, password string, newEmail string) (*UserLoginSession, error) {
	return nil, nil
}
func (m *BackendMemory) UpdatePasswordAndInvalidateSessions(email string, oldPassword string, newPassword string) (*UserLoginSession, error) {
	return nil, nil
}
func (m *BackendMemory) InvalidateSession(sessionHash string) error {
	m.removeSession(sessionHash)
	return nil
}
func (m *BackendMemory) InvalidateRememberMe(selector string) error {
	m.removeRememberMe(selector)
	return nil
}

func (m *BackendMemory) ToString() string {
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

func (m *BackendMemory) Close() error {
	return nil
}

func (m *BackendMemory) removeRememberMe(selector string) {
	for i := 0; i < len(m.RememberMes); i++ {
		rememberMe := m.RememberMes[i]
		if rememberMe.Selector == selector {
			m.RememberMes = append(m.RememberMes[:i], m.RememberMes[i+1:]...) // remove item
			break
		}
	}
}

func (m *BackendMemory) removeSession(sessionHash string) {
	for i := 0; i < len(m.Sessions); i++ {
		session := m.Sessions[i]
		if session.SessionHash == sessionHash {
			m.Sessions = append(m.Sessions[:i], m.Sessions[i+1:]...) // remove item
			break
		}
	}
}

func (m *BackendMemory) removeSessions(userId int) {
	for i := 0; i < len(m.Sessions); i++ {
		session := m.Sessions[i]
		if session.UserId == userId {
			m.Sessions = append(m.Sessions[:i], m.Sessions[i+1:]...) // remove item
			i--                                                      // removed item, so keep at the same index
		}
	}
}

func (m *BackendMemory) getLoginProvider(name string) *UserLoginProvider {
	for _, provider := range m.LoginProviders {
		if provider.Name == name {
			return provider
		}
	}
	return nil
}

func (m *BackendMemory) getLoginByUser(userId int, loginProvider string) *UserLogin {
	provider := m.getLoginProvider(loginProvider)
	if provider == nil {
		return nil
	}
	for _, login := range m.Logins {
		if login.UserId == userId && login.LoginProviderId == provider.LoginProviderId {
			return login
		}
	}
	return nil
}

func (m *BackendMemory) getLoginByLoginId(loginId int) *UserLogin {
	for _, login := range m.Logins {
		if login.LoginId == loginId {
			return login
		}
	}
	return nil
}

func (m *BackendMemory) getUserByEmail(email string) *User {
	for _, user := range m.Users {
		if user.PrimaryEmail == email {
			return user
		}
	}
	return nil
}

func (m *BackendMemory) getUserByEmailVerifyHash(hash string) *User {
	for _, user := range m.Users {
		if user.EmailVerifyHash == hash {
			return user
		}
	}
	return nil
}

func (m *BackendMemory) getSessionByHash(sessionHash string) *UserLoginSession {
	for _, session := range m.Sessions {
		if session.SessionHash == sessionHash {
			return session
		}
	}
	return nil
}

func (m *BackendMemory) getRememberMe(selector string) *UserLoginRememberMe {
	for _, rememberMe := range m.RememberMes {
		if rememberMe.Selector == selector {
			return rememberMe
		}
	}
	return nil
}
