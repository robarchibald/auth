package main

import (
	"bytes"
	"fmt"
	"time"
)

type userLoginMemory struct {
	UserID       int
	Email        string
	FullName     string
	PasswordHash string
}

type backendMemory struct {
	backender
	EmailSessions  []*emailSession
	Users          []*user
	Logins         []*userLoginMemory
	Sessions       []*loginSession
	RememberMes    []*rememberMeSession
	LoginProviders []*loginProvider
	LastUserID     int
	LastLoginID    int
}

const loginProviderDefaultName string = "Default"

func newBackendMemory() backender {
	return &backendMemory{LoginProviders: []*loginProvider{&loginProvider{LoginProviderID: 1, Name: loginProviderDefaultName}}}
}

func (m *backendMemory) Login(email, password string) (*userLogin, error) {
	login := m.getLoginByEmail(email)
	if login == nil {
		return nil, errLoginNotFound
	}
	if err := cryptoHashEquals(password, login.PasswordHash); err != nil {
		return nil, err
	}
	return &userLogin{login.UserID, login.Email, login.FullName}, nil
}

func (m *backendMemory) CreateSession(userID int, email, fullname, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*loginSession, *rememberMeSession, error) {
	session := m.getSessionByHash(sessionHash)
	if session != nil {
		return nil, nil, errSessionAlreadyExists
	}

	session = &loginSession{userID, email, fullname, sessionHash, sessionRenewTimeUTC, sessionExpireTimeUTC}
	m.Sessions = append(m.Sessions, session)
	var rememberItem *rememberMeSession
	if rememberMe {
		rememberItem = m.getRememberMe(rememberMeSelector)
		if rememberItem != nil {
			return nil, nil, errRememberMeSelectorExists
		}

		rememberItem = &rememberMeSession{userID, email, rememberMeSelector, rememberMeTokenHash, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC}
		m.RememberMes = append(m.RememberMes, rememberItem)
	}
	return session, rememberItem, nil
}

func (m *backendMemory) GetSession(sessionHash string) (*loginSession, error) {
	session := m.getSessionByHash(sessionHash)
	if session == nil {
		return nil, errSessionNotFound
	}
	return session, nil
}

func (m *backendMemory) RenewSession(sessionHash string, renewTimeUTC time.Time) (*loginSession, error) {
	session := m.getSessionByHash(sessionHash)
	if session == nil {
		return nil, errSessionNotFound
	}
	session.RenewTimeUTC = renewTimeUTC
	return session, nil
}

func (m *backendMemory) GetRememberMe(selector string) (*rememberMeSession, error) {
	rememberMe := m.getRememberMe(selector)
	if rememberMe == nil {
		return nil, errRememberMeNotFound
	}
	return rememberMe, nil
}

func (m *backendMemory) RenewRememberMe(selector string, renewTimeUTC time.Time) (*rememberMeSession, error) {
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

func (m *backendMemory) CreateEmailSession(email, emailVerifyHash string) error {
	if m.getUserByEmail(email) != nil {
		return errUserAlreadyExists
	}
	if m.getEmailSessionByEmailVerifyHash(emailVerifyHash) != nil {
		return errEmailVerifyHashExists
	}

	m.EmailSessions = append(m.EmailSessions, &emailSession{Email: email, EmailVerifyHash: emailVerifyHash})

	return nil
}

func (m *backendMemory) GetEmailSession(emailVerifyHash string) (*emailSession, error) {
	session := m.getEmailSessionByEmailVerifyHash(emailVerifyHash)
	if session == nil {
		return nil, errInvalidEmailVerifyHash
	}

	return session, nil
}

func (m *backendMemory) UpdateEmailSession(verifyHash string, userID int, email string) error {
	session := m.getEmailSessionByEmailVerifyHash(verifyHash)
	if session == nil {
		return errEmailVerifyHashExists
	}
	session.UserID = userID
	return nil
}

// ***************** TODO: need to come up with a way to clean up all sessions for this email **************
func (m *backendMemory) DeleteEmailSession(emailVerifyHash string) error {
	m.removeEmailSession(emailVerifyHash)
	return nil
}

func (m *backendMemory) AddUser(email string) (int, error) {
	u := m.getUserByEmail(email)
	if u != nil {
		return -1, errUserAlreadyExists
	}
	m.LastUserID++
	m.Users = append(m.Users, &user{m.LastUserID, "", email, nil, 0})
	return m.LastUserID, nil
}

func (m *backendMemory) GetUser(email string) (*user, error) {
	u := m.getUserByEmail(email)
	if u == nil {
		return nil, errUserNotFound
	}
	return u, nil
}

func (m *backendMemory) UpdateUser(email, fullname string, company string, pictureURL string) error {
	user := m.getUserByEmail(email)
	if user == nil {
		return errUserNotFound
	}
	user.FullName = fullname
	// need to be able to create company and set pictureURL
	return nil
}

func (m *backendMemory) CreateLogin(userID, dbUserID int, email, passwordHash, fullName, homeDirectory string, uidNumber, gidNumber int, mailQuota, fileQuota string) (*userLogin, error) {
	login := userLoginMemory{userID, email, fullName, passwordHash}
	m.Logins = append(m.Logins, &login)

	return &userLogin{userID, email, fullName}, nil
}

func (m *backendMemory) UpdateEmail(email string, password string, newEmail string) (*loginSession, error) {
	return nil, nil
}

func (m *backendMemory) UpdatePassword(email string, oldPassword string, newPassword string) (*loginSession, error) {
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

func (m *backendMemory) removeEmailSession(emailVerifyHash string) {
	for i := 0; i < len(m.EmailSessions); i++ {
		session := m.EmailSessions[i]
		if session.EmailVerifyHash == emailVerifyHash {
			m.EmailSessions = append(m.EmailSessions[:i], m.EmailSessions[i+1:]...) // remove item
			break
		}
	}
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

func (m *backendMemory) getLoginByUser(email string) *userLoginMemory {
	for _, login := range m.Logins {
		if login.Email == email {
			return login
		}
	}
	return nil
}

func (m *backendMemory) getLoginByEmail(email string) *userLoginMemory {
	for _, login := range m.Logins {
		if login.Email == email {
			return login
		}
	}
	return nil
}

func (m *backendMemory) getUserByEmail(email string) *user {
	for _, user := range m.Users {
		if user.PrimaryEmail == email {
			return user
		}
	}
	return nil
}

func (m *backendMemory) getEmailSessionByEmailVerifyHash(hash string) *emailSession {
	for _, session := range m.EmailSessions {
		if session.EmailVerifyHash == hash {
			return session
		}
	}
	return nil
}

func (m *backendMemory) getSessionByHash(sessionHash string) *loginSession {
	for _, session := range m.Sessions {
		if session.SessionHash == sessionHash {
			return session
		}
	}
	return nil
}

func (m *backendMemory) getRememberMe(selector string) *rememberMeSession {
	for _, rememberMe := range m.RememberMes {
		if rememberMe.Selector == selector {
			return rememberMe
		}
	}
	return nil
}
