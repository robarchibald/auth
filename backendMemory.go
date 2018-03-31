package auth

import (
	"bytes"
	"fmt"
	"strconv"
	"time"
)

type backendMemory struct {
	Backender
	EmailSessions  []*emailSession
	Users          []*user
	Sessions       []*LoginSession
	RememberMes    []*rememberMeSession
	LoginProviders []*loginProvider
	LastUserID     int
	LastLoginID    int
	c              Crypter
}

const loginProviderDefaultName string = "Default"

// NewBackendMemory creates a memory-backed Backender
func NewBackendMemory(c Crypter) Backender {
	return &backendMemory{c: c, LoginProviders: []*loginProvider{&loginProvider{LoginProviderID: 1, Name: loginProviderDefaultName}}}
}

func (m *backendMemory) Login(email, password string) (*User, error) {
	user := m.getUserByEmail(email)
	if user == nil {
		return nil, errUserNotFound
	}
	if err := m.c.HashEquals(password, user.PasswordHash); err != nil {
		return nil, err
	}
	return &User{user.UserID, user.PrimaryEmail, user.FullName, user.Roles}, nil
}

func (m *backendMemory) CreateSession(userID, email, fullname, sessionHash, csrfToken string, roles []string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time) (*LoginSession, error) {
	session := m.getSessionByHash(sessionHash)
	if session != nil {
		return nil, errSessionAlreadyExists
	}

	session = &LoginSession{userID, email, fullname, sessionHash, csrfToken, roles, sessionRenewTimeUTC, sessionExpireTimeUTC}
	m.Sessions = append(m.Sessions, session)
	return session, nil
}

func (m *backendMemory) CreateRememberMe(userID, email, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*rememberMeSession, error) {
	rememberItem := m.getRememberMe(rememberMeSelector)
	if rememberItem != nil {
		return nil, errRememberMeSelectorExists
	}

	rememberItem = &rememberMeSession{userID, email, rememberMeSelector, rememberMeTokenHash, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC}
	m.RememberMes = append(m.RememberMes, rememberItem)
	return rememberItem, nil
}

func (m *backendMemory) GetSession(sessionHash string) (*LoginSession, error) {
	session := m.getSessionByHash(sessionHash)
	if session == nil {
		return nil, errSessionNotFound
	}
	return session, nil
}

func (m *backendMemory) UpdateSession(sessionHash string, renewTimeUTC, expireTimeUTC time.Time) error {
	session := m.getSessionByHash(sessionHash)
	if session == nil {
		return errSessionNotFound
	}
	session.ExpireTimeUTC = expireTimeUTC
	session.RenewTimeUTC = renewTimeUTC
	return nil
}

func (m *backendMemory) GetRememberMe(selector string) (*rememberMeSession, error) {
	rememberMe := m.getRememberMe(selector)
	if rememberMe == nil {
		return nil, errRememberMeNotFound
	}
	return rememberMe, nil
}

func (m *backendMemory) UpdateRememberMe(selector string, renewTimeUTC time.Time) error {
	rememberMe := m.getRememberMe(selector)
	if rememberMe == nil {
		return errRememberMeNotFound
	}
	rememberMe.RenewTimeUTC = renewTimeUTC
	return nil
}

func (m *backendMemory) CreateEmailSession(email, emailVerifyHash, csrfToken, destinationURL string) error {
	if m.getUserByEmail(email) != nil {
		return errUserAlreadyExists
	}
	if m.getEmailSessionByEmailVerifyHash(emailVerifyHash) != nil {
		return errEmailVerifyHashExists
	}

	m.EmailSessions = append(m.EmailSessions, &emailSession{"", email, emailVerifyHash, csrfToken, destinationURL})

	return nil
}

func (m *backendMemory) GetEmailSession(emailVerifyHash string) (*emailSession, error) {
	session := m.getEmailSessionByEmailVerifyHash(emailVerifyHash)
	if session == nil {
		return nil, errInvalidEmailVerifyHash
	}

	return session, nil
}

func (m *backendMemory) UpdateEmailSession(verifyHash, userID string) error {
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

func (m *backendMemory) AddUser(email string) (string, error) {
	u := m.getUserByEmail(email)
	if u != nil {
		return "", errUserAlreadyExists
	}
	m.LastUserID++
	m.Users = append(m.Users, &user{strconv.Itoa(m.LastUserID), "", "", email, nil, 0, nil})
	return strconv.Itoa(m.LastUserID), nil
}

func (m *backendMemory) GetUser(email string) (*User, error) {
	u := m.getUserByEmail(email)
	if u == nil {
		return nil, errUserNotFound
	}
	return &User{u.UserID, u.PrimaryEmail, u.FullName, u.Roles}, nil
}

func (m *backendMemory) UpdateUser(userID, fullname string, company string, pictureURL string) error {
	user := m.getUserByID(userID)
	if user == nil {
		return errUserNotFound
	}
	user.FullName = fullname
	// need to be able to create company and set pictureURL
	return nil
}

func (m *backendMemory) CreateLogin(userID, email, password, fullName string) (*User, error) {
	passwordHash, err := m.c.Hash(password)
	if err != nil {
		return nil, err
	}
	user := m.getUserByID(userID)
	if user == nil {
		return nil, errUserNotFound
	}
	user.FullName = fullName
	user.PasswordHash = passwordHash

	return &User{userID, email, fullName, user.Roles}, nil
}
func (m *backendMemory) CreateSecondaryEmail(userID, secondaryEmail string) error {
	return nil
}

func (m *backendMemory) SetPrimaryEmail(userID, newPrimaryEmail string) error {
	return nil
}

func (m *backendMemory) UpdatePassword(userID string, newPassword string) error {
	return nil
}

func (m *backendMemory) DeleteSession(sessionHash string) error {
	m.removeSession(sessionHash)
	return nil
}

func (m *backendMemory) InvalidateSessions(email string) error {
	return nil
}

func (m *backendMemory) DeleteRememberMe(selector string) error {
	m.removeRememberMe(selector)
	return nil
}

func (m *backendMemory) ToString() string {
	var buf bytes.Buffer
	buf.WriteString("Users:\n")
	for _, user := range m.Users {
		buf.WriteString(fmt.Sprintln("    ", *user))
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

func (m *backendMemory) getUserByID(userID string) *user {
	for _, user := range m.Users {
		if user.UserID == userID {
			return user
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

func (m *backendMemory) getSessionByHash(sessionHash string) *LoginSession {
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
