package nginxauth

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
	return &BackendMemory{LoginProviders: []*UserLoginProvider{&UserLoginProvider{1, LoginProviderDefaultName}}}
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

func (m *BackendMemory) NewLoginSession(loginId int, sessionId string, sessionRenewsAt, sessionExpiresAt time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewsAt, rememberMeExpiresAt time.Time) (*UserLoginSession, *UserLoginRememberMe, error) {
	login := m.getLoginByLoginId(loginId)
	if login == nil {
		return nil, nil, ErrLoginNotFound
	}
	session := m.getSessionByLoginId(login.LoginId)
	if session != nil {
		session.SessionId = sessionId // update sessionID
		session.ExpiresAt = sessionExpiresAt
		session.RenewsAt = sessionRenewsAt
	} else {
		session = &UserLoginSession{loginId, sessionId, login.UserId, sessionExpiresAt, sessionRenewsAt, false}
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
			rememberItem.ExpiresAt = rememberMeExpiresAt
			rememberItem.RenewsAt = rememberMeRenewsAt
		} else {
			rememberItem = &UserLoginRememberMe{login.LoginId, rememberMeSelector, rememberMeTokenHash, rememberMeExpiresAt, rememberMeRenewsAt}
			m.RememberMes = append(m.RememberMes, rememberItem)
		}
	}
	return session, rememberItem, nil
}
func (m *BackendMemory) GetSession(sessionId string) (*UserLoginSession, error) {
	session := m.getSessionById(sessionId)
	if session == nil {
		return nil, ErrSessionNotFound
	}
	return session, nil
}
func (m *BackendMemory) RenewSession(sessionId string, renewsAt time.Time) (*UserLoginSession, error) {
	session := m.getSessionById(sessionId)
	if session == nil {
		return nil, ErrSessionNotFound
	}
	session.RenewsAt = renewsAt
	return session, nil
}
func (m *BackendMemory) GetRememberMe(selector string) (*UserLoginRememberMe, error) {
	rememberMe := m.getRememberMe(selector)
	if rememberMe == nil {
		return nil, ErrRememberMeNotFound
	}
	return rememberMe, nil
}
func (m *BackendMemory) RenewRememberMe(selector string, renewsAt time.Time) (*UserLoginRememberMe, error) {
	rememberMe := m.getRememberMe(selector)
	if rememberMe == nil {
		return nil, ErrRememberMeNotFound
	} else if rememberMe.ExpiresAt.Before(time.Now().UTC()) {
		return nil, ErrRememberMeExpired
	} else if rememberMe.ExpiresAt.Before(renewsAt) || renewsAt.Before(time.Now().UTC()) {
		return nil, ErrInvalidRenewsAtTime
	}
	rememberMe.RenewsAt = renewsAt
	return rememberMe, nil
}
func (m *BackendMemory) AddUser(email, emailVerifyHash, sessionId string, sessionRenewsAt, sessionExpiresAt time.Time) (*UserLoginSession, error) {
	if m.getUserByEmail(email) != nil {
		return nil, ErrUserAlreadyExists
	}
	if m.getUserByEmailVerifyHash(emailVerifyHash) != nil {
		return nil, ErrEmailVerifyCodeExists
	}
	m.LastUserId = m.LastUserId + 1
	user := &User{m.LastUserId, "", email, emailVerifyHash, false, nil, 0}
	m.Users = append(m.Users, user)
	m.LastLoginId = m.LastLoginId + 1
	login := &UserLogin{m.LastLoginId, user.UserId, 1, ""}
	m.Logins = append(m.Logins, login)
	session := &UserLoginSession{login.LoginId, sessionId, user.UserId, sessionExpiresAt, sessionRenewsAt, true}
	m.Sessions = append(m.Sessions, session)

	return session, nil
}

func (m *BackendMemory) VerifyEmail(emailVerifyHash, sessionId string, sessionRenewsAt, sessionExpiresAt time.Time) (*UserLoginSession, string, error) {
	user := m.getUserByEmailVerifyHash(emailVerifyHash)
	if user == nil {
		return nil, "", ErrInvalidEmailVerifyCode
	}

	login := m.getLoginByUser(user.UserId, LoginProviderDefaultName)
	if login == nil {
		return nil, "", ErrLoginNotFound
	}
	session := m.getSessionById(sessionId)
	if session != nil && (session.UserId != user.UserId || session.LoginId != login.LoginId) {
		return nil, "", ErrInvalidSessionId
	} else if session != nil {
		session.ExpiresAt = sessionExpiresAt
		session.RenewsAt = sessionRenewsAt
	} else {
		session = &UserLoginSession{login.LoginId, sessionId, user.UserId, sessionExpiresAt, sessionRenewsAt, true}
		m.Sessions = append(m.Sessions, session)
	}
	user.EmailVerified = true
	return session, user.PrimaryEmail, nil
}

func (m *BackendMemory) UpdateUser(session *UserLoginSession, fullname string, company string, pictureUrl string) error {
	return nil
}

func (m *BackendMemory) CreateProfileAndInvalidateSessions(loginId int, passwordHash string, fullName string, company string, pictureUrl string, sessionId string, sessionExpiresAt, sessionRenewsAt time.Time) (*UserLoginSession, error) {
	login := m.getLoginByLoginId(loginId)
	if login == nil {
		return nil, ErrLoginNotFound
	}
	login.ProviderKey = passwordHash
	user := m.getUserByUserId(login.UserId)
	if user == nil {
		return nil, ErrUserNotFound
	}
	user.FullName = fullName
	m.removeSessions(login.LoginId)
	session, _, err := m.NewLoginSession(login.LoginId, sessionId, sessionRenewsAt, sessionExpiresAt, false, "", "", time.Time{}, time.Time{})
	return session, err
	//user.CompanyId = ???
	return nil, nil
}
func (m *BackendMemory) UpdateEmailAndInvalidateSessions(email string, password string, newEmail string) (*UserLoginSession, error) {
	return nil, nil
}
func (m *BackendMemory) UpdatePasswordAndInvalidateSessions(email string, oldPassword string, newPassword string) (*UserLoginSession, error) {
	return nil, nil
}
func (m *BackendMemory) InvalidateUserSessions(userId int) error {
	m.removeSessions(userId)
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

func (m *BackendMemory) getUserByUserId(userId int) *User {
	for _, user := range m.Users {
		if user.UserId == userId {
			return user
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

func (m *BackendMemory) getSessionById(sessionId string) *UserLoginSession {
	for _, session := range m.Sessions {
		if session.SessionId == sessionId {
			return session
		}
	}
	return nil
}

func (m *BackendMemory) getSessionByLoginId(loginId int) *UserLoginSession {
	for _, session := range m.Sessions {
		if session.LoginId == loginId {
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
