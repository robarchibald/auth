package nginxauth

import (
	"errors"

	"time"

	"github.com/robarchibald/configReader"
	"github.com/robarchibald/onedb"
)

type userLoginSessionPlusEmail struct {
	LoginId      int
	SessionId    string
	UserId       int
	PrimaryEmail string
	ExpiresAt    time.Time
	RenewsAt     time.Time
	IsHalfAuth   bool
}

type BackendPostgres struct {
	BackendQuerier
	Db                                       onedb.DBer
	BackendType                              string
	BackendServer                            string
	BackendPort                              int
	BackendUser                              string
	BackendDatabase                          string
	BackendPassword                          string
	GetUserLoginQuery                        string
	GetSessionQuery                          string
	RenewSessionQuery                        string
	GetRememberMeQuery                       string
	RenewRememberMeQuery                     string
	AddUserQuery                             string
	VerifyEmailQuery                         string
	UpdateUserQuery                          string
	CreateProfileAndInvalidateSessionsQuery  string
	UpdateEmailAndInvalidateSessionsQuery    string
	UpdatePasswordAndInvalidateSessionsQuery string
	InvalidateUserSessionsQuery              string
}

func NewBackend(configPath string) (BackendQuerier, error) {
	backend := &BackendPostgres{}
	configReader.ReadFile(configPath, backend)

	db, err := onedb.NewPgx(backend.BackendServer, uint16(backend.BackendPort), backend.BackendUser,
		backend.BackendPassword, backend.BackendDatabase)
	if err != nil {
		return nil, err
	}
	backend.Db = db
	return backend, nil
}

func (b *BackendPostgres) GetUserLogin(email, loginProvider string) (*UserLogin, error) {
	var login *UserLogin
	return login, b.Db.QueryStruct(onedb.NewSqlQuery(b.GetUserLoginQuery, email, loginProvider), login)
}
func (b *BackendPostgres) GetSession(sessionId string) (*UserLoginSession, error) {
	var session *UserLoginSession
	return session, b.Db.QueryStructRow(onedb.NewSqlQuery(b.GetSessionQuery, sessionId), session)
}

func (b *BackendPostgres) RenewSession(sessionId string, renewsAt time.Time) (*UserLoginSession, error) {
	var session *UserLoginSession
	return session, b.Db.QueryStructRow(onedb.NewSqlQuery(b.RenewSessionQuery, sessionId), session)
}

func (b *BackendPostgres) GetRememberMe(selector string) (*UserLoginRememberMe, error) {
	var rememberMe *UserLoginRememberMe
	return rememberMe, b.Db.QueryStructRow(onedb.NewSqlQuery(b.GetRememberMeQuery, selector), rememberMe)
}

func (b *BackendPostgres) RenewRememberMe(selector string, renewsAt time.Time) (*UserLoginRememberMe, error) {
	var rememberMe *UserLoginRememberMe
	return rememberMe, b.Db.QueryStructRow(onedb.NewSqlQuery(b.RenewRememberMeQuery, selector), rememberMe)
}

func (b *BackendPostgres) AddUser(email, emailVerifyHash, sessionId string, sessionRenewsAt, sessionExpiresAt time.Time) (*UserLoginSession, error) {
	var session *UserLoginSession
	return session, b.Db.QueryStructRow(onedb.NewSqlQuery(b.AddUserQuery, email, emailVerifyHash), session) // should be stored proc so it'll add to multiple tables, plus return values needed
}

func (b *BackendPostgres) VerifyEmail(emailVerifyCode string, sessionId string, sessionRenewsAt, sessionExpiresAt time.Time) (*UserLoginSession, string, error) {
	var session *userLoginSessionPlusEmail
	err := b.Db.QueryStructRow(onedb.NewSqlQuery(b.VerifyEmailQuery, emailVerifyCode), session) // should be stored proc so it'll verify, plus return values needed
	if err != nil || session == nil {
		return nil, "", errors.New("Unable to verify email: " + err.Error())
	}
	return &UserLoginSession{session.LoginId, session.SessionId, session.UserId, session.ExpiresAt, session.RenewsAt, session.IsHalfAuth}, session.PrimaryEmail, err

	return nil, "email", nil
}

func (b *BackendPostgres) UpdateUser(session *UserLoginSession, fullname string, company string, pictureUrl string) error {
	return nil
}

func (b *BackendPostgres) CreateProfileAndInvalidateSessions(loginId int, passwordHash string, fullName string, company string, pictureUrl string, sessionId string, sessionExpiresAt, sessionRenewsAt time.Time) (*UserLoginSession, error) {
	return nil, nil
}

func (b *BackendPostgres) UpdateEmailAndInvalidateSessions(email string, password string, newEmail string) (*UserLoginSession, error) {
	return nil, nil
}

func (b *BackendPostgres) UpdatePasswordAndInvalidateSessions(email string, oldPassword string, newPassword string) (*UserLoginSession, error) {
	return nil, nil
}

func (b *BackendPostgres) InvalidateUserSessions(userId int) error {
	return nil
}

func (b *BackendPostgres) Close() error {
	return b.Db.Close()
}
