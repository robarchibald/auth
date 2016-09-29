package nginxauth

import (
	"errors"

	"time"

	"github.com/robarchibald/configReader"
	"github.com/robarchibald/onedb"
)

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
	CreateLoginQuery                         string
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
func (b *BackendPostgres) GetSession(sessionHash string) (*UserLoginSession, error) {
	var session *UserLoginSession
	return session, b.Db.QueryStructRow(onedb.NewSqlQuery(b.GetSessionQuery, sessionHash), session)
}

func (b *BackendPostgres) RenewSession(sessionHash string, renewTimeUTC time.Time) (*UserLoginSession, error) {
	var session *UserLoginSession
	return session, b.Db.QueryStructRow(onedb.NewSqlQuery(b.RenewSessionQuery, sessionHash), session)
}

func (b *BackendPostgres) GetRememberMe(selector string) (*UserLoginRememberMe, error) {
	var rememberMe *UserLoginRememberMe
	return rememberMe, b.Db.QueryStructRow(onedb.NewSqlQuery(b.GetRememberMeQuery, selector), rememberMe)
}

func (b *BackendPostgres) RenewRememberMe(selector string, renewTimeUTC time.Time) (*UserLoginRememberMe, error) {
	var rememberMe *UserLoginRememberMe
	return rememberMe, b.Db.QueryStructRow(onedb.NewSqlQuery(b.RenewRememberMeQuery, selector), rememberMe)
}

func (b *BackendPostgres) AddUser(email, emailVerifyHash string) error {
	return b.Db.Execute(onedb.NewSqlQuery(b.AddUserQuery, email, emailVerifyHash))
}

func (b *BackendPostgres) VerifyEmail(emailVerifyHash string) (string, error) {
	var user *User
	err := b.Db.QueryStructRow(onedb.NewSqlQuery(b.VerifyEmailQuery, emailVerifyHash), user)
	if err != nil || user == nil {
		return "", errors.New("Unable to verify email: " + err.Error())
	}
	return user.PrimaryEmail, err
}

func (b *BackendPostgres) UpdateUser(session *UserLoginSession, fullname string, company string, pictureUrl string) error {
	return nil
}

func (b *BackendPostgres) CreateLogin(email, passwordHash string, fullName string, company string, pictureUrl string, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time) (*UserLoginSession, error) {
	return nil, nil
}

func (b *BackendPostgres) UpdateEmailAndInvalidateSessions(email string, password string, newEmail string) (*UserLoginSession, error) {
	return nil, nil
}

func (b *BackendPostgres) UpdatePasswordAndInvalidateSessions(email string, oldPassword string, newPassword string) (*UserLoginSession, error) {
	return nil, nil
}

func (b *BackendPostgres) InvalidateSession(sessionHash string) error {
	return nil
}

func (b *BackendPostgres) Close() error {
	return b.Db.Close()
}
