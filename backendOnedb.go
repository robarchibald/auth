package main

import (
	"errors"
	"github.com/robarchibald/onedb"
	"time"
)

type BackendOnedb struct {
	BackendQuerier
	Db onedb.DBer

	GetUserLoginQuery                        string
	GetSessionQuery                          string
	NewLoginSessionQuery                     string
	NewRememberMeQuery                       string
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

func (b *BackendOnedb) GetUserLogin(email, loginProvider string) (*UserLogin, error) {
	var login *UserLogin
	return login, b.Db.QueryStruct(onedb.NewSqlQuery(b.GetUserLoginQuery, email, loginProvider), login)
}
func (b *BackendOnedb) GetSession(sessionHash string) (*UserLoginSession, error) {
	var session *UserLoginSession
	return session, b.Db.QueryStructRow(onedb.NewSqlQuery(b.GetSessionQuery, sessionHash), session)
}

func (m *BackendOnedb) NewLoginSession(loginId, userId int, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*UserLoginSession, *UserLoginRememberMe, error) {
	var session *UserLoginSession
	var remember *UserLoginRememberMe
	err := m.Db.QueryStructRow(onedb.NewSqlQuery(m.NewLoginSessionQuery, loginId, userId, sessionHash, sessionRenewTimeUTC, sessionExpireTimeUTC), session)
	if err != nil {
		return nil, nil, err
	}
	err = m.Db.QueryStructRow(onedb.NewSqlQuery(m.NewRememberMeQuery, loginId, userId, sessionHash, sessionRenewTimeUTC, sessionExpireTimeUTC), rememberMe)
	if err != nil {
		return nil, nil, err
	}
	return session, remember, nil
}

func (b *BackendOnedb) RenewSession(sessionHash string, renewTimeUTC time.Time) (*UserLoginSession, error) {
	var session *UserLoginSession
	return session, b.Db.QueryStructRow(onedb.NewSqlQuery(b.RenewSessionQuery, sessionHash), session)
}

func (b *BackendOnedb) GetRememberMe(selector string) (*UserLoginRememberMe, error) {
	var rememberMe *UserLoginRememberMe
	return rememberMe, b.Db.QueryStructRow(onedb.NewSqlQuery(b.GetRememberMeQuery, selector), rememberMe)
}

func (b *BackendOnedb) RenewRememberMe(selector string, renewTimeUTC time.Time) (*UserLoginRememberMe, error) {
	var rememberMe *UserLoginRememberMe
	return rememberMe, b.Db.QueryStructRow(onedb.NewSqlQuery(b.RenewRememberMeQuery, selector), rememberMe)
}

func (b *BackendOnedb) AddUser(email, emailVerifyHash string) error {
	return b.Db.Execute(onedb.NewSqlQuery(b.AddUserQuery, email, emailVerifyHash))
}

func (b *BackendOnedb) VerifyEmail(emailVerifyHash string) (string, error) {
	var user *User
	err := b.Db.QueryStructRow(onedb.NewSqlQuery(b.VerifyEmailQuery, emailVerifyHash), user)
	if err != nil || user == nil {
		return "", errors.New("Unable to verify email: " + err.Error())
	}
	return user.PrimaryEmail, err
}

func (b *BackendOnedb) UpdateUser(session *UserLoginSession, fullname string, company string, pictureUrl string) error {
	return nil
}

func (b *BackendOnedb) CreateLogin(email, passwordHash string, fullName string, company string, pictureUrl string, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time) (*UserLoginSession, error) {
	return nil, nil
}

func (b *BackendOnedb) UpdateEmailAndInvalidateSessions(email string, password string, newEmail string) (*UserLoginSession, error) {
	return nil, nil
}

func (b *BackendOnedb) UpdatePasswordAndInvalidateSessions(email string, oldPassword string, newPassword string) (*UserLoginSession, error) {
	return nil, nil
}

func (b *BackendOnedb) InvalidateSession(sessionHash string) error {
	return nil
}

func (b *BackendOnedb) Close() error {
	return b.Db.Close()
}
