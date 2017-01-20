package main

import (
	"errors"
	"github.com/robarchibald/onedb"
)

type backendDbUser struct {
	Db onedb.DBer

	GetUserLoginQuery string
	AddUserQuery      string
	VerifyEmailQuery  string
	UpdateUserQuery   string
	CreateLoginQuery  string
}

func newBackendDbUser(server string, port int, username, password, database string, getUserLoginQuery, addUserQuery, verifyEmailQuery, updateUserQuery string) (userBackender, error) {
	db, err := onedb.NewPgx(server, uint16(port), username, password, database)
	if err != nil {
		return nil, err
	}
	return &backendDbUser{Db: db,
		GetUserLoginQuery: getUserLoginQuery,
		AddUserQuery:      addUserQuery,
		VerifyEmailQuery:  verifyEmailQuery,
		UpdateUserQuery:   updateUserQuery}, nil
}

func (u *backendDbUser) GetLogin(email, loginProvider string) (*userLogin, error) {
	var login *userLogin
	return login, u.Db.QueryStruct(onedb.NewSqlQuery(u.GetUserLoginQuery, email, loginProvider), login)
}

func (u *backendDbUser) AddUser(email string) error {
	return u.Db.Execute(onedb.NewSqlQuery(u.AddUserQuery, email))
}

func (u *backendDbUser) GetUser(email string) (*user, error) {
	var r *user
	err := u.Db.QueryStructRow(onedb.NewSqlQuery(u.VerifyEmailQuery, email), r)
	if err != nil || r == nil {
		return nil, errors.New("Unable to get user: " + err.Error())
	}
	return r, err
}

func (u *backendDbUser) UpdateUser(email, fullname string, company string, pictureURL string) error {
	return nil
}

func (u *backendDbUser) Close() error {
	return nil
}
