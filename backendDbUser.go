package main

import (
	"github.com/pkg/errors"
	"github.com/robarchibald/onedb"
)

type backendDbUser struct {
	Db onedb.DBer

	AddUserQuery     string
	GetUserQuery     string
	UpdateUserQuery  string
	CreateLoginQuery string
}

func newBackendDbUser(server string, port int, username, password, database string, addUserQuery, getUserQuery, updateUserQuery string) (userBackender, error) {
	db, err := onedb.NewPgx(server, uint16(port), username, password, database)
	if err != nil {
		return nil, err
	}
	return &backendDbUser{Db: db,
		GetUserQuery:    getUserQuery,
		AddUserQuery:    addUserQuery,
		UpdateUserQuery: updateUserQuery}, nil
}

func (u *backendDbUser) AddUser(email string) (int, error) {
	var userID int32 = -1
	return int(userID), u.Db.QueryValues(onedb.NewSqlQuery(u.AddUserQuery, email), &userID)
}

func (u *backendDbUser) GetUser(email string) (*user, error) {
	r := &user{}
	err := u.Db.QueryStructRow(onedb.NewSqlQuery(u.GetUserQuery, email), r)
	if err != nil {
		return nil, errors.New("Unable to get user: " + err.Error())
	}
	return r, err
}

func (u *backendDbUser) UpdateUser(userID int, fullname string, company string, pictureURL string) error {
	return u.Db.Execute(onedb.NewSqlQuery(u.UpdateUserQuery, userID, fullname))
}

func (u *backendDbUser) Close() error {
	return nil
}
