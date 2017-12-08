package auth

import (
	"github.com/EndFirstCorp/onedb/mgo"
	"gopkg.in/mgo.v2/bson"
)

type backendMongoUser struct {
	m mgo.Sessioner
}

// NewBackendMongoUser creates a MongoDB-based UserBackender
func NewBackendMongoUser(url string) (UserBackender, error) {
	m, err := mgo.Dial(url)
	return &backendMongoUser{m}, err
}

func (u *backendMongoUser) AddUser(email string) (string, error) {
	m := u.m.Clone()
	id := bson.NewObjectId()
	return string(id), m.DB("users").C("user").Insert(user{UserID: string(id), PrimaryEmail: email})
}

func (u *backendMongoUser) GetUser(email string) (*user, error) {
	r := &user{}
	m := u.m.Clone()
	return r, m.DB("users").C("user").Find(bson.M{"email": email}).One(r)
}

func (u *backendMongoUser) UpdateUser(userID string, fullname string, company string, pictureURL string) error {
	m := u.m.Clone()
	return m.DB("users").C("user").UpdateId(userID, bson.M{})
}

func (u *backendMongoUser) Close() error {
	u.m.Close()
	return nil
}
