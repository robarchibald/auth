package auth

import (
	"time"

	"github.com/EndFirstCorp/onedb/mgo"
	"gopkg.in/mgo.v2/bson"
)

type backendMongo struct {
	m mgo.Sessioner
}

// NewBackendMongo creates a MongoDB-based Backender
func NewBackendMongo(url string) (Backender, error) {
	m, err := mgo.Dial(url)
	return &backendMongo{m}, err
}

func (b *backendMongo) AddUser(email string) (string, error) {
	m := b.m.Clone()
	id := bson.NewObjectId()
	return string(id), m.DB("users").C("user").Insert(user{UserID: string(id), PrimaryEmail: email})
}

func (b *backendMongo) GetUser(email string) (*user, error) {
	r := &user{}
	m := b.m.Clone()
	return r, m.DB("users").C("user").Find(bson.M{"primaryEmail": email}).One(r)
}

func (b *backendMongo) UpdateUser(userID string, fullname string, company string, pictureURL string) error {
	m := b.m.Clone()
	return m.DB("users").C("user").UpdateId(userID, bson.M{"$set": bson.M{"fullName": fullname}})
}

func (b *backendMongo) Close() error {
	b.m.Close()
	return nil
}

func (b *backendMongo) Login(email, password string) (*UserLogin, error) {
	//m := b.m.Clone()
	return nil, nil
}

func (b *backendMongo) GetLogin(email string) (*UserLogin, error) {
	//m := b.m.Clone()
	return nil, nil
}

func (b *backendMongo) CreateLogin(userID, email, password, fullName string) (*UserLogin, error) {
	//m := b.m.Clone()
	return nil, nil
}

func (b *backendMongo) UpdateEmail(email string, password string, newEmail string) (*LoginSession, error) {
	//m := b.m.Clone()
	return nil, nil
}

func (b *backendMongo) UpdatePassword(email string, oldPassword string, newPassword string) (*LoginSession, error) {
	//m := b.m.Clone()
	return nil, nil
}

func (b *backendMongo) CreateEmailSession(email, emailVerifyHash, destinationURL string) error {
	//m := b.m.Clone()
	return nil
}
func (b *backendMongo) GetEmailSession(verifyHash string) (*emailSession, error) {
	//m := b.m.Clone()
	return nil, nil
}
func (b *backendMongo) UpdateEmailSession(verifyHash string, userID, email, destinationURL string) error {
	//m := b.m.Clone()
	return nil
}
func (b *backendMongo) DeleteEmailSession(verifyHash string) error {
	//m := b.m.Clone()
	return nil
}

func (b *backendMongo) CreateSession(userID, email, fullname, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*LoginSession, *rememberMeSession, error) {
	//m := b.m.Clone()
	return nil, nil, nil
}
func (b *backendMongo) GetSession(sessionHash string) (*LoginSession, error) {
	//m := b.m.Clone()
	return nil, nil
}
func (b *backendMongo) RenewSession(sessionHash string, renewTimeUTC time.Time) (*LoginSession, error) {
	//m := b.m.Clone()
	return nil, nil

}
func (b *backendMongo) InvalidateSession(sessionHash string) error {
	//m := b.m.Clone()
	return nil
}
func (b *backendMongo) InvalidateSessions(email string) error {
	//m := b.m.Clone()
	return nil
}

func (b *backendMongo) GetRememberMe(selector string) (*rememberMeSession, error) {
	//m := b.m.Clone()
	return nil, nil
}
func (b *backendMongo) RenewRememberMe(selector string, renewTimeUTC time.Time) (*rememberMeSession, error) {
	//m := b.m.Clone()
	return nil, nil
}
func (b *backendMongo) InvalidateRememberMe(selector string) error {
	//m := b.m.Clone()
	return nil
}
