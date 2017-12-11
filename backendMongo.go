package auth

import (
	"time"

	"github.com/EndFirstCorp/onedb/mgo"
	"github.com/pkg/errors"
	"gopkg.in/mgo.v2/bson"
)

type backendMongo struct {
	m mgo.Sessioner
	c Crypter
}

type mongoUser struct {
	ID                bson.ObjectId `bson:"_id"               json:"id"`
	PrimaryEmail      string        `bson:"primaryEmail"      json:"primaryEmail"`
	SecondaryEmails   []email       `bson:"secondaryEmails"   json:"secondaryEmails"`
	FullName          string        `bson:"fullName"          json:"fullName"`
	PasswordHash      string        `bson:"passwordHash"      json:"passwordHash"`
	LockoutEndTimeUTC *time.Time    `bson:"lockoutEndTimeUTC" json:"lockoutEndTimeUTC"`
	AccessFailedCount int           `bson:"accessFailedCount" json:"accessFailedCount"`
}

type email struct {
	Address    string `bson:"address"    json:"address"`
	VerifyHash string `bson:"verifyHash" json:"verifyHash"`
	IsVerified bool   `bson:"isVerified" json:"isVerified"`
}

// NewBackendMongo creates a MongoDB-based Backender
func NewBackendMongo(url string, c Crypter) (Backender, error) {
	m, err := mgo.Dial(url)
	return &backendMongo{m, c}, err
}

func (b *backendMongo) AddUser(email string) (string, error) {
	u, err := b.getUser(email)
	if err == nil {
		return u.ID.Hex(), errors.New("user already exists")
	}

	m := b.m.Clone()
	id := bson.NewObjectId()
	return id.Hex(), m.DB("users").C("users").Insert(mongoUser{ID: id, PrimaryEmail: email})
}

func (b *backendMongo) getUser(email string) (*mongoUser, error) {
	u := &mongoUser{}
	m := b.m.Clone()
	return u, m.DB("users").C("users").Find(bson.M{"email": email}).One(u)
}

func (b *backendMongo) GetUser(email string) (*user, error) {
	u, err := b.getUser(email)
	if err != nil {
		return nil, err
	}
	return &user{UserID: u.ID.Hex(), FullName: u.FullName, PrimaryEmail: u.PrimaryEmail, AccessFailedCount: u.AccessFailedCount, LockoutEndTimeUTC: u.LockoutEndTimeUTC}, nil
}

func (b *backendMongo) UpdateUser(userID string, fullname string, company string, pictureURL string) error {
	m := b.m.Clone()
	return m.DB("users").C("users").UpdateId(bson.ObjectIdHex(userID), bson.M{"$set": bson.M{"fullName": fullname}})
}

func (b *backendMongo) Close() error {
	b.m.Close()
	return nil
}

func (b *backendMongo) Login(email, password string) (*UserLogin, error) {
	u, err := b.getUser(email)
	if err != nil {
		return nil, err
	}
	if err := b.c.HashEquals(password, u.PasswordHash); err != nil {
		return nil, err
	}
	return &UserLogin{UserID: u.ID.Hex(), FullName: u.FullName, Email: u.PrimaryEmail}, nil
}

func (b *backendMongo) GetLogin(email string) (*UserLogin, error) {
	u, err := b.getUser(email)
	if err != nil {
		return nil, err
	}
	return &UserLogin{UserID: u.ID.Hex(), FullName: u.FullName, Email: u.PrimaryEmail}, nil
}

func (b *backendMongo) CreateLogin(userID, email, password, fullName string) (*UserLogin, error) {
	m := b.m.Clone()
	passwordHash, err := b.c.Hash(password)
	if err != nil {
		return nil, err
	}
	return &UserLogin{UserID: userID, FullName: fullName, Email: email},
		m.DB("users").C("users").UpdateId(bson.ObjectIdHex(userID), bson.M{"$set": bson.M{"email": email, "passwordHash": passwordHash, "fullName": fullName}})
}

func (b *backendMongo) CreateSecondaryEmail(userID, secondaryEmail string) error {
	return nil
}
func (b *backendMongo) SetPrimaryEmail(userID, secondaryEmail string) error {
	return nil
}
func (b *backendMongo) UpdatePassword(userID, newPassword string) error {
	return nil
}
func (b *backendMongo) CreateEmailSession(email, emailVerifyHash, destinationURL string) error {
	return nil
}
func (b *backendMongo) GetEmailSession(verifyHash string) (*emailSession, error) {
	return nil, nil
}
func (b *backendMongo) UpdateEmailSession(verifyHash string, userID, email, destinationURL string) error {
	return nil
}
func (b *backendMongo) DeleteEmailSession(verifyHash string) error {
	return nil
}
func (b *backendMongo) CreateSession(userID, email, fullname, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*LoginSession, *rememberMeSession, error) {
	return nil, nil, nil
}
func (b *backendMongo) GetSession(sessionHash string) (*LoginSession, error) {
	return nil, nil
}
func (b *backendMongo) RenewSession(sessionHash string, renewTimeUTC time.Time) (*LoginSession, error) {
	return nil, nil
}
func (b *backendMongo) InvalidateSession(sessionHash string) error {
	return nil
}
func (b *backendMongo) InvalidateSessions(email string) error {
	return nil
}
func (b *backendMongo) GetRememberMe(selector string) (*rememberMeSession, error) {
	return nil, nil
}
func (b *backendMongo) RenewRememberMe(selector string, renewTimeUTC time.Time) (*rememberMeSession, error) {
	return nil, nil
}
func (b *backendMongo) InvalidateRememberMe(selector string) error {
	return nil
}
