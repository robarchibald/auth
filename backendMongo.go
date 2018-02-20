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
func NewBackendMongo(m mgo.Sessioner, c Crypter) Backender {
	return &backendMongo{m, c}
}

func (b *backendMongo) AddUser(email string) (string, error) {
	u, err := b.getUser(email)
	if err == nil {
		return u.ID.Hex(), errors.New("user already exists")
	}

	id := bson.NewObjectId()
	return id.Hex(), b.users().Insert(mongoUser{ID: id, PrimaryEmail: email})
}

func (b *backendMongo) getUser(email string) (*mongoUser, error) {
	u := &mongoUser{}
	return u, b.users().Find(bson.M{"primaryEmail": email}).One(u)
}

func (b *backendMongo) GetUser(email string) (*user, error) {
	u, err := b.getUser(email)
	if err != nil {
		return nil, err
	}
	return &user{UserID: u.ID.Hex(), FullName: u.FullName, PrimaryEmail: u.PrimaryEmail, AccessFailedCount: u.AccessFailedCount, LockoutEndTimeUTC: u.LockoutEndTimeUTC}, nil
}

func (b *backendMongo) UpdateUser(userID string, fullname string, company string, pictureURL string) error {
	return b.users().UpdateId(bson.ObjectIdHex(userID), bson.M{"$set": bson.M{"fullName": fullname}})
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
	passwordHash, err := b.c.Hash(password)
	if err != nil {
		return nil, err
	}
	return &UserLogin{UserID: userID, FullName: fullName, Email: email},
		b.users().UpdateId(bson.ObjectIdHex(userID), bson.M{"$set": bson.M{"passwordHash": passwordHash}})
}

func (b *backendMongo) CreateSecondaryEmail(userID, secondaryEmail string) error {
	return nil
}
func (b *backendMongo) SetPrimaryEmail(userID, secondaryEmail string) error {
	return nil
}
func (b *backendMongo) UpdatePassword(userID, newPassword string) error {
	passwordHash, err := b.c.Hash(newPassword)
	if err != nil {
		return err
	}
	return b.users().UpdateId(bson.ObjectIdHex(userID), bson.M{"$set": bson.M{"passwordHash": passwordHash}})
}
func (b *backendMongo) CreateEmailSession(email, emailVerifyHash, csrfToken, destinationURL string) error {
	s := b.emailSessions()
	c, _ := s.FindId(emailVerifyHash).Count()
	if c > 0 {
		return errors.New("invalid emailVerifyHash")
	}
	return s.Insert(&emailSession{"", email, emailVerifyHash, csrfToken, destinationURL})
}

func (b *backendMongo) GetEmailSession(verifyHash string) (*emailSession, error) {
	session := &emailSession{}
	return session, b.emailSessions().FindId(verifyHash).One(session)
}

func (b *backendMongo) UpdateEmailSession(verifyHash, userID string) error {
	return b.emailSessions().UpdateId(verifyHash, bson.M{"$set": bson.M{"userID": userID}})
}
func (b *backendMongo) DeleteEmailSession(verifyHash string) error {
	return b.emailSessions().RemoveId(verifyHash)
}
func (b *backendMongo) CreateSession(userID, email, fullname, sessionHash, csrfToken string, renewTimeUTC, expireTimeUTC time.Time) (*LoginSession, error) {
	s := LoginSession{userID, email, fullname, sessionHash, csrfToken, renewTimeUTC, expireTimeUTC}
	return &s, b.loginSessions().Insert(s)
}

func (b *backendMongo) CreateRememberMe(userID, email, selector, tokenHash string, renewTimeUTC, expireTimeUTC time.Time) (*rememberMeSession, error) {
	r := rememberMeSession{userID, email, selector, tokenHash, renewTimeUTC, expireTimeUTC}
	return &r, b.rememberMeSessions().Insert(&r)
}

func (b *backendMongo) GetSession(sessionHash string) (*LoginSession, error) {
	session := &LoginSession{}
	return session, b.loginSessions().FindId(sessionHash).One(session)
}

func (b *backendMongo) UpdateSession(sessionHash string, renewTimeUTC, expireTimeUTC time.Time) error {
	return b.loginSessions().UpdateId(sessionHash, bson.M{"$set": bson.M{"expireTimeUTC": expireTimeUTC, "renewTimeUTC": renewTimeUTC}})
}

func (b *backendMongo) DeleteSession(sessionHash string) error {
	return b.loginSessions().RemoveId(sessionHash)
}
func (b *backendMongo) InvalidateSessions(email string) error {
	return nil
}
func (b *backendMongo) GetRememberMe(selector string) (*rememberMeSession, error) {
	rememberMe := &rememberMeSession{}
	return rememberMe, b.rememberMeSessions().FindId(selector).One(rememberMe)
}
func (b *backendMongo) UpdateRememberMe(selector string, renewTimeUTC time.Time) error {
	return b.rememberMeSessions().UpdateId(selector, bson.M{"$set": bson.M{"renewTimeUTC": renewTimeUTC}})
}
func (b *backendMongo) DeleteRememberMe(selector string) error {
	return b.rememberMeSessions().RemoveId(selector)
}

func (b *backendMongo) users() mgo.Collectioner {
	return b.m.Clone().DB("users").C("users")
}
func (b *backendMongo) emailSessions() mgo.Collectioner {
	return b.m.Clone().DB("users").C("emailSessions")
}
func (b *backendMongo) loginSessions() mgo.Collectioner {
	return b.m.Clone().DB("users").C("loginSessions")
}
func (b *backendMongo) rememberMeSessions() mgo.Collectioner {
	return b.m.Clone().DB("users").C("rememberMeSessions")
}
