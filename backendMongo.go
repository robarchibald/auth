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
	ID                bson.ObjectId          `bson:"_id"               json:"id"`
	PrimaryEmail      string                 `bson:"primaryEmail"      json:"primaryEmail"`
	SecondaryEmails   []email                `bson:"secondaryEmails"   json:"secondaryEmails"`
	PasswordHash      string                 `bson:"passwordHash"      json:"passwordHash"`
	Info              map[string]interface{} `bson:"info"              json:"info"`
	LockoutEndTimeUTC *time.Time             `bson:"lockoutEndTimeUTC" json:"lockoutEndTimeUTC"`
	AccessFailedCount int                    `bson:"accessFailedCount" json:"accessFailedCount"`
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

func (b *backendMongo) Clone() Backender {
	return &backendMongo{b.m.Clone(), b.c}
}

func (b *backendMongo) AddUser(email string, info map[string]interface{}) (string, error) {
	u, err := b.getUser(email)
	if err == nil {
		return u.ID.Hex(), errors.New("user already exists")
	}

	id := bson.NewObjectId()
	return id.Hex(), b.users().Insert(mongoUser{ID: id, PrimaryEmail: email, Info: info})
}

func (b *backendMongo) AddUserFull(email, password string, info map[string]interface{}) (*User, error) {
	passwordHash, err := b.c.Hash(password)
	if err != nil {
		return nil, err
	}
	_, err = b.getUser(email)
	if err == nil {
		return nil, errors.New("user already exists")
	}

	id := bson.NewObjectId()
	return &User{id.Hex(), email, info}, b.users().Insert(mongoUser{ID: id, PrimaryEmail: email, PasswordHash: passwordHash, Info: info})
}

func (b *backendMongo) getUser(email string) (*mongoUser, error) {
	u := &mongoUser{}
	return u, b.users().Find(bson.M{"primaryEmail": email}).One(u)
}

func (b *backendMongo) GetUser(email string) (*User, error) {
	u, err := b.getUser(email)
	if err != nil {
		return nil, err
	}
	return &User{u.ID.Hex(), u.PrimaryEmail, u.Info}, nil
}

func (b *backendMongo) UpdateUser(userID, password string, info map[string]interface{}) error {
	passwordHash, err := b.c.Hash(password)
	if err != nil {
		return err
	}
	set := bson.M{"passwordHash": passwordHash, "info": info}
	return b.users().UpdateId(bson.ObjectIdHex(userID), bson.M{"$set": set})
}

func (b *backendMongo) UpdatePassword(userID, password string) error {
	passwordHash, err := b.c.Hash(password)
	if err != nil {
		return err
	}
	return b.users().UpdateId(bson.ObjectIdHex(userID), bson.M{"$set": bson.M{"passwordHash": passwordHash}})
}

func (b *backendMongo) UpdateInfo(userID string, info map[string]interface{}) error {
	var set bson.M
	for key := range info {
		set["info."+key] = info[key]
	}
	return b.users().UpdateId(bson.ObjectIdHex(userID), bson.M{"$set": set})
}

func (b *backendMongo) Close() error {
	b.m.Close()
	return nil
}

func (b *backendMongo) LoginAndGetUser(email, password string) (*User, error) {
	u, err := b.getUser(email)
	if err != nil {
		return nil, err
	}
	if err := b.c.HashEquals(password, u.PasswordHash); err != nil {
		return nil, err
	}
	return &User{u.ID.Hex(), u.PrimaryEmail, u.Info}, nil
}

func (b *backendMongo) Login(email, password string) error {
	_, err := b.LoginAndGetUser(email, password)
	return err
}

func (b *backendMongo) AddSecondaryEmail(userID, secondaryEmail string) error {
	return nil
}

func (b *backendMongo) UpdatePrimaryEmail(userID, secondaryEmail string) error {
	return nil
}

func (b *backendMongo) CreateEmailSession(email string, info map[string]interface{}, emailVerifyHash, csrfToken string) error {
	s := b.emailSessions()
	c, _ := s.FindId(emailVerifyHash).Count()
	if c > 0 {
		return errors.New("invalid emailVerifyHash")
	}
	return s.Insert(&emailSession{"", email, info, emailVerifyHash, csrfToken})
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
func (b *backendMongo) CreateSession(userID, email string, info map[string]interface{}, sessionHash, csrfToken string, renewTimeUTC, expireTimeUTC time.Time) (*LoginSession, error) {
	s := LoginSession{userID, email, info, sessionHash, csrfToken, renewTimeUTC, expireTimeUTC}
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
	return b.m.DB("users").C("users")
}
func (b *backendMongo) emailSessions() mgo.Collectioner {
	return b.m.DB("users").C("emailSessions")
}
func (b *backendMongo) loginSessions() mgo.Collectioner {
	return b.m.DB("users").C("loginSessions")
}
func (b *backendMongo) rememberMeSessions() mgo.Collectioner {
	return b.m.DB("users").C("rememberMeSessions")
}
