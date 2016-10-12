package main

import (
	"encoding/json"
	"fmt"
	"github.com/garyburd/redigo/redis"
	"time"
)

var redisCreate redisCreator = &redisRealCreator{}

type redisCreator interface {
	newConnPool(server string, port int, password string, maxIdle, maxConnections int) redisBackender
}

type redisRealCreator struct{}

func (c *redisRealCreator) newConnPool(server string, port int, password string, maxIdle, maxConnections int) redisBackender {
	return &redis.Pool{
		MaxIdle:   maxIdle,
		MaxActive: maxConnections,
		Dial: func() (redis.Conn, error) {
			if password != "" {
				return redis.Dial("tcp", fmt.Sprintf("%s:%d", server, port), redis.DialPassword(password))
			}
			return redis.Dial("tcp", fmt.Sprintf("%s:%d", server, port))
		},
	}
}

type redisBackender interface {
	Close() error
	Get() redis.Conn
}

type SessionBackender interface {
	CreateSession(loginID, userID int, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time, rememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*UserLoginSession, *UserLoginRememberMe, error)
	GetSession(sessionHash string) (*UserLoginSession, error)
	RenewSession(sessionHash string, renewTimeUTC time.Time) (*UserLoginSession, error)
	InvalidateSession(sessionHash string) error

	GetRememberMe(selector string) (*UserLoginRememberMe, error)
	RenewRememberMe(selector string, renewTimeUTC time.Time) (*UserLoginRememberMe, error)
	InvalidateRememberMe(selector string) error

	Close() error
}

type RedisSessionBackend struct {
	pool redisBackender
}

func NewRedis(server string, port int, password string, maxIdle, maxConnections int) redisBackender {
	return redisCreate.newConnPool(server, port, password, maxIdle, maxConnections)
}

func NewRedisSessionBackend(server string, port int, password string, maxIdle, maxConnections int) SessionBackender {
	r := NewRedis(server, port, password, maxIdle, maxConnections)
	return &RedisSessionBackend{pool: r}
}

func (r *RedisSessionBackend) CreateSession(loginID, userID int, sessionHash string, sessionRenewTimeUTC, sessionExpireTimeUTC time.Time,
	includeRememberMe bool, rememberMeSelector, rememberMeTokenHash string, rememberMeRenewTimeUTC, rememberMeExpireTimeUTC time.Time) (*UserLoginSession, *UserLoginRememberMe, error) {
	session := UserLoginSession{LoginID: loginID, UserID: userID, SessionHash: sessionHash, RenewTimeUTC: sessionRenewTimeUTC, ExpireTimeUTC: sessionExpireTimeUTC}
	err := r.save("session/"+sessionHash, &session)
	if err != nil {
		return nil, nil, err
	}

	var rememberMe UserLoginRememberMe
	if includeRememberMe {
		rememberMe = UserLoginRememberMe{LoginID: loginID, Selector: rememberMeSelector, TokenHash: rememberMeTokenHash, RenewTimeUTC: rememberMeRenewTimeUTC, ExpireTimeUTC: rememberMeExpireTimeUTC}
		err = r.save("rememberMe/"+rememberMeSelector, &rememberMe)
		if err != nil {
			return nil, nil, err
		}
	}

	return &session, &rememberMe, nil
}

func (r *RedisSessionBackend) GetSession(sessionHash string) (*UserLoginSession, error) {
	var session *UserLoginSession
	return session, r.get("session"+sessionHash, session)
}

func (r *RedisSessionBackend) RenewSession(sessionHash string, renewTimeUTC time.Time) (*UserLoginSession, error) {
	var session *UserLoginSession
	key := "session/" + sessionHash
	err := r.get(key, session)
	if err != nil {
		return nil, err
	}
	session.RenewTimeUTC = renewTimeUTC
	return session, r.save(key, session)
}

func (r *RedisSessionBackend) InvalidateSession(sessionHash string) error {
	return r.del("session/" + sessionHash)
}

func (r *RedisSessionBackend) GetRememberMe(selector string) (*UserLoginRememberMe, error) {
	var rememberMe *UserLoginRememberMe
	return rememberMe, r.get("rememberMe/"+selector, rememberMe)
}

func (r *RedisSessionBackend) RenewRememberMe(selector string, renewTimeUTC time.Time) (*UserLoginRememberMe, error) {
	var rememberMe *UserLoginRememberMe
	err := r.get("rememberMe/"+selector, rememberMe)
	if err != nil {
		return nil, errRememberMeNotFound
	} else if rememberMe.ExpireTimeUTC.Before(time.Now().UTC()) {
		return nil, errRememberMeExpired
	} else if rememberMe.ExpireTimeUTC.Before(renewTimeUTC) || renewTimeUTC.Before(time.Now().UTC()) {
		return nil, errInvalidRenewTimeUTC
	}
	rememberMe.RenewTimeUTC = renewTimeUTC
	return rememberMe, nil
}

func (r *RedisSessionBackend) InvalidateRememberMe(selector string) error {
	return r.del("rememberMe/" + selector)
}

func (r *RedisSessionBackend) Close() error {
	return r.pool.Close()
}

func (r *RedisSessionBackend) del(key string) error {
	c := r.pool.Get()
	defer c.Close()

	if _, err := c.Do("DEL", key); err != nil {
		return err
	}
	return nil
}

func (r *RedisSessionBackend) save(key, value interface{}) error {
	json, err := json.Marshal(value)
	if err != nil {
		return err
	}

	c := r.pool.Get()
	defer c.Close()

	if _, err := c.Do("SET", key, string(json)); err != nil {
		return err
	}
	return nil
}

func (r *RedisSessionBackend) get(key string, value interface{}) error {
	c := r.pool.Get()
	defer c.Close()

	data, err := redis.Bytes(c.Do("GET", key))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}
