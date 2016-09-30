// This file taken with some modification from authboss
// github.com/go-authboss
package main

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

var cookieStore *securecookie.SecureCookie

type CookieStorer interface {
	Get(key string, result interface{}) error
	Put(key string, value interface{}) error
	PutWithExpire(key string, expireMins int, value interface{}) error
	Delete(key string)
}

type CookieStore struct {
	w          http.ResponseWriter
	r          *http.Request
	secureOnly bool
}

func NewCookieStore(w http.ResponseWriter, r *http.Request, cookieKey []byte, secureOnly bool) *CookieStore {
	if cookieStore == nil {
		cookieStore = securecookie.New(cookieKey, nil)
	}
	return &CookieStore{w, r, secureOnly}
}

func (s *CookieStore) Encode(key string, value interface{}) (string, error) {
	return cookieStore.Encode(key, value)
}

func (s *CookieStore) Decode(key string, value string, result interface{}) error {
	return cookieStore.Decode(key, value, result)
}

func (s *CookieStore) Get(key string, result interface{}) error {
	cookie, err := s.r.Cookie(key)
	if err != nil {
		return err
	}

	err = s.Decode(key, cookie.Value, result)
	if err != nil {
		s.Delete(key) // problem decoding the cookie, so delete
		return err
	}
	return nil
}

func (s *CookieStore) Put(key string, value interface{}) error {
	return s.PutWithExpire(key, 60*24*30, value) // default to 30 day expiration
}

func (s *CookieStore) PutWithExpire(key string, expireMins int, value interface{}) error {
	encoded, err := s.Encode(key, value)
	if err != nil {
		return err
	}

	http.SetCookie(s.w, newCookie(key, encoded, s.secureOnly, expireMins))
	return nil
}

func (s *CookieStore) Delete(key string) {
	cookie := &http.Cookie{
		MaxAge: -1,
		Name:   key,
		Path:   "/",
	}
	http.SetCookie(s.w, cookie)
}

func newCookie(name string, value string, secureOnly bool, expireMins int) *http.Cookie {
	return &http.Cookie{
		Expires:  time.Now().UTC().Add(time.Duration(expireMins) * time.Minute),
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secureOnly,
		MaxAge:   expireMins,
	}
}
