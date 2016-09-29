// This file taken with some modification from authboss
// github.com/go-authboss
package nginxauth

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

var cookieStore *securecookie.SecureCookie

type CookieStorer interface {
	Get(key string, result interface{}) error
	Put(key string, value interface{}) error
	PutWithExpire(key string, value interface{}, expireMins int) error
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
	return s.PutWithExpire(key, value, 60*24*30) // default to 30 day expiration
}

func (s *CookieStore) PutWithExpire(key string, value interface{}, expireMins int) error {
	encoded, err := s.Encode(key, value)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Expires:  time.Now().UTC().Add(time.Duration(expireMins) * time.Minute),
		Name:     key,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureOnly,
		MaxAge:   expireMins,
	}
	http.SetCookie(s.w, cookie)
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
