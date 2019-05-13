// This file taken with some modification from authboss
// github.com/go-authboss
package auth

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
)

// CookieStorer interface provides the necessary methods for handling cookies
type CookieStorer interface {
	Get(w http.ResponseWriter, r *http.Request, key string, result interface{}) error
	Put(w http.ResponseWriter, r *http.Request, key string, value interface{}) error
	PutWithExpire(w http.ResponseWriter, r *http.Request, key string, expireMins int, value interface{}) error
	PutUnsecured(w http.ResponseWriter, r *http.Request, key string, value interface{}) error
	Delete(w http.ResponseWriter, key string)
}

type cookieStore struct {
	s      *securecookie.SecureCookie
	domain string
}

func newCookieStore(cookieKey []byte, domain string) CookieStorer {
	return &cookieStore{securecookie.New(cookieKey, nil), domain}
}

func (s *cookieStore) Encode(key string, value interface{}) (string, error) {
	return s.s.Encode(key, value)
}

func (s *cookieStore) Decode(key string, value string, result interface{}) error {
	return s.s.Decode(key, value, result)
}

func (s *cookieStore) Get(w http.ResponseWriter, r *http.Request, key string, result interface{}) error {
	cookie, err := r.Cookie(key)
	if err != nil {
		return err
	}

	err = s.Decode(key, cookie.Value, result)
	if err != nil {
		s.Delete(w, key) // problem decoding the cookie, so delete
		return err
	}
	return nil
}

func (s *cookieStore) PutUnsecured(w http.ResponseWriter, r *http.Request, key string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	s.putCookie(w, r, key, string(data), 60*24*30) // default to 30 day expiration
	return nil
}

func (s *cookieStore) Put(w http.ResponseWriter, r *http.Request, key string, value interface{}) error {
	return s.PutWithExpire(w, r, key, 60*24*30, value) // default to 30 day expiration
}

func (s *cookieStore) PutWithExpire(w http.ResponseWriter, r *http.Request, key string, expireMins int, value interface{}) error {
	encoded, err := s.Encode(key, value)
	if err != nil {
		return err
	}
	s.putCookie(w, r, key, encoded, expireMins)
	return nil
}

func (s *cookieStore) putCookie(w http.ResponseWriter, r *http.Request, key, value string, expireMins int) {
	secureOnly := strings.HasPrefix(r.Referer(), "https") // proxy to back-end so if referer is secure connection, we can use secureOnly cookies
	http.SetCookie(w, newCookie(key, value, s.domain, secureOnly, expireMins))
}

func (s *cookieStore) Delete(w http.ResponseWriter, key string) {
	cookie := &http.Cookie{
		MaxAge: -1,
		Name:   key,
		Path:   "/",
	}
	http.SetCookie(w, cookie)
}

func newCookie(name string, value string, domain string, secureOnly bool, expireMins int) *http.Cookie {
	return &http.Cookie{
		Expires:  time.Now().UTC().Add(time.Duration(expireMins) * time.Minute),
		Name:     name,
		Value:    value,
		Domain:   domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   secureOnly,
		MaxAge:   expireMins * 60, // time in seconds
	}
}
