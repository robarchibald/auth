package main

import (
	"fmt"
)

type loginStorer interface {
	Login(email, password string, rememberMe bool) (*userLogin, error)

	CreateLogin(email, fullName, password string, mailQuota, fileQuota int) (*userLogin, error)
	UpdateEmail() error
	UpdatePassword() error
}

type loginStore struct {
	backend backender
	mailer  mailer
}

func newLoginStore(backend backender, mailer mailer) loginStorer {
	return &loginStore{backend, mailer}
}

func (s *loginStore) Login(email, password string, rememberMe bool) (*userLogin, error) {
	if !isValidEmail(email) {
		return nil, newAuthError("Please enter a valid email address.", nil)
	}
	if !isValidPassword(password) {
		return nil, newAuthError(passwordValidationMessage, nil)
	}

	// add in check for DDOS attack. Slow down or lock out checks for same account
	// or same IP with multiple failed attempts
	login, err := s.backend.GetLogin(email, loginProviderDefaultName)
	if err != nil {
		return nil, newLoggedError("Invalid username or password", err)
	}

	if err := cryptoHashEquals(password, login.ProviderKey); err != nil {
		return nil, newLoggedError("Invalid username or password +crypto"+login.ProviderKey, err)
	}
	return login, nil
}

/****************  TODO: send 0 for UID and GID numbers and empty quotas if mailQuota and fileQuota are 0 **********************/
func (s *loginStore) CreateLogin(email, fullName, password string, mailQuota, fileQuota int) (*userLogin, error) {
	passwordHash, err := cryptoHash(password)
	if err != nil {
		return nil, newLoggedError("Unable to create login", err)
	}

	uidNumber := 10000 // vmail user
	gidNumber := 10000 // vmail user
	homeDirectory := "/home"
	mQuota := fmt.Sprintf("%dGB", mailQuota)
	fQuota := fmt.Sprintf("%dGB", fileQuota)
	login, err := s.backend.CreateLogin(email, passwordHash, fullName, homeDirectory, uidNumber, gidNumber, mQuota, fQuota)
	if err != nil {
		return nil, newLoggedError("Unable to create login", err)
	}
	return login, err
}

func (s *loginStore) UpdateEmail() error { return nil }

func (s *loginStore) UpdatePassword() error {
	return nil
}

func isValidPassword(password string) bool {
	return len(password) >= 7 && len(password) <= 20
}
