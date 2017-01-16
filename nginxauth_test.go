package main

import (
	"testing"
)

func TestNewRestServer(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	_, err := newNginxAuth()
	if err != nil { // will connect to the db and LDAP servers specified in auth.conf
		t.Error("expected success", err)
	}
}

func TestNewEmailer(t *testing.T) {
	n := authConf{
		VerifyEmailTemplate:     "testTemplates/verifyEmail.html",
		VerifyEmailSubject:      "verifyEmailSubject",
		WelcomeTemplate:         "testTemplates/welcomeEmail.html",
		WelcomeSubject:          "welcomeSubject",
		NewLoginTemplate:        "testTemplates/newLogin.html",
		NewLoginSubject:         "newLoginSubject",
		LockedOutTemplate:       "testTemplates/lockedOut.html",
		LockedOutSubject:        "lockedOutSubject",
		EmailChangedTemplate:    "testTemplates/emailChanged.html",
		EmailChangedSubject:     "emailChangedSubject",
		PasswordChangedTemplate: "testTemplates/passwordChanged.html",
		PasswordChangedSubject:  "passwordChangedSubject",
	}
	n.NewEmailer()
}
