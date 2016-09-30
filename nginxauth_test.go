package main

import (
	"testing"
)

func TestNewRestServer(t *testing.T) {
	_, err := newNginxAuth()
	if err != nil { // will connect to the docker Postgres db specified in auth.conf
		t.Error("expected success")
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
