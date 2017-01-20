package main

import (
	"bytes"
	"html/template"
	"path/filepath"

	"gopkg.in/gomail.v2"
)

type mailer interface {
	SendWelcome(to string, data interface{}) error
	SendVerify(to string, data interface{}) error
	SendNewLogin(to string, data interface{}) error
	SendLockedOut(to string, data interface{}) error
	SendEmailChanged(to string, data interface{}) error
	SendPasswordChanged(to string, data interface{}) error
}

type sender interface {
	Send(to, subject, body string) error
}

type emailer struct {
	templateCache *template.Template
	sender        sender

	VerifyEmailTemplate     string
	VerifyEmailSubject      string
	WelcomeTemplate         string
	WelcomeSubject          string
	NewLoginTemplate        string
	NewLoginSubject         string
	LockedOutTemplate       string
	LockedOutSubject        string
	EmailChangedTemplate    string
	EmailChangedSubject     string
	PasswordChangedTemplate string
	PasswordChangedSubject  string
}

type smtpSender struct {
	SMTPServer           string
	SMTPPort             int
	SMTPFromEmail        string
	SMTPPassword         string
	EmailFromDisplayName string
}

func (s *smtpSender) Send(to, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", m.FormatAddress(s.SMTPFromEmail, s.EmailFromDisplayName))
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewPlainDialer(s.SMTPServer, s.SMTPPort, s.SMTPFromEmail, s.SMTPPassword)

	if err := d.DialAndSend(m); err != nil {
		return err
	}
	return nil
}

func (e *emailer) SendVerify(to string, data interface{}) error {
	return e.send(to, e.VerifyEmailSubject, e.VerifyEmailTemplate, data)
}

func (e *emailer) SendWelcome(to string, data interface{}) error {
	return e.send(to, e.WelcomeSubject, e.WelcomeTemplate, data)
}

func (e *emailer) SendNewLogin(to string, data interface{}) error {
	return e.send(to, e.NewLoginSubject, e.NewLoginTemplate, data)
}

func (e *emailer) SendLockedOut(to string, data interface{}) error {
	return e.send(to, e.LockedOutSubject, e.LockedOutTemplate, data)
}

func (e *emailer) SendEmailChanged(to string, data interface{}) error {
	return e.send(to, e.EmailChangedSubject, e.EmailChangedTemplate, data)
}

func (e *emailer) SendPasswordChanged(to string, data interface{}) error {
	return e.send(to, e.PasswordChangedSubject, e.PasswordChangedTemplate, data)
}

func (e *emailer) send(to string, subject string, emailTemplate string, data interface{}) error {
	body, err := e.renderHTMLBody(emailTemplate, data)
	if err != nil {
		return err
	}

	return e.sender.Send(to, subject, body)
}

func (e *emailer) renderHTMLBody(path string, data interface{}) (string, error) {
	var buf bytes.Buffer
	err := e.templateCache.ExecuteTemplate(&buf, filepath.Base(path), data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
