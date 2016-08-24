package nginxauth

import (
	"bytes"
	"errors"
	"html/template"
	"path/filepath"

	"github.com/robarchibald/configReader"
	"gopkg.in/gomail.v2"
)

type Mailer interface {
	SendWelcome(to string, data interface{}) error
	SendVerify(to string, data interface{}) error
	SendNewLogin(to string, data interface{}) error
	SendLockedOut(to string, data interface{}) error
	SendEmailChanged(to string, data interface{}) error
	SendPasswordChanged(to string, data interface{}) error
}

type Sender interface {
	Send(to, subject, body string) error
}

type Emailer struct {
	templateCache           *template.Template
	sender                  Sender
	SmtpServer              string
	SmtpPort                int
	SmtpFromEmail           string
	SmtpPassword            string
	EmailFromDisplayName    string
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

type SmtpSender struct {
	SmtpServer           string
	SmtpPort             int
	SmtpFromEmail        string
	SmtpPassword         string
	EmailFromDisplayName string
}

func (s *SmtpSender) Send(to, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", m.FormatAddress(s.SmtpFromEmail, s.EmailFromDisplayName))
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewPlainDialer(s.SmtpServer, s.SmtpPort, s.SmtpFromEmail, s.SmtpPassword)

	if err := d.DialAndSend(m); err != nil {
		return err
	}
	return nil
}

func NewEmailer(configPath string) (*Emailer, error) {
	mailer := &Emailer{}
	err := configReader.ReadFile(configPath, mailer)
	if err != nil {
		return nil, errors.New("Unable to open config file: " + err.Error())
	}
	mailer.sender = &SmtpSender{mailer.SmtpServer, mailer.SmtpPort, mailer.SmtpFromEmail, mailer.SmtpPassword, mailer.EmailFromDisplayName}
	mailer.templateCache, err = template.ParseFiles(mailer.VerifyEmailTemplate, mailer.WelcomeTemplate,
		mailer.NewLoginTemplate, mailer.LockedOutTemplate, mailer.EmailChangedTemplate, mailer.PasswordChangedTemplate)
	if err != nil {
		return nil, errors.New("Unable to parse template files: " + err.Error())
	}
	return mailer, nil
}

func (e *Emailer) SendVerify(to string, data interface{}) error {
	return e.send(to, e.VerifyEmailSubject, e.VerifyEmailTemplate, data)
}

func (e *Emailer) SendWelcome(to string, data interface{}) error {
	return e.send(to, e.WelcomeSubject, e.WelcomeTemplate, data)
}

func (e *Emailer) SendNewLogin(to string, data interface{}) error {
	return e.send(to, e.NewLoginSubject, e.NewLoginTemplate, data)
}

func (e *Emailer) SendLockedOut(to string, data interface{}) error {
	return e.send(to, e.LockedOutSubject, e.LockedOutTemplate, data)
}

func (e *Emailer) SendEmailChanged(to string, data interface{}) error {
	return e.send(to, e.EmailChangedSubject, e.EmailChangedTemplate, data)
}

func (e *Emailer) SendPasswordChanged(to string, data interface{}) error {
	return e.send(to, e.PasswordChangedSubject, e.PasswordChangedTemplate, data)
}

func (e *Emailer) send(to string, subject string, emailTemplate string, data interface{}) error {
	body, err := e.renderHtmlBody(emailTemplate, data)
	if err != nil {
		return err
	}

	return e.sender.Send(to, subject, body)
}

func (e *Emailer) renderHtmlBody(path string, data interface{}) (string, error) {
	var buf bytes.Buffer
	err := e.templateCache.ExecuteTemplate(&buf, filepath.Base(path), data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
