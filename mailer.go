package auth

import (
	"bytes"
	"html/template"
	"path/filepath"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"gopkg.in/gomail.v2"
)

// Mailer interface includes methods needed to send communication to users on account updates
type Mailer interface {
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

type Emailer struct {
	TemplateCache *template.Template
	Sender        sender

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
	SMTPServer           string
	SMTPPort             int
	SMTPFromEmail        string
	SMTPPassword         string
	EmailFromDisplayName string
}

type SendGridSender struct {
	APIKey               string
	EmailFromDisplayName string
	EmailFromAddress     string
}

func (s *SendGridSender) Send(to, subject, body string) error {
	from := mail.NewEmail(s.EmailFromDisplayName, s.EmailFromAddress)
	message := mail.NewSingleEmail(from, subject, mail.NewEmail("", to), body, body)
	client := sendgrid.NewSendClient(s.APIKey)
	_, err := client.Send(message)
	return err
}

func (s *SmtpSender) Send(to, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", m.FormatAddress(s.SMTPFromEmail, s.EmailFromDisplayName))
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewPlainDialer(s.SMTPServer, s.SMTPPort, s.SMTPFromEmail, s.SMTPPassword)

	return d.DialAndSend(m)
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
	body, err := e.renderHTMLBody(emailTemplate, data)
	if err != nil {
		return err
	}

	return e.Sender.Send(to, subject, body)
}

func (e *Emailer) renderHTMLBody(path string, data interface{}) (string, error) {
	var buf bytes.Buffer
	err := e.TemplateCache.ExecuteTemplate(&buf, filepath.Base(path), data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
