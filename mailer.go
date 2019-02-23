package auth

import (
	"bytes"
	"html/template"

	sendgrid "github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	gomail "gopkg.in/gomail.v2"
)

// Mailer interface includes method needed to send communication to users on account updates
type Mailer interface {
	SendMessage(to, templateName, emailSubject string, data interface{}) error
}

type sender interface {
	Send(to, subject, body string) error
}

// Emailer struct contains parsed glob of email templates a Sender interface to send emails
type Emailer struct {
	TemplateCache *template.Template
	Sender        sender
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

// Send mails the provided email body to recipient at "to" with subject "subject"
func (s *SendGridSender) Send(to, subject, body string) error {
	from := mail.NewEmail(s.EmailFromDisplayName, s.EmailFromAddress)
	message := mail.NewSingleEmail(from, subject, mail.NewEmail("", to), body, body)
	client := sendgrid.NewSendClient(s.APIKey)
	_, err := client.Send(message)
	return err
}

// Send mails the provided email body to recipient at "to" with subject "subject"
func (s *SmtpSender) Send(to, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", m.FormatAddress(s.SMTPFromEmail, s.EmailFromDisplayName))
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewPlainDialer(s.SMTPServer, s.SMTPPort, s.SMTPFromEmail, s.SMTPPassword)

	return d.DialAndSend(m)
}

// SendMessage prepares an email with the provided template and passes it to Send for mailing
func (e *Emailer) SendMessage(to, templateName, emailSubject string, data interface{}) error {
	var buf bytes.Buffer
	err := e.TemplateCache.ExecuteTemplate(&buf, templateName, data)
	if err != nil {
		return err
	}
	return e.Sender.Send(to, emailSubject, buf.String())
}
