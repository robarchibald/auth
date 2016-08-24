package nginxauth

import (
	"html/template"
	"strings"
	"testing"
)

const verifyEmailTmpl string = "code:{{ .VerificationCode }}, email:{{ .Email }}"

func TestNewEmailer(t *testing.T) {
	_, err := NewEmailer("bogus") // invalid path
	if !strings.HasPrefix(err.Error(), "Unable to open config file: ") {
		t.Error("Expected error opening config file")
	}

	_, err = NewEmailer("mailer.go") // valid path, but invalid config file
	if !strings.HasPrefix(err.Error(), "Unable to parse template files: ") {
		t.Error("Expected error parsing template files")
	}

	if _, err := NewEmailer("testTemplates/mailer.conf"); err != nil {
		t.Error("Expected success")
	}
}

func TestRenderHtmlBody(t *testing.T) {
	m := Emailer{templateCache: template.Must(template.New("verifyEmail").Parse(verifyEmailTmpl))}
	if txt, err := m.renderHtmlBody("verifyEmail", SendVerifyParams{VerificationCode: "1234", Email: "email@example.com"}); txt != "code:1234, email:email@example.com" || err != nil {
		t.Error("expected correct txt and no error", txt, err)
	}

	m = Emailer{templateCache: template.Must(template.New("verifyEmail").Parse(verifyEmailTmpl))}
	if _, err := m.renderHtmlBody("verifyEmail..", nil); err == nil {
		t.Error("expected error", err)
	}
}

func TestSends(t *testing.T) {
	m, _ := NewEmailer("testTemplates/mailer.conf")
	data := &VerifyEmailReturn{Email: "myemail@here.com"}
	m.sender = &NilSender{}
	m.SendVerify("to", data)
	sender := m.sender.(*NilSender)
	if sender.LastBody != "verifyEmail:myemail@here.com" || sender.LastTo != "to" || sender.LastSubject != "verifyEmailSubject" {
		t.Error("expected valid values", sender)
	}

	m.SendWelcome("to1", data)
	if sender.LastBody != "welcomeEmail:myemail@here.com" || sender.LastTo != "to1" || sender.LastSubject != "welcomeSubject" {
		t.Error("expected valid values", sender)
	}

	m.SendNewLogin("to2", data)
	if sender.LastBody != "newLogin:myemail@here.com" || sender.LastTo != "to2" || sender.LastSubject != "newLoginSubject" {
		t.Error("expected valid values", sender)
	}

	m.SendLockedOut("to3", data)
	if sender.LastBody != "lockedOut:myemail@here.com" || sender.LastTo != "to3" || sender.LastSubject != "lockedOutSubject" {
		t.Error("expected valid values", sender)
	}

	m.SendEmailChanged("to4", data)
	if sender.LastBody != "emailChanged:myemail@here.com" || sender.LastTo != "to4" || sender.LastSubject != "emailChangedSubject" {
		t.Error("expected valid values", sender)
	}

	m.SendPasswordChanged("to5", data)
	if sender.LastBody != "passwordChanged:myemail@here.com" || sender.LastTo != "to5" || sender.LastSubject != "passwordChangedSubject" {
		t.Error("expected valid values", sender)
	}
}

/***************************************************************************************/

type NilSender struct {
	LastTo      string
	LastSubject string
	LastBody    string
}

func (s *NilSender) Send(to, subject, body string) error {
	s.LastTo = to
	s.LastSubject = subject
	s.LastBody = body
	return nil
}

type TextMailer struct {
	Mailer
	MessageTo   string
	MessageData interface{}
}

func (t *TextMailer) SendVerify(to string, data interface{}) error {
	return t.send(to, data)
}

func (t *TextMailer) SendWelcome(to string, data interface{}) error {
	return t.send(to, data)
}

func (t *TextMailer) SendNewLogin(to string, data interface{}) error {
	return t.send(to, data)
}

func (t *TextMailer) SendLockedOut(to string, data interface{}) error {
	return t.send(to, data)
}

func (t *TextMailer) SendEmailChanged(to string, data interface{}) error {
	return t.send(to, data)
}

func (t *TextMailer) SendPasswordChanged(to string, data interface{}) error {
	return t.send(to, data)
}

func (t *TextMailer) send(to string, data interface{}) error {
	t.MessageTo = to
	t.MessageData = data
	return nil
}
