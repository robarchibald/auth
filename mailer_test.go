package auth

import (
	"html/template"
	"testing"
)

const verifyEmailTmpl string = "email:{{ .Email }}"

func TestSends(t *testing.T) {
	sender := &NilSender{}
	m := Emailer{
		Sender: sender,
	}
	m.TemplateCache = template.Must(template.New("testTempl").Parse(verifyEmailTmpl))
	data := &emailSession{Email: "myemail@here.com"}
	err := m.SendMessage("to", "testTempl", "testEmailSubject", data)
	if err != nil || sender.LastBody != "email:myemail@here.com" || sender.LastTo != "to" || sender.LastSubject != "testEmailSubject" {
		t.Error("expected valid values", sender, err)
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
	Err error
	Mailer
	MessageTo   string
	MessageData interface{}
}

func (t *TextMailer) SendMessage(to, templateName, emailSubject string, data interface{}) error {
	return t.send(to, data)
}

func (t *TextMailer) send(to string, data interface{}) error {
	t.MessageTo = to
	t.MessageData = data
	return t.Err
}
