package main

import (
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/robarchibald/configReader"
	"github.com/robarchibald/onedb"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
)

type authConf struct {
	AuthServerListenPort                     int
	BackendType                              string
	BackendServer                            string
	BackendPort                              int
	BackendUser                              string
	BackendDatabase                          string
	BackendPassword                          string
	GetUserLoginQuery                        string
	GetSessionQuery                          string
	RenewSessionQuery                        string
	GetRememberMeQuery                       string
	RenewRememberMeQuery                     string
	AddUserQuery                             string
	VerifyEmailQuery                         string
	UpdateUserQuery                          string
	CreateLoginQuery                         string
	UpdateEmailAndInvalidateSessionsQuery    string
	UpdatePasswordAndInvalidateSessionsQuery string
	InvalidateUserSessionsQuery              string

	CookieBase64Key string

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

type nginxauth struct {
	backend   BackendQuerier
	mailer    Mailer
	cookieKey []byte
	conf      authConf
}

func main() {
	server, err := newNginxAuth()
	if err != nil {
		log.Fatal(err)
	}
	defer server.backend.Close()

	server.serve(server.conf.AuthServerListenPort)
}

func newNginxAuth() (*nginxauth, error) {
	config := authConf{}
	err := configReader.ReadFile("nginxauth.conf", &config)
	if err != nil {
		log.Fatal(err)
	}

	backend := NewBackendMemory() //temporarily using the in-memory DB for testing

	mailer, err := config.NewEmailer()
	if err != nil {
		return nil, err
	}

	cookieKey, err := decodeFromString(config.CookieBase64Key)
	if err != nil {
		return nil, err
	}

	return &nginxauth{backend, mailer, cookieKey, config}, nil
}

func (n *authConf) newOnedbBackend() (BackendQuerier, error) {
	db, err := onedb.NewPgx(n.BackendServer, uint16(n.BackendPort), n.BackendUser, n.BackendPassword, n.BackendDatabase)
	if err != nil {
		return nil, err
	}
	return &BackendOnedb{Db: db,
		GetUserLoginQuery:                        n.GetUserLoginQuery,
		GetSessionQuery:                          n.GetSessionQuery,
		RenewSessionQuery:                        n.RenewSessionQuery,
		GetRememberMeQuery:                       n.GetRememberMeQuery,
		RenewRememberMeQuery:                     n.RenewRememberMeQuery,
		AddUserQuery:                             n.AddUserQuery,
		VerifyEmailQuery:                         n.VerifyEmailQuery,
		UpdateUserQuery:                          n.UpdateUserQuery,
		CreateLoginQuery:                         n.CreateLoginQuery,
		UpdateEmailAndInvalidateSessionsQuery:    n.UpdateEmailAndInvalidateSessionsQuery,
		UpdatePasswordAndInvalidateSessionsQuery: n.UpdatePasswordAndInvalidateSessionsQuery,
		InvalidateUserSessionsQuery:              n.InvalidateUserSessionsQuery}, nil
}

func (n *authConf) NewEmailer() (*Emailer, error) {
	sender := &SmtpSender{n.SmtpServer, n.SmtpPort, n.SmtpFromEmail, n.SmtpPassword, n.EmailFromDisplayName}
	templateCache, err := template.ParseFiles(n.VerifyEmailTemplate, n.WelcomeTemplate,
		n.NewLoginTemplate, n.LockedOutTemplate, n.EmailChangedTemplate, n.PasswordChangedTemplate)
	if err != nil {
		return nil, err
	}
	return &Emailer{
		templateCache:           templateCache,
		sender:                  sender,
		VerifyEmailTemplate:     n.VerifyEmailTemplate,
		VerifyEmailSubject:      n.VerifyEmailSubject,
		WelcomeTemplate:         n.WelcomeTemplate,
		WelcomeSubject:          n.WelcomeSubject,
		NewLoginTemplate:        n.NewLoginTemplate,
		NewLoginSubject:         n.NewLoginSubject,
		LockedOutTemplate:       n.LockedOutTemplate,
		LockedOutSubject:        n.LockedOutSubject,
		EmailChangedTemplate:    n.EmailChangedTemplate,
		EmailChangedSubject:     n.EmailChangedSubject,
		PasswordChangedTemplate: n.PasswordChangedTemplate,
		PasswordChangedSubject:  n.PasswordChangedSubject,
	}, nil
}

func (s *nginxauth) serve(port int) {
	http.HandleFunc("/auth", s.method("GET", auth))
	http.HandleFunc("/authBasic", s.method("GET", authBasic))
	http.HandleFunc("/createProfile", s.method("POST", createProfile))
	http.HandleFunc("/login", s.method("POST", login))
	http.HandleFunc("/register", s.method("POST", register))
	http.HandleFunc("/verifyEmail", s.method("POST", verifyEmail))
	http.HandleFunc("/updateEmail", s.method("POST", updateEmail))
	http.HandleFunc("/updatePassword", s.method("POST", updatePassword))

	http.ListenAndServe(fmt.Sprintf(":%d", port), fileLoggerHandler(handlers.CompressHandler(http.DefaultServeMux)))
}

func fileLoggerHandler(h http.Handler) http.Handler {
	logFile, err := os.OpenFile("nginxauth.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	return handlers.CombinedLoggingHandler(logFile, h)
}

func (s *nginxauth) method(name string, handler func(sessionStore SessionStorer, w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != name {
			http.Error(w, "Unsupported method", http.StatusInternalServerError)
			return
		}
		secureOnly := strings.HasPrefix(r.Referer(), "https") // proxy to back-end so if referer is secure connection, we can use secureOnly cookies
		sessionStore := NewSessionStore(s.backend, s.mailer, w, r, s.cookieKey, "ef", secureOnly)
		handler(sessionStore, w, r)
	}
}
