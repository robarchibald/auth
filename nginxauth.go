package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/robarchibald/configReader"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type authConf struct {
	AuthServerListenPort                     int
	StoragePrefix                            string
	DbType                                   string
	DbServer                                 string
	DbPort                                   int
	DbUser                                   string
	DbDatabase                               string
	DbPassword                               string
	LdapServer                               string
	LdapPort                                 int
	LdapBindDn                               string
	LdapPassword                             string
	LdapBaseDn                               string
	LdapUserFilter                           string
	GetSessionQuery                          string
	RenewSessionQuery                        string
	GetRememberMeQuery                       string
	RenewRememberMeQuery                     string
	AddUserQuery                             string
	GetUserQuery                             string
	UpdateUserQuery                          string
	CreateLoginQuery                         string
	UpdateEmailAndInvalidateSessionsQuery    string
	UpdatePasswordAndInvalidateSessionsQuery string
	InvalidateUserSessionsQuery              string

	RedisServer         string
	RedisPort           int
	RedisPassword       string
	RedisMaxIdle        int
	RedisMaxConnections int
	ConcurrentDownloads int

	CookieBase64Key string

	SMTPServer              string
	SMTPPort                int
	SMTPFromEmail           string
	SMTPPassword            string
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
	backend   backender
	mailer    mailer
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

	m := newBackendMemory(&cryptoHashStore{})
	s := newBackendRedisSession(config.RedisServer, config.RedisPort, config.RedisPassword, config.RedisMaxIdle, config.RedisMaxConnections, config.StoragePrefix)
	/*l, err := newBackendLDAPLogin(config.LdapServer, config.LdapPort, config.LdapBindDn, config.LdapPassword, config.LdapBaseDn, config.LdapUserFilter)
	if err != nil {
		return nil, err
	}
	u, err := newBackendDbUser(config.DbServer, config.DbPort, config.DbUser, config.DbPassword, config.DbDatabase, config.AddUserQuery, config.GetUserQuery, config.UpdateUserQuery)
	if err != nil {
		return nil, err
	}*/
	b := &backend{u: m, l: m, s: s}

	mailer, err := config.NewEmailer()
	if err != nil {
		return nil, err
	}

	cookieKey, err := decodeFromString(config.CookieBase64Key)
	if err != nil {
		return nil, err
	}

	return &nginxauth{b, mailer, cookieKey, config}, nil
}

func (n *authConf) NewEmailer() (*emailer, error) {
	sender := &smtpSender{n.SMTPServer, n.SMTPPort, n.SMTPFromEmail, n.SMTPPassword, n.EmailFromDisplayName}
	templateCache, err := template.ParseFiles(n.VerifyEmailTemplate, n.WelcomeTemplate,
		n.NewLoginTemplate, n.LockedOutTemplate, n.EmailChangedTemplate, n.PasswordChangedTemplate)
	if err != nil {
		return nil, err
	}
	return &emailer{
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

func (s *nginxauth) method(name string, handler func(authStore authStorer, w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != name {
			http.Error(w, "Unsupported method", http.StatusInternalServerError)
			return
		}
		secureOnly := strings.HasPrefix(r.Referer(), "https") // proxy to back-end so if referer is secure connection, we can use secureOnly cookies
		authStore := newAuthStore(s.backend, s.mailer, &cryptoHashStore{}, w, r, s.conf.StoragePrefix, s.cookieKey, secureOnly)
		handler(authStore, w, r)
	}
}

func auth(authStore authStorer, w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	log.Println("auth begin:")
	session, err := authStore.GetSession()
	if err != nil {
		authErr(w, r, err)
		log.Println("auth end:   session error", time.Since(startTime))
		return
	}

	user, err := json.Marshal(&userLogin{Email: session.Email, UserID: session.UserID, FullName: session.FullName})
	if err != nil {
		authErr(w, r, err)
		log.Println("auth end:   json error", time.Since(startTime))
		return
	}

	addUserHeader(string(user), w)
	log.Println("auth end:   success", time.Since(startTime))
}

func authErr(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, "Authentication required: "+err.Error(), http.StatusUnauthorized)
	if a, ok := err.(*authError); ok {
		fmt.Println(a.Trace())
	} else {
		fmt.Println(err)
	}
}

func authBasic(authStore authStorer, w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	log.Println("authBasic begin:")
	session, err := authStore.GetBasicAuth()
	if err != nil {
		basicErr(w, r, err)
		log.Println("authBasic end:   session error", time.Since(startTime))
		return
	}

	user, err := json.Marshal(&userLogin{Email: session.Email, UserID: session.UserID, FullName: session.FullName})
	if err != nil {
		basicErr(w, r, err)
		log.Println("authBasic end:   json error", time.Since(startTime))
		return
	}

	addUserHeader(string(user), w)
	log.Println("authBasic end:   success", time.Since(startTime))
}

func basicErr(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("WWW-Authenticate", "Basic realm='Endfirst.com'")
	http.Error(w, "Authentication required: "+err.Error(), http.StatusUnauthorized)
}

func login(authStore authStorer, w http.ResponseWriter, r *http.Request) {
	run("login", authStore.Login, w)
}

func register(authStore authStorer, w http.ResponseWriter, r *http.Request) {
	run("register", authStore.Register, w)
}

func createProfile(authStore authStorer, w http.ResponseWriter, r *http.Request) {
	run("createProfile", authStore.CreateProfile, w)
}

func updateEmail(authStore authStorer, w http.ResponseWriter, r *http.Request) {
	run("updateEmail", authStore.UpdateEmail, w)
}

func updatePassword(authStore authStorer, w http.ResponseWriter, r *http.Request) {
	run("updatePassword", authStore.UpdatePassword, w)
}

func verifyEmail(authStore authStorer, w http.ResponseWriter, r *http.Request) {
	run("verifyEmail", authStore.VerifyEmail, w)
}

func run(name string, method func() error, w http.ResponseWriter) {
	startTime := time.Now()
	log.Println(name, "begin:")
	err := method()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		if a, ok := err.(*authError); ok {
			fmt.Println(a.Trace())
		}
		log.Println(name, "end:   error", time.Since(startTime))
	} else {
		w.Header().Add("Access-Control-Allow-Origin", "*")
		w.Header().Add("Content-Type", "application/javascript")
		fmt.Fprint(w, "{ \"result\": \"Success\" }")
		log.Println(name, "end:   success", time.Since(startTime))
	}
}

func addUserHeader(userJSON string, w http.ResponseWriter) {
	w.Header().Add("X-User", userJSON)
}
