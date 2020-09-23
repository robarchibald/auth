package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path"

	"github.com/EndFirstCorp/auth"
	"github.com/EndFirstCorp/configReader"
	"github.com/EndFirstCorp/onedb/mgo"
	"github.com/gorilla/handlers"
)

type authConf struct {
	AuthServerListenPort                     int
	StoragePrefix                            string
	ConnectionURI                            string
	GetSessionQuery                          string
	RenewSessionQuery                        string
	GetRememberMeQuery                       string
	RenewRememberMeQuery                     string
	AddUserQuery                             string
	GetUserQuery                             string
	UpdateUserQuery                          string
	CreateSecondaryEmailQuery                string
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
	CookieDomain    string

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
	backend  auth.Backender
	a        auth.AuthStorer
	conf     authConf
	errorLog *os.File
}

func main() {
	configFile := flag.String("c", "/etc/nginxauth/nginxauth.conf", "config file location")
	logfile := flag.String("l", "/var/log/nginxauth.log", "log file")
	flag.Parse()

	server, err := newNginxAuth(*configFile, *logfile)
	if err != nil {
		log.Fatal(err)
	}
	defer server.backend.Close()
	defer server.errorLog.Close()

	server.serve(server.conf.AuthServerListenPort)
}

func newNginxAuth(configFle, logfile string) (*nginxauth, error) {
	eLog, err := createLogfile(logfile)
	if err != nil {
		return nil, err
	}
	log.Println("Starting auth server")

	config := authConf{}
	err = configReader.ReadFile(configFle, &config)
	if err != nil {
		return nil, err
	}
	m, err := mgo.Dial(config.ConnectionURI)
	if err != nil {
		return nil, err
	}

	s := auth.NewBackendRedisSession(config.RedisServer, config.RedisPort, config.RedisPassword, config.RedisMaxIdle, config.RedisMaxConnections, config.StoragePrefix)
	b := auth.NewBackend(auth.NewBackendMongo(m, &auth.CryptoHashStore{}), s)

	mailer, err := config.NewEmailer()
	if err != nil {
		return nil, err
	}

	cookieKey, err := base64.URLEncoding.DecodeString(config.CookieBase64Key)
	if err != nil {
		return nil, err
	}

	return &nginxauth{b, auth.NewAuthStore(b, mailer, config.StoragePrefix, config.CookieDomain, cookieKey), config, eLog}, nil
}

func (n *authConf) NewEmailer() (*auth.Emailer, error) {
	sender := &auth.SmtpSender{n.SMTPServer, n.SMTPPort, n.SMTPFromEmail, n.SMTPPassword, n.EmailFromDisplayName}
	templateCache, err := template.ParseFiles(n.VerifyEmailTemplate, n.WelcomeTemplate,
		n.NewLoginTemplate, n.LockedOutTemplate, n.EmailChangedTemplate, n.PasswordChangedTemplate)
	if err != nil {
		return nil, err
	}
	return &auth.Emailer{
		TemplateCache: templateCache,
		Sender:        sender,
	}, nil
}

func (s *nginxauth) serve(port int) {
	http.HandleFunc("/auth", s.method("GET", authCookie))
	http.HandleFunc("/authBasic", s.method("GET", authBasic))
	http.HandleFunc("/createProfile", s.method("POST", createProfile))
	http.HandleFunc("/login", s.method("POST", login))
	http.HandleFunc("/oauth", s.method("GET", oauthLogin))
	http.HandleFunc("/register", s.method("POST", register))
	http.HandleFunc("/verifyEmail", s.method("POST", verifyEmail))
	http.HandleFunc("/createSecondaryEmail", s.method("POST", createSecondaryEmail))
	http.HandleFunc("/setPrimaryEmail", s.method("POST", setPrimaryEmail))
	http.HandleFunc("/updatePassword", s.method("POST", updatePassword))

	http.ListenAndServe(fmt.Sprintf(":%d", port), handlers.CompressHandler(http.DefaultServeMux))
}

func (s *nginxauth) method(name string, handler func(authStore auth.AuthStorer, w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != name {
			http.Error(w, "Unsupported method", http.StatusInternalServerError)
			return
		}
		handler(s.a, w, r)
	}
}

func authCookie(authStore auth.AuthStorer, w http.ResponseWriter, r *http.Request) {
	session, err := authStore.GetSession(w, r)
	if err != nil {
		authErr(w, r, err)
		return
	}

	user, err := json.Marshal(&auth.User{Email: session.Email, UserID: session.UserID, Info: session.Info})
	if err != nil {
		authErr(w, r, err)
		return
	}

	addUserHeader(string(user), w)
}

func authErr(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, "Authentication required: "+err.Error(), http.StatusUnauthorized)
	logError(err)
}

func logError(err error) {
	if a, ok := err.(*auth.AuthError); ok {
		log.Println(a.Trace())
	} else {
		log.Println(err)
	}
}

func authBasic(authStore auth.AuthStorer, w http.ResponseWriter, r *http.Request) {
	session, err := authStore.GetBasicAuth(w, r)
	if err != nil {
		basicErr(w, r, err)
		return
	}

	user, err := json.Marshal(&auth.User{Email: session.Email, UserID: session.UserID, Info: session.Info})
	if err != nil {
		basicErr(w, r, err)
		return
	}

	addUserHeader(string(user), w)
}

func basicErr(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("WWW-Authenticate", "Basic realm='Endfirst.com'")
	http.Error(w, "Authentication required: "+err.Error(), http.StatusUnauthorized)
	logError(err)
}

func oauthLogin(authStore auth.AuthStorer, w http.ResponseWriter, r *http.Request) {
	runWithCSRF(authStore.OAuthLogin, w, r)
}

func login(authStore auth.AuthStorer, w http.ResponseWriter, r *http.Request) {
	runWithProfile(authStore.Login, w, r)
}

func register(authStore auth.AuthStorer, w http.ResponseWriter, r *http.Request) {
	outputMessage(w, `{ "result": "Success" }`, authStore.Register(w, r, "", auth.TemplateNames{}, "", nil))
}

func createProfile(authStore auth.AuthStorer, w http.ResponseWriter, r *http.Request) {
	runWithProfile(authStore.CreateProfile, w, r)
}

func createSecondaryEmail(authStore auth.AuthStorer, w http.ResponseWriter, r *http.Request) {
	outputMessage(w, `{ "result": "Success" }`, authStore.CreateSecondaryEmail(w, r, "", ""))
}

func setPrimaryEmail(authStore auth.AuthStorer, w http.ResponseWriter, r *http.Request) {
	outputMessage(w, `{ "result": "Success" }`, authStore.SetPrimaryEmail(w, r, "", ""))
}

func updatePassword(authStore auth.AuthStorer, w http.ResponseWriter, r *http.Request) {
	_, err := authStore.UpdatePassword(w, r)
	outputMessage(w, `{ "result": "Success" }`, err)
}

type verifyEmailResponse struct {
	DestinationURL string `json:"destinationURL"`
	Email          string `json:"email"`
	CSRFToken      string `json:"csrfToken"`
}

func verifyEmail(authStore auth.AuthStorer, w http.ResponseWriter, r *http.Request) {
	csrfToken, user, err := authStore.VerifyEmail(w, r, "", "", "")
	if err != nil {
		outputError(w, err)
		return
	}
	outputData(w, verifyEmailResponse{user.GetInfoString("destinationURL"), user.Email, csrfToken})
}

func run(name string, method func(http.ResponseWriter, *http.Request) error, w http.ResponseWriter, r *http.Request) {
	outputMessage(w, `{ "result": "Success" }`, method(w, r))
}

func runWithProfile(method func(http.ResponseWriter, *http.Request) (*auth.LoginSession, error), w http.ResponseWriter, r *http.Request) {
	s, err := method(w, r)
	if err != nil {
		authErr(w, r, err)
		return
	}
	outputData(w, &auth.User{Email: s.Email, UserID: s.UserID, Info: s.Info})
}

func runWithCSRF(method func(http.ResponseWriter, *http.Request) (string, error), w http.ResponseWriter, r *http.Request) {
	csrfToken, err := method(w, r)
	outputMessage(w, fmt.Sprintf(`{ "result": "Success", "csrfToken": "%s" }`, csrfToken), err)
}

func outputMessage(w http.ResponseWriter, message string, err error) {
	w.Header().Add("Access-Control-Allow-Origin", "*")
	if err != nil {
		outputError(w, err)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	fmt.Fprint(w, message)
}

func outputError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
	if aerr, ok := err.(*auth.AuthError); ok {
		log.Println(aerr.Trace())
	}
}

func outputData(w http.ResponseWriter, data interface{}) {
	outData, err := json.Marshal(data)
	outputMessage(w, string(outData), err)
}

func addUserHeader(userJSON string, w http.ResponseWriter) {
	w.Header().Add("X-User", userJSON)
}

func createLogfile(logFile string) (*os.File, error) {
	dir := path.Dir(logFile)
	if _, err := os.Stat(dir); err != nil && os.IsNotExist(err) {
		os.MkdirAll(dir, 0755)
	}
	eLog, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	log.SetOutput(eLog)
	return eLog, nil
}
