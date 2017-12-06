package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var emailCookieName = "Email"
var sessionCookieName = "Session"
var rememberMeCookieName = "RememberMe"
var emailRegex = regexp.MustCompile(`^(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$`)

const emailExpireMins int = 60 * 24 * 365 // 1 year
const emailExpireDuration time.Duration = time.Duration(emailExpireMins) * time.Minute
const sessionRenewDuration time.Duration = 5 * time.Minute
const sessionExpireDuration time.Duration = time.Hour
const rememberMeRenewDuration time.Duration = time.Hour
const rememberMeExpireDuration time.Duration = time.Hour * 24 * 30 // 30 days
const passwordValidationMessage string = "Password must be between 7 and 20 characters"

// AuthStorer interface provides the necessary functionality to get and store authentication information
type AuthStorer interface {
	GetSession(w http.ResponseWriter, r *http.Request) (*LoginSession, error)
	GetBasicAuth(w http.ResponseWriter, r *http.Request) (*LoginSession, error)
	OAuthLogin(w http.ResponseWriter, r *http.Request) error
	Login(w http.ResponseWriter, r *http.Request) error
	Register(w http.ResponseWriter, r *http.Request) error
	CreateProfile(w http.ResponseWriter, r *http.Request) error
	VerifyEmail(w http.ResponseWriter, r *http.Request) (string, error)
	UpdateEmail(w http.ResponseWriter, r *http.Request) error
	UpdatePassword(w http.ResponseWriter, r *http.Request) error
}

type emailCookie struct {
	EmailVerificationCode string
	ExpireTimeUTC         time.Time
}

type sessionCookie struct {
	SessionID     string
	RenewTimeUTC  time.Time
	ExpireTimeUTC time.Time
}

type rememberMeCookie struct {
	Selector      string
	Token         string
	RenewTimeUTC  time.Time
	ExpireTimeUTC time.Time
}

type authStore struct {
	backend     Backender
	mailer      Mailer
	cookieStore CookieStorer
	c           Crypter
}

func NewAuthStore(b Backender, mailer Mailer, c Crypter, customPrefix string, cookieKey []byte) AuthStorer {
	emailCookieName = customPrefix + "Email"
	sessionCookieName = customPrefix + "Session"
	rememberMeCookieName = customPrefix + "RememberMe"
	return &authStore{b, mailer, newCookieStore(cookieKey), c}
}

func (s *authStore) GetSession(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	cookie, err := s.getSessionCookie(w, r)
	if err != nil || cookie.SessionID == "" { // impossible to get the session if there is no cookie
		return nil, newAuthError("Session cookie not found", err)
	}
	sessionHash, err := decodeStringToHash(cookie.SessionID)
	if err != nil {
		return nil, newAuthError("Unable to decode session cookie", err)
	}

	if cookie.RenewTimeUTC.Before(time.Now().UTC()) || cookie.ExpireTimeUTC.Before(time.Now().UTC()) {
		return s.renewSession(w, r, cookie.SessionID, sessionHash, &cookie.RenewTimeUTC, &cookie.ExpireTimeUTC)
	}

	session, err := s.backend.GetSession(sessionHash)
	if err != nil {
		if err == errSessionNotFound {
			s.deleteSessionCookie(w)
		}
		return nil, newLoggedError("Failed to verify session", err)
	}
	return session, nil
}

func (s *authStore) GetBasicAuth(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	session, err := s.GetSession(w, r)
	if err == nil {
		return session, nil
	}

	if email, password, ok := r.BasicAuth(); ok {
		session, err := s.login(w, r, email, password, false)
		if err != nil {
			return nil, err
		}
		return session, nil
	}
	return nil, newAuthError("Problem decoding credentials from basic auth", nil)
}

func (s *authStore) getRememberMe(w http.ResponseWriter, r *http.Request) (*rememberMeSession, error) {
	cookie, err := s.getRememberMeCookie(w, r)
	if err != nil || cookie.Selector == "" { // impossible to get the remember Me if there is no cookie
		return nil, newAuthError("RememberMe cookie not found", err)
	}
	if cookie.ExpireTimeUTC.Before(time.Now().UTC()) {
		s.deleteRememberMeCookie(w)
		return nil, newAuthError("RememberMe cookie has expired", nil)
	}

	rememberMe, err := s.backend.GetRememberMe(cookie.Selector)
	if err != nil {
		if err == errRememberMeNotFound {
			s.deleteRememberMeCookie(w)
		}
		return nil, newLoggedError("Unable to find matching RememberMe in DB", err)
	}
	if err := encodedHashEquals(cookie.Token, rememberMe.TokenHash); err != nil {
		s.deleteRememberMeCookie(w)
		return nil, newLoggedError("RememberMe cookie doesn't match backend token", err)
	}
	if rememberMe.RenewTimeUTC.Before(time.Now().UTC()) {
		rememberMe, err = s.backend.RenewRememberMe(cookie.Selector, time.Now().UTC().Add(rememberMeRenewDuration))
		if err != nil {
			if err == errRememberMeNotFound {
				s.deleteRememberMeCookie(w)
			}
			return nil, newLoggedError("Unable to renew RememberMe", err)
		}
	}
	return rememberMe, nil
}

func (s *authStore) renewSession(w http.ResponseWriter, r *http.Request, sessionID, sessionHash string, renewTimeUTC, expireTimeUTC *time.Time) (*LoginSession, error) {
	// expired so check for valid rememberMe for renewal
	if expireTimeUTC.Before(time.Now().UTC()) {
		_, err := s.getRememberMe(w, r)
		if err != nil {
			return nil, newAuthError("Unable to renew session", err)
		}
	}
	// TODO: may want to change to add logic to ensure that we don't renew past the expire date
	// and so that we can't exceed the rememberMe expire time. Then, again, it may not matter much
	// with just a 5 minute renew time.
	session, err := s.backend.RenewSession(sessionHash, time.Now().UTC().Add(sessionRenewDuration))
	if err != nil {
		if err == errSessionNotFound {
			s.deleteSessionCookie(w)
		}
		return nil, newLoggedError("Problem renewing session", err)
	}

	if err = s.saveSessionCookie(w, r, sessionID, session.RenewTimeUTC, session.ExpireTimeUTC); err != nil {
		return nil, err
	}
	return session, nil
}

/******************************** Login ***********************************************/
func (s *authStore) Login(w http.ResponseWriter, r *http.Request) error {
	credentials, err := getCredentials(r)
	if err != nil {
		return newAuthError("Unable to get credentials", err)
	}
	_, err = s.login(w, r, credentials.Email, credentials.Password, credentials.RememberMe)
	return err
}

func (s *authStore) login(w http.ResponseWriter, r *http.Request, email, password string, rememberMe bool) (*LoginSession, error) {
	if !isValidEmail(email) {
		return nil, newAuthError("Please enter a valid email address.", nil)
	}
	if !isValidPassword(password) {
		return nil, newAuthError(passwordValidationMessage, nil)
	}

	// add in check for DDOS attack. Slow down or lock out checks for same account
	// or same IP with multiple failed attempts
	login, err := s.backend.Login(email, password)
	if err != nil {
		return nil, newLoggedError("Invalid username or password", err)
	}

	return s.createSession(w, r, email, login.UserID, login.FullName, rememberMe)
}

func (s *authStore) OAuthLogin(w http.ResponseWriter, r *http.Request) error {
	email, fullname, err := getOAuthCredentials(r)
	if err != nil {
		return err
	}
	return s.oauthLogin(w, r, email, fullname)
}

func (s *authStore) oauthLogin(w http.ResponseWriter, r *http.Request, email, fullname string) error {
	var userID int
	user, err := s.backend.GetUser(email)
	if user == nil || err != nil {
		userID, err = s.backend.AddUser(email)
		if err != nil {
			return newLoggedError("Failed to create new user in database", err)
		}

		err = s.backend.UpdateUser(userID, fullname, "", "")
		if err != nil {
			return newLoggedError("Unable to update user", err)
		}
	} else {
		userID = user.UserID
	}

	if _, err := s.backend.GetLogin(email); err != nil {
		_, err = s.createLogin(userID, email, fullname, "", 0, 0)
		if err != nil {
			return newLoggedError("Unable to create login", err)
		}
	}

	_, err = s.createSession(w, r, email, userID, fullname, false)
	if err != nil {
		return err
	}
	return nil
}

func getOAuthCredentials(r *http.Request) (string, string, error) {
	var fullname, email, email2 string
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", "", fmt.Errorf("No authorization found")
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", "", fmt.Errorf("Authorization header format must be Bearer {token}")
	}

	// need to actually parse here and handle error
	token, _ := jwt.Parse(authHeaderParts[1], func(token *jwt.Token) (interface{}, error) {
		//if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		//	return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		//}
		// supposed to validate the signature according to Microsoft. This is not trivial
		// https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-tokens#validating-tokens

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte("my_secret_key"), nil
	})

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok {
		fullname = fmt.Sprintf("%v", claims["name"])
		email = fmt.Sprintf("%v", claims["unique_name"])
		fmt.Println("unique_name:", email)
		email2 = fmt.Sprintf("%v", claims["email"])
		fmt.Println("email:", email2)
		if email == "" || fullname == "" {
			return "", "", fmt.Errorf("expected email and fullname")
		}
	}
	return email, fullname, nil
}

func (s *authStore) createSession(w http.ResponseWriter, r *http.Request, email string, userID int, fullname string, rememberMe bool) (*LoginSession, error) {
	var err error
	var selector, token, tokenHash string
	if rememberMe {
		selector, token, tokenHash, err = generateSelectorTokenAndHash()
		if err != nil {
			return nil, newLoggedError("Unable to generate RememberMe", err)
		}
	}
	sessionID, sessionHash, err := generateStringAndHash()
	if err != nil {
		return nil, newLoggedError("Problem generating sessionId", nil)
	}

	session, remember, err := s.backend.CreateSession(userID, email, fullname, sessionHash, time.Now().UTC().Add(sessionRenewDuration), time.Now().UTC().Add(sessionExpireDuration), rememberMe, selector, tokenHash, time.Now().UTC().Add(rememberMeRenewDuration), time.Now().UTC().Add(rememberMeExpireDuration))
	if err != nil {
		return nil, newLoggedError("Unable to create new session", err)
	}

	sessionCookie, err := s.getSessionCookie(w, r)
	if err == nil {
		oldSessionHash, err := decodeStringToHash(sessionCookie.SessionID)
		if err == nil {
			s.backend.InvalidateSession(oldSessionHash)
		}
	}

	rememberCookie, err := s.getRememberMeCookie(w, r)
	if err == nil {
		s.backend.InvalidateRememberMe(rememberCookie.Selector)
		s.deleteRememberMeCookie(w)
	}

	if rememberMe {
		err := s.saveRememberMeCookie(w, r, selector, token, remember.RenewTimeUTC, remember.ExpireTimeUTC)
		if err != nil {
			return nil, newAuthError("Unable to save rememberMe cookie", err)
		}
	}
	err = s.saveSessionCookie(w, r, sessionID, session.RenewTimeUTC, session.ExpireTimeUTC)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func isValidPassword(password string) bool {
	return len(password) >= 7 && len(password) <= 20
}

type sendVerifyParams struct {
	VerificationCode string
	Email            string
	RefererBaseURL   string
}

func (s *authStore) Register(w http.ResponseWriter, r *http.Request) error {
	registration, err := getRegistration(r)
	if err != nil {
		return newAuthError("Unable to get email", err)
	}
	return s.register(r, registration.Email, registration.DestinationURL)
}

func (s *authStore) register(r *http.Request, email, destinationURL string) error {
	if !isValidEmail(email) {
		return newAuthError("Invalid email", nil)
	}

	user, err := s.backend.GetUser(email)
	if user != nil {
		return newAuthError("User already registered", err)
	}

	verifyCode, err := s.addEmailSession(email, destinationURL)
	if err != nil {
		return newLoggedError("Unable to save user", err)
	}

	code := verifyCode[:len(verifyCode)-1] // drop the "=" at the end of the code since it makes it look like a querystring
	if err := s.mailer.SendVerify(email, &sendVerifyParams{code, email, getBaseURL(r.Referer())}); err != nil {
		return newLoggedError("Unable to send verification email", err)
	}

	return nil
}

func getBaseURL(url string) string {
	protoIndex := strings.Index(url, "://")
	if protoIndex == -1 { // must be relative URL, return default
		return "https://endfirst.com"
	}
	firstSlash := strings.Index(url[protoIndex+3:], "/")
	if firstSlash == -1 { // must not have trailing slash, return whole url
		return url
	}
	return url[:protoIndex+3+firstSlash]
}

func (s *authStore) addEmailSession(email, destinationURL string) (string, error) {
	verifyCode, verifyHash, err := generateStringAndHash()
	if err != nil {
		return "", newLoggedError("Problem generating email confirmation code", err)
	}

	err = s.backend.CreateEmailSession(email, verifyHash, destinationURL)
	if err != nil {
		return "", newLoggedError("Problem adding user to database", err)
	}

	return verifyCode, nil
}

func (s *authStore) CreateProfile(w http.ResponseWriter, r *http.Request) error {
	profile, err := getProfile(r)
	if err != nil {
		return newAuthError("Unable to get profile information from form", err)
	}
	return s.createProfile(w, r, profile.FullName, profile.Organization, profile.Password, profile.PicturePath, profile.MailQuota, profile.FileQuota)
}

func (s *authStore) createProfile(w http.ResponseWriter, r *http.Request, fullName, organization, password, picturePath string, mailQuota, fileQuota int) error {
	emailCookie, err := s.getEmailCookie(w, r)
	if err != nil || emailCookie.EmailVerificationCode == "" {
		return newLoggedError("Unable to get email verification cookie", err)
	}

	emailVerifyHash, err := decodeStringToHash(emailCookie.EmailVerificationCode) // base64 decode and hash
	if err != nil {
		return newLoggedError("Invalid email verification cookie", err)
	}

	session, err := s.backend.GetEmailSession(emailVerifyHash)
	if err != nil {
		return newLoggedError("Invalid email verification", err)
	}

	err = s.backend.UpdateUser(session.UserID, fullName, organization, picturePath)
	if err != nil {
		return newLoggedError("Unable to update user", err)
	}

	err = s.backend.DeleteEmailSession(session.EmailVerifyHash)
	if err != nil {
		return newLoggedError("Error while creating profile", err)
	}

	_, err = s.createLogin(session.UserID, session.Email, fullName, password, mailQuota, fileQuota)
	if err != nil {
		return newLoggedError("Unable to create login", err)
	}

	_, err = s.createSession(w, r, session.Email, session.UserID, fullName, false)
	if err != nil {
		return err
	}

	s.deleteEmailCookie(w)
	return nil
}

/****************  TODO: send 0 for UID and GID numbers and empty quotas if mailQuota and fileQuota are 0 **********************/
func (s *authStore) createLogin(userID int, email, fullName, password string, mailQuota, fileQuota int) (*UserLogin, error) {
	passwordHash, err := s.c.Hash(password)
	if err != nil {
		return nil, newLoggedError("Unable to create login", err)
	}
	if mailQuota == 0 || fileQuota == 0 {
		return s.createAccount(userID, email, fullName, password)
	}
	return s.createSubscriber(userID, email, fullName, passwordHash, mailQuota, fileQuota)
}

func (s *authStore) createAccount(userID int, email, fullName, passwordHash string) (*UserLogin, error) {
	login, err := s.backend.CreateAccount(userID, email, passwordHash, fullName)
	if err != nil {
		return nil, newLoggedError("Unable to create account", err)
	}
	return login, nil
}

func (s *authStore) createSubscriber(userID int, email, fullName, passwordHash string, mailQuota, fileQuota int) (*UserLogin, error) {
	uidNumber := 10000 // vmail user
	gidNumber := 10000 // vmail user
	sepIndex := strings.Index(email, "@")
	if sepIndex == -1 {
		return nil, errors.New("invalid email address")
	}
	domain := email[sepIndex+1:]
	user := email[:sepIndex]
	homeDirectory := fmt.Sprintf("/srv/vmail/%s/%s", domain, user)
	mQuota := fmt.Sprintf("%dGB", mailQuota)
	fQuota := fmt.Sprintf("%dGB", fileQuota)

	login, err := s.backend.CreateSubscriber(userID, email, passwordHash, fullName, homeDirectory, uidNumber, gidNumber, mQuota, fQuota)
	if err != nil {
		return nil, newLoggedError("Unable to create login", err)
	}
	return login, nil
}

// move to sessionStore
func (s *authStore) VerifyEmail(w http.ResponseWriter, r *http.Request) (string, error) {
	verify, err := getVerificationCode(r)
	if err != nil {
		return "", newAuthError("Unable to get verification email from JSON", err)
	}
	return s.verifyEmail(w, r, verify.EmailVerificationCode)
}

func (s *authStore) verifyEmail(w http.ResponseWriter, r *http.Request, emailVerificationCode string) (string, error) {
	if !strings.HasSuffix(emailVerificationCode, "=") { // add back the "=" then decode
		emailVerificationCode = emailVerificationCode + "="
	}
	emailVerifyHash, err := decodeStringToHash(emailVerificationCode)
	if err != nil {
		return "", newLoggedError("Invalid verification code", err)
	}

	session, err := s.backend.GetEmailSession(emailVerifyHash)
	if err != nil {
		return "", newLoggedError("Failed to verify email", err)
	}

	userID, err := s.backend.AddUser(session.Email)
	if err != nil {
		return "", newLoggedError("Failed to create new user in database", err)
	}

	err = s.backend.UpdateEmailSession(emailVerifyHash, userID, session.Email, session.DestinationURL)
	if err != nil {
		return "", newLoggedError("Failed to update email session", err)
	}

	err = s.saveEmailCookie(w, r, emailVerificationCode, time.Now().UTC().Add(emailExpireDuration))
	if err != nil {
		return "", newLoggedError("Failed to save email cookie", err)
	}

	err = s.mailer.SendWelcome(session.Email, nil)
	if err != nil {
		return "", newLoggedError("Failed to send welcome email", err)
	}
	return session.DestinationURL, nil
}

func (s *authStore) UpdateEmail(w http.ResponseWriter, r *http.Request) error { return nil }

func (s *authStore) UpdatePassword(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (s *authStore) getEmailCookie(w http.ResponseWriter, r *http.Request) (*emailCookie, error) {
	email := &emailCookie{}
	return email, s.cookieStore.Get(w, r, emailCookieName, email)
}

func (s *authStore) getSessionCookie(w http.ResponseWriter, r *http.Request) (*sessionCookie, error) {
	session := &sessionCookie{}
	return session, s.cookieStore.Get(w, r, sessionCookieName, session)
}

func (s *authStore) getRememberMeCookie(w http.ResponseWriter, r *http.Request) (*rememberMeCookie, error) {
	rememberMe := &rememberMeCookie{}
	return rememberMe, s.cookieStore.Get(w, r, rememberMeCookieName, rememberMe)
}

func (s *authStore) deleteEmailCookie(w http.ResponseWriter) {
	s.cookieStore.Delete(w, emailCookieName)
}

func (s *authStore) deleteSessionCookie(w http.ResponseWriter) {
	s.cookieStore.Delete(w, sessionCookieName)
}

func (s *authStore) deleteRememberMeCookie(w http.ResponseWriter) {
	s.cookieStore.Delete(w, rememberMeCookieName)
}

func (s *authStore) saveEmailCookie(w http.ResponseWriter, r *http.Request, emailVerificationCode string, expireTimeUTC time.Time) error {
	cookie := emailCookie{EmailVerificationCode: emailVerificationCode, ExpireTimeUTC: expireTimeUTC}
	return s.cookieStore.PutWithExpire(w, r, emailCookieName, emailExpireMins, &cookie)
}

func (s *authStore) saveSessionCookie(w http.ResponseWriter, r *http.Request, sessionID string, renewTimeUTC, expireTimeUTC time.Time) error {
	cookie := sessionCookie{SessionID: sessionID, RenewTimeUTC: renewTimeUTC, ExpireTimeUTC: expireTimeUTC}
	err := s.cookieStore.Put(w, r, sessionCookieName, &cookie)
	if err != nil {
		return newAuthError("Error saving session cookie", err)
	}
	return nil
}

func (s *authStore) saveRememberMeCookie(w http.ResponseWriter, r *http.Request, selector, token string, renewTimeUTC, expireTimeUTC time.Time) error {
	cookie := rememberMeCookie{Selector: selector, Token: token, RenewTimeUTC: renewTimeUTC, ExpireTimeUTC: expireTimeUTC}
	return s.cookieStore.Put(w, r, rememberMeCookieName, &cookie)
}

type registration struct {
	Email          string
	DestinationURL string
}

func getRegistration(r *http.Request) (*registration, error) {
	register := &registration{}
	return register, getJSON(r, register)
}

type emailVerificationCode struct {
	EmailVerificationCode string
}

func getVerificationCode(r *http.Request) (*emailVerificationCode, error) {
	verificationCode := &emailVerificationCode{}
	return verificationCode, getJSON(r, verificationCode)
}

type credentials struct {
	Email      string
	Password   string
	RememberMe bool
}

func getCredentials(r *http.Request) (*credentials, error) {
	credentials := &credentials{}
	return credentials, getJSON(r, credentials)
}

func generateThumbnail(filename string) (string, error) {
	newName, err := generateRandomString()
	if err != nil {
		return "", newLoggedError("Unable to create new filename", err)
	}
	var args = []string{
		"-s", "150",
		"-o", newName,
		filename,
	}

	var cmd *exec.Cmd
	path, _ := exec.LookPath("vipsthumbnail")
	cmd = exec.Command(path, args...)
	err = cmd.Run()
	if err != nil {
		return "", newLoggedError("Error running vipsthumbnail", err)
	}
	return newName, nil
}

type profile struct {
	FullName     string
	Organization string
	Password     string
	PicturePath  string
	MailQuota    int
	FileQuota    int
}

func getProfile(r *http.Request) (*profile, error) {
	profile := &profile{}
	r.ParseMultipartForm(32 << 20) // 32 MB file
	file, handler, err := r.FormFile("file")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	f, err := os.OpenFile(handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	io.Copy(f, file)

	// **************  TODO: change to generic way to get other parameters *******************

	// get quota. will be zero if not found
	mailQuota, _ := strconv.Atoi(r.FormValue("mailQuota"))
	fileQuota, _ := strconv.Atoi(r.FormValue("fileQuota"))
	profile.FullName = r.FormValue("fullName")
	profile.Organization = r.FormValue("Organization")
	profile.Password = r.FormValue("password")
	profile.PicturePath = handler.Filename
	profile.MailQuota = mailQuota
	profile.FileQuota = fileQuota

	return profile, nil
}

func getJSON(r *http.Request, result interface{}) error {
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, result)
}

func isValidEmail(email string) bool {
	return len(email) <= 254 && len(email) >= 6 && emailRegex.MatchString(email) == true
}

func substringAfter(source, find string) string {
	fromIndex := strings.Index(source, find)
	if fromIndex == -1 {
		return source
	}
	fromIndex += len(find)
	return source[fromIndex:]
}
