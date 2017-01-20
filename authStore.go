package main

import (
	"encoding/json"
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

type authStorer interface {
	GetSession() (*loginSession, error)
	GetBasicAuth() (*loginSession, error)
	Login() error
	Register() error
	CreateProfile() error
	VerifyEmail() error
	UpdateEmail() error
	UpdatePassword() error
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
	backend     backender
	mailer      mailer
	cookieStore cookieStorer
	r           *http.Request
}

func newAuthStore(b backender, mailer mailer, w http.ResponseWriter, r *http.Request, customPrefix string, cookieKey []byte, secureOnlyCookie bool) authStorer {
	emailCookieName = customPrefix + "Email"
	sessionCookieName = customPrefix + "Session"
	rememberMeCookieName = customPrefix + "RememberMe"
	return &authStore{b, mailer, newCookieStore(w, r, cookieKey, secureOnlyCookie), r}
}

func (s *authStore) GetSession() (*loginSession, error) {
	cookie, err := s.getSessionCookie()
	if err != nil || cookie.SessionID == "" { // impossible to get the session if there is no cookie
		return nil, newAuthError("Session cookie not found", err)
	}
	sessionHash, err := decodeStringToHash(cookie.SessionID)
	if err != nil {
		return nil, newAuthError("Unable to decode session cookie", err)
	}

	if cookie.RenewTimeUTC.Before(time.Now().UTC()) || cookie.ExpireTimeUTC.Before(time.Now().UTC()) {
		return s.renewSession(cookie.SessionID, sessionHash, &cookie.RenewTimeUTC, &cookie.ExpireTimeUTC)
	}

	session, err := s.backend.GetSession(sessionHash)
	if err != nil {
		if err == errSessionNotFound {
			s.deleteSessionCookie()
		}
		return nil, newLoggedError("Failed to verify session", err)
	}
	return session, nil
}

func (s *authStore) GetBasicAuth() (*loginSession, error) {
	session, err := s.GetSession()
	if err == nil {
		return session, nil
	}

	if email, password, ok := s.r.BasicAuth(); ok {
		session, err := s.login(email, password, false)
		if err != nil {
			return nil, err
		}
		return session, nil
	}
	return nil, newAuthError("Problem decoding credentials from basic auth", nil)
}

func (s *authStore) getRememberMe() (*rememberMeSession, error) {
	cookie, err := s.getRememberMeCookie()
	if err != nil || cookie.Selector == "" { // impossible to get the remember Me if there is no cookie
		return nil, newAuthError("RememberMe cookie not found", err)
	}
	if cookie.ExpireTimeUTC.Before(time.Now().UTC()) {
		s.deleteRememberMeCookie()
		return nil, newAuthError("RememberMe cookie has expired", nil)
	}

	rememberMe, err := s.backend.GetRememberMe(cookie.Selector)
	if err != nil {
		if err == errRememberMeNotFound {
			s.deleteRememberMeCookie()
		}
		return nil, newLoggedError("Unable to find matching RememberMe in DB", err)
	}
	if !encodedHashEquals(cookie.Token, rememberMe.TokenHash) {
		s.deleteRememberMeCookie()
		return nil, newLoggedError("RememberMe cookie doesn't match backend token", nil)
	}
	if rememberMe.RenewTimeUTC.Before(time.Now().UTC()) {
		rememberMe, err = s.backend.RenewRememberMe(cookie.Selector, time.Now().UTC().Add(rememberMeRenewDuration))
		if err != nil {
			if err == errRememberMeNotFound {
				s.deleteRememberMeCookie()
			}
			return nil, newLoggedError("Unable to renew RememberMe", err)
		}
	}
	return rememberMe, nil
}

func (s *authStore) renewSession(sessionID, sessionHash string, renewTimeUTC, expireTimeUTC *time.Time) (*loginSession, error) {
	if renewTimeUTC.Before(time.Now().UTC()) && expireTimeUTC.After(time.Now().UTC()) {
		session, err := s.backend.RenewSession(sessionHash, time.Now().UTC().Add(sessionRenewDuration))
		if err != nil {
			return nil, newLoggedError("Unable to renew session", err)
		}

		if err = s.saveSessionCookie(sessionID, session.RenewTimeUTC, session.ExpireTimeUTC); err != nil {
			return nil, err
		}
		return session, nil
	}

	_, err := s.getRememberMe()
	if err != nil {
		return nil, newAuthError("Unable to renew session", err)
	}

	session, err := s.backend.RenewSession(sessionHash, time.Now().UTC().Add(sessionRenewDuration))
	if err != nil {
		if err == errSessionNotFound {
			s.deleteSessionCookie()
		}
		return nil, newLoggedError("Problem renewing session", err)
	}

	if err = s.saveSessionCookie(sessionID, session.RenewTimeUTC, session.ExpireTimeUTC); err != nil {
		return nil, err
	}
	return session, nil
}

/******************************** Login ***********************************************/
func (s *authStore) Login() error {
	credentials, err := getCredentials(s.r)
	if err != nil {
		return newAuthError("Unable to get credentials", err)
	}
	_, err = s.login(credentials.Email, credentials.Password, credentials.RememberMe)
	return err
}

func (s *authStore) login(email, password string, rememberMe bool) (*loginSession, error) {
	if !isValidEmail(email) {
		return nil, newAuthError("Please enter a valid email address.", nil)
	}
	if !isValidPassword(password) {
		return nil, newAuthError(passwordValidationMessage, nil)
	}

	// add in check for DDOS attack. Slow down or lock out checks for same account
	// or same IP with multiple failed attempts
	login, err := s.backend.GetLogin(email, loginProviderDefaultName)
	if err != nil {
		return nil, newLoggedError("Invalid username or password", err)
	}

	if err := cryptoHashEquals(password, login.ProviderKey); err != nil {
		return nil, newLoggedError("Invalid username or password", err)
	}
	if err != nil {
		return nil, err
	}
	return s.createSession(email, rememberMe)
}

func (s *authStore) createSession(email string, rememberMe bool) (*loginSession, error) {
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

	session, remember, err := s.backend.CreateSession(email, sessionHash, time.Now().UTC().Add(sessionRenewDuration), time.Now().UTC().Add(sessionExpireDuration), rememberMe, selector, tokenHash, time.Now().UTC().Add(rememberMeRenewDuration), time.Now().UTC().Add(rememberMeExpireDuration))
	if err != nil {
		return nil, newLoggedError("Unable to create new session", err)
	}

	sessionCookie, err := s.getSessionCookie()
	if err == nil {
		oldSessionHash, err := decodeStringToHash(sessionCookie.SessionID)
		if err == nil {
			s.backend.InvalidateSession(oldSessionHash)
		}
	}

	rememberCookie, err := s.getRememberMeCookie()
	if err == nil {
		s.backend.InvalidateRememberMe(rememberCookie.Selector)
		s.deleteRememberMeCookie()
	}

	if rememberMe {
		err := s.saveRememberMeCookie(selector, token, remember.RenewTimeUTC, remember.ExpireTimeUTC)
		if err != nil {
			return nil, newAuthError("Unable to save rememberMe cookie", err)
		}
	}
	err = s.saveSessionCookie(sessionID, session.RenewTimeUTC, session.ExpireTimeUTC)
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

func (s *authStore) Register() error {
	registration, err := getRegistration(s.r)
	if err != nil {
		return newAuthError("Unable to get email", err)
	}
	return s.register(registration.Email)
}

func (s *authStore) register(email string) error {
	if !isValidEmail(email) {
		return newAuthError("Invalid email", nil)
	}

	user, err := s.backend.GetUser(email)
	if user != nil {
		return newAuthError("User already registered", err)
	}

	verifyCode, err := s.addEmailSession(email)
	if err != nil {
		return newLoggedError("Unable to save user", err)
	}

	code := verifyCode[:len(verifyCode)-1] // drop the "=" at the end of the code since it makes it look like a querystring
	if err := s.mailer.SendVerify(email, &sendVerifyParams{code, email, getBaseURL(s.r.Referer())}); err != nil {
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

func (s *authStore) addEmailSession(email string) (string, error) {
	verifyCode, verifyHash, err := generateStringAndHash()
	if err != nil {
		return "", newLoggedError("Problem generating email confirmation code", err)
	}

	err = s.backend.CreateEmailSession(email, verifyHash)
	if err != nil {
		return "", newLoggedError("Problem adding user to database", err)
	}

	return verifyCode, nil
}

func (s *authStore) CreateProfile() error {
	profile, err := getProfile(s.r)
	if err != nil {
		return newAuthError("Unable to get profile information from form", err)
	}
	return s.createProfile(profile.FullName, profile.Organization, profile.Password, profile.PicturePath, profile.MailQuota, profile.FileQuota)
}

func (s *authStore) createProfile(fullName, organization, password, picturePath string, mailQuota, fileQuota int) error {
	emailCookie, err := s.getEmailCookie()
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

	err = s.backend.UpdateUser(session.Email, fullName, organization, picturePath)
	if err != nil {
		return newLoggedError("Unable to update user", err)
	}

	err = s.backend.DeleteEmailSession(session.EmailVerifyHash)
	if err != nil {
		return newLoggedError("Error verifying email", err)
	}

	_, err = s.createLogin(session.Email, fullName, password, mailQuota, fileQuota)
	if err != nil {
		return newLoggedError("Unable to create login", err)
	}

	_, err = s.createSession(session.Email, false)
	if err != nil {
		return err
	}

	s.deleteEmailCookie()
	return nil
}

/****************  TODO: send 0 for UID and GID numbers and empty quotas if mailQuota and fileQuota are 0 **********************/
func (s *authStore) createLogin(email, fullName, password string, mailQuota, fileQuota int) (*userLogin, error) {
	passwordHash, err := cryptoHash(password)
	if err != nil {
		return nil, newLoggedError("Unable to create login", err)
	}

	uidNumber := 10000 // vmail user
	gidNumber := 10000 // vmail user
	homeDirectory := "/home"
	mQuota := fmt.Sprintf("%dGB", mailQuota)
	fQuota := fmt.Sprintf("%dGB", fileQuota)
	login, err := s.backend.CreateLogin(email, passwordHash, fullName, homeDirectory, uidNumber, gidNumber, mQuota, fQuota)
	if err != nil {
		return nil, newLoggedError("Unable to create login", err)
	}
	return login, err
}

// move to sessionStore
func (s *authStore) VerifyEmail() error {
	verify, err := getVerificationCode(s.r)
	if err != nil {
		return newAuthError("Unable to get verification email from JSON", err)
	}
	return s.verifyEmail(verify.EmailVerificationCode)
}

func (s *authStore) verifyEmail(emailVerificationCode string) error {
	if !strings.HasSuffix(emailVerificationCode, "=") { // add back the "=" then decode
		emailVerificationCode = emailVerificationCode + "="
	}
	emailVerifyHash, err := decodeStringToHash(emailVerificationCode)
	if err != nil {
		return newLoggedError("Invalid verification code", err)
	}

	session, err := s.backend.GetEmailSession(emailVerifyHash)
	if err != nil {
		return newLoggedError("Failed to verify email", err)
	}

	err = s.backend.AddUser(session.Email)
	if err != nil {
		return newLoggedError("Failed to create new user in database", err)
	}

	err = s.saveEmailCookie(emailVerificationCode, time.Now().UTC().Add(emailExpireDuration))
	if err != nil {
		return newLoggedError("Failed to save email cookie", err)
	}

	err = s.mailer.SendWelcome(session.Email, nil)
	if err != nil {
		return newLoggedError("Failed to send welcome email", err)
	}
	return nil
}

func (s *authStore) UpdateEmail() error { return nil }

func (s *authStore) UpdatePassword() error {
	return nil
}

func (s *authStore) getEmailCookie() (*emailCookie, error) {
	email := &emailCookie{}
	return email, s.cookieStore.Get(emailCookieName, email)
}

func (s *authStore) getSessionCookie() (*sessionCookie, error) {
	session := &sessionCookie{}
	return session, s.cookieStore.Get(sessionCookieName, session)
}

func (s *authStore) getRememberMeCookie() (*rememberMeCookie, error) {
	rememberMe := &rememberMeCookie{}
	return rememberMe, s.cookieStore.Get(rememberMeCookieName, rememberMe)
}

func (s *authStore) deleteEmailCookie() {
	s.cookieStore.Delete(emailCookieName)
}

func (s *authStore) deleteSessionCookie() {
	s.cookieStore.Delete(sessionCookieName)
}

func (s *authStore) deleteRememberMeCookie() {
	s.cookieStore.Delete(rememberMeCookieName)
}

func (s *authStore) saveEmailCookie(emailVerificationCode string, expireTimeUTC time.Time) error {
	cookie := emailCookie{EmailVerificationCode: emailVerificationCode, ExpireTimeUTC: expireTimeUTC}
	return s.cookieStore.PutWithExpire(emailCookieName, emailExpireMins, &cookie)
}

func (s *authStore) saveSessionCookie(sessionID string, renewTimeUTC, expireTimeUTC time.Time) error {
	cookie := sessionCookie{SessionID: sessionID, RenewTimeUTC: renewTimeUTC, ExpireTimeUTC: expireTimeUTC}
	err := s.cookieStore.Put(sessionCookieName, &cookie)
	if err != nil {
		return newAuthError("Error saving session cookie", err)
	}
	return nil
}

func (s *authStore) saveRememberMeCookie(selector, token string, renewTimeUTC, expireTimeUTC time.Time) error {
	cookie := rememberMeCookie{Selector: selector, Token: token, RenewTimeUTC: renewTimeUTC, ExpireTimeUTC: expireTimeUTC}
	return s.cookieStore.Put(rememberMeCookieName, &cookie)
}

type registration struct {
	Email string
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
