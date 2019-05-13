package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

var (
	emailCookieName      = "Email"
	sessionCookieName    = "Session"
	rememberMeCookieName = "RememberMe"
	userCookieName       = "User"
	emailRegex           = regexp.MustCompile(`^(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$`)
	errInvalidCSRF       = errors.New("Invalid CSRF token")
	errMissingCSRF       = errors.New("Missing CSRF token")
)

const (
	emailExpireMins                  = 60 * 24 * 365 // 1 year
	emailExpireDuration              = time.Duration(emailExpireMins) * time.Minute
	passwordResetEmailExpireMins     = 60 * 48 // 2 days
	passwordResetEmailExpireDuration = time.Duration(passwordResetEmailExpireMins) * time.Minute
	sessionRenewDuration             = 5 * time.Minute
	sessionExpireDuration            = time.Hour
	rememberMeRenewDuration          = time.Hour
	rememberMeExpireDuration         = time.Hour * 24 * 30 // 30 days
	passwordValidationMessage        = "Password must be at least 7 characters"
)

// AuthStorer interface provides the necessary functionality to get and store authentication information
type AuthStorer interface {
	GetSession(w http.ResponseWriter, r *http.Request) (*LoginSession, error)
	GetBasicAuth(w http.ResponseWriter, r *http.Request) (*LoginSession, error)
	OAuthLogin(w http.ResponseWriter, r *http.Request) (string, error)
	Login(w http.ResponseWriter, r *http.Request) (*LoginSession, error)
	Register(w http.ResponseWriter, r *http.Request, email string, templates TemplateNames, emailSubject string, info map[string]interface{}) error
	RequestPasswordReset(w http.ResponseWriter, r *http.Request, email string, templates TemplateNames, emailSubject string, info map[string]interface{}) error
	Logout(w http.ResponseWriter, r *http.Request) error
	CreateProfile(w http.ResponseWriter, r *http.Request) (*LoginSession, error)
	VerifyEmail(w http.ResponseWriter, r *http.Request, emailVerificationCode, templateName, emailSubject string) (string, *User, error)
	VerifyPasswordReset(w http.ResponseWriter, r *http.Request, emailVerificationCode string) (string, *User, error)
	CreateSecondaryEmail(w http.ResponseWriter, r *http.Request, templateName, emailSubject string) error
	SetPrimaryEmail(w http.ResponseWriter, r *http.Request, templateName, emailSubject string) error
	UpdatePassword(w http.ResponseWriter, r *http.Request) (*LoginSession, error)
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
	b           Backender
	mailer      Mailer
	cookieStore CookieStorer
}

// NewAuthStore is used to create an AuthStorer for most authentication needs
func NewAuthStore(b Backender, mailer Mailer, customPrefix, cookieDomain string, cookieKey []byte) AuthStorer {
	emailCookieName = customPrefix + "Email"
	sessionCookieName = customPrefix + "Session"
	rememberMeCookieName = customPrefix + "RememberMe"
	return &authStore{b, mailer, newCookieStore(cookieKey, cookieDomain)}
}

func (s *authStore) GetSession(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	b := s.b.Clone()
	defer b.Close()
	return s.getSession(w, r, b)
}

func (s *authStore) getSession(w http.ResponseWriter, r *http.Request, b Backender) (*LoginSession, error) {
	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken == "" {
		return nil, errMissingCSRF
	}
	cookie, err := s.getSessionCookie(w, r)
	if err != nil || cookie.SessionID == "" { // impossible to get the session if there is no cookie
		return nil, newAuthError("Session cookie not found", err)
	}
	sessionHash, err := decodeStringToHash(cookie.SessionID)
	if err != nil {
		return nil, newAuthError("Unable to decode session cookie", err)
	}

	session, err := b.GetSession(sessionHash)
	if err != nil {
		if err == errSessionNotFound {
			s.deleteSessionCookie(w)
		}
		return nil, newLoggedError("Failed to verify session", err)
	}
	if session.RenewTimeUTC.Before(time.Now().UTC()) || session.ExpireTimeUTC.Before(time.Now().UTC()) {
		if err := s.renewSession(w, r, b, cookie.SessionID, session); err != nil {
			return nil, err
		}
	}

	if session.CSRFToken != csrfToken {
		return nil, errInvalidCSRF
	}
	return session, nil
}

func (s *authStore) GetBasicAuth(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	b := s.b.Clone()
	defer b.Close()
	return s.getBasicAuth(w, r, b)
}

func (s *authStore) getBasicAuth(w http.ResponseWriter, r *http.Request, b Backender) (*LoginSession, error) {
	session, err := s.getSession(w, r, b)
	if err == nil {
		return session, nil
	}

	if email, password, ok := r.BasicAuth(); ok {
		session, err := s.login(w, r, b, email, password, false)
		if err != nil {
			return nil, err
		}
		return session, nil
	}
	return nil, newAuthError("Problem decoding credentials from basic auth", nil)
}

func (s *authStore) getRememberMe(w http.ResponseWriter, r *http.Request, b Backender) (*rememberMeSession, error) {
	cookie, err := s.getRememberMeCookie(w, r)
	if err != nil || cookie.Selector == "" { // impossible to get the remember Me if there is no cookie
		return nil, newAuthError("RememberMe cookie not found", err)
	}
	if cookie.ExpireTimeUTC.Before(time.Now().UTC()) {
		s.deleteRememberMeCookie(w)
		return nil, newAuthError("RememberMe cookie has expired", nil)
	}

	rememberMe, err := b.GetRememberMe(cookie.Selector)
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
		renewTimeUTC := time.Now().UTC().Add(rememberMeRenewDuration)
		err = b.UpdateRememberMe(cookie.Selector, renewTimeUTC)
		if err != nil {
			if err == errRememberMeNotFound {
				s.deleteRememberMeCookie(w)
			}
			return nil, newLoggedError("Unable to renew RememberMe", err)
		}
		rememberMe.RenewTimeUTC = renewTimeUTC
	}
	return rememberMe, nil
}

func (s *authStore) renewSession(w http.ResponseWriter, r *http.Request, b Backender, sessionID string, session *LoginSession) error {
	// expired so check for valid rememberMe for renewal
	if session.ExpireTimeUTC.Before(time.Now().UTC()) {
		r, err := s.getRememberMe(w, r, b)
		if err != nil {
			return newAuthError("Unable to renew session", err)
		}
		session.ExpireTimeUTC = time.Now().UTC().Add(sessionExpireDuration) // renew for sessionExpireDuration like we just typed in password again
		if session.ExpireTimeUTC.After(r.ExpireTimeUTC) {                   // don't exceed rememberMe expiration time
			session.ExpireTimeUTC = r.ExpireTimeUTC
		}
	}

	session.RenewTimeUTC = time.Now().UTC().Add(sessionRenewDuration)
	if session.RenewTimeUTC.After(session.ExpireTimeUTC) {
		session.RenewTimeUTC = session.ExpireTimeUTC
	}

	err := b.UpdateSession(session.SessionHash, session.RenewTimeUTC, session.ExpireTimeUTC)
	if err != nil {
		return newLoggedError("Problem updating session cookie", err)
	}
	err = s.saveSessionCookie(w, r, sessionID, session.RenewTimeUTC, session.ExpireTimeUTC)
	if err != nil {
		return newLoggedError("Problem updating user cookie", err)
	}
	return s.saveUserCookie(w, r, session.Info)
}

/******************************** Logout ***********************************************/
func (s *authStore) Logout(w http.ResponseWriter, r *http.Request) error {
	b := s.b.Clone()
	defer b.Close()
	session, err := s.getSession(w, r, b)
	s.deleteSessionCookie(w)
	if err != nil {
		return err
	}
	return b.DeleteSession(session.SessionHash)
}

/******************************** Login ***********************************************/
func (s *authStore) Login(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	credentials, err := getCredentials(r)
	if err != nil {
		return nil, newAuthError("Unable to get credentials", err)
	}
	b := s.b.Clone()
	defer b.Close()
	session, err := s.login(w, r, b, credentials.Email, credentials.Password, credentials.RememberMe)
	if err != nil {
		return nil, err
	}
	return session, err
}

func (s *authStore) login(w http.ResponseWriter, r *http.Request, b Backender, email, password string, rememberMe bool) (*LoginSession, error) {
	if !isValidEmail(email) {
		return nil, newAuthError("Please enter a valid email address.", nil)
	}
	if !isValidPassword(password) {
		return nil, newAuthError(passwordValidationMessage, nil)
	}

	// add in check for DDOS attack. Slow down or lock out checks for same account
	// or same IP with multiple failed attempts
	login, err := b.LoginAndGetUser(email, password)
	if err != nil {
		return nil, newLoggedError("Invalid username or password", err)
	}

	return s.createSession(w, r, b, login.UserID, email, login.Info, rememberMe)
}

func (s *authStore) OAuthLogin(w http.ResponseWriter, r *http.Request) (string, error) {
	email, info, err := getOAuthCredentials(r)
	if err != nil {
		return "", err
	}
	b := s.b.Clone()
	defer b.Close()
	return s.oauthLogin(w, r, b, email, info)
}

func (s *authStore) oauthLogin(w http.ResponseWriter, r *http.Request, b Backender, email string, info map[string]interface{}) (string, error) {
	user, err := b.GetUser(email)
	if user == nil || err != nil {
		user, err = b.AddUserFull(email, "", info)
		if err != nil {
			return "", newLoggedError("Unable to create login", err)
		}
	}

	session, err := s.createSession(w, r, b, user.UserID, email, info, false)
	if err != nil {
		return "", err
	}
	return session.CSRFToken, nil
}

func getOAuthCredentials(r *http.Request) (string, map[string]interface{}, error) {
	var email, email2 string
	info := make(map[string]interface{})
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", nil, fmt.Errorf("No authorization found")
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", nil, fmt.Errorf("Authorization header format must be Bearer {token}")
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
		info["fullname"] = fmt.Sprintf("%v", claims["name"])
		email = fmt.Sprintf("%v", claims["unique_name"])
		fmt.Println("unique_name:", email)
		email2 = fmt.Sprintf("%v", claims["email"])
		fmt.Println("email:", email2)
		if email == "" || info["fullname"] == "" {
			return "", nil, fmt.Errorf("expected email and fullname")
		}
	}
	return email, info, nil
}

func (s *authStore) createSession(w http.ResponseWriter, r *http.Request, b Backender, userID, email string, info map[string]interface{}, rememberMe bool) (*LoginSession, error) {
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

	csrfToken, err := generateRandomString()
	if err != nil {
		return nil, newLoggedError("Problem generating csrf token", nil)
	}

	session, err := b.CreateSession(userID, email, info, sessionHash, csrfToken, time.Now().UTC().Add(sessionRenewDuration), time.Now().UTC().Add(sessionExpireDuration))
	if err != nil {
		return nil, newLoggedError("Unable to create new session", err)
	}

	var remember *rememberMeSession
	if rememberMe {
		remember, err = b.CreateRememberMe(userID, email, selector, tokenHash, time.Now().UTC().Add(rememberMeRenewDuration), time.Now().UTC().Add(rememberMeExpireDuration))
		if err != nil {
			return nil, newLoggedError("Unable to create rememberMe session", err)
		}
	}

	sessionCookie, err := s.getSessionCookie(w, r)
	if err == nil && sessionCookie.SessionID != "" {
		oldSessionHash, err := decodeStringToHash(sessionCookie.SessionID)
		if err == nil {
			b.DeleteSession(oldSessionHash)
		}
	}

	rememberCookie, err := s.getRememberMeCookie(w, r)
	if err == nil && rememberCookie.Selector != "" {
		b.DeleteRememberMe(rememberCookie.Selector)
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
	return session, s.saveUserCookie(w, r, session.Info)
}

func isValidPassword(password string) bool {
	return len(password) >= 7
}

type sendParams struct {
	VerificationCode string
	Email            string
	RefererBaseURL   string
	Info             map[string]interface{}
}

// TemplateNames contains the names of the html email templates to be used on Success and/or Failure conditions
type TemplateNames struct {
	Success string
	Failure string
}

func (s *authStore) RequestPasswordReset(w http.ResponseWriter, r *http.Request, email string, templates TemplateNames, emailSubject string, info map[string]interface{}) error {
	b := s.b.Clone()
	defer b.Close()
	return s.requestPasswordReset(r, b, email, templates, emailSubject, info)
}

func (s *authStore) requestPasswordReset(r *http.Request, b Backender, email string, templates TemplateNames, emailSubject string, info map[string]interface{}) error {
	if !isValidEmail(email) {
		return newAuthError("Invalid email", nil)
	}

	u, err := b.GetUser(email)
	if err != nil {
		if err := s.mailer.SendMessage(email, templates.Failure, "Attempted Password Reset", &sendParams{RefererBaseURL: getBaseURL(r.Referer()), Info: info}); err != nil {
			return newLoggedError("An email has been sent to the user with instructions on how to reset their password", err)
		}
		return nil // user does not exist, send success message anyway to prevent fishing for user data. Email owner will be notified of attempt
	}

	if info != nil {
		for key, value := range info {
			u.Info[key] = value
		}
	}

	verifyCode, err := s.addEmailSession(b, u.UserID, email, u.Info)
	if err != nil {
		return newLoggedError("An email has been sent to the user with instructions on how to reset their password", err)
	}

	code := verifyCode[:len(verifyCode)-1] // drop the "=" at the end of the code since it makes it look like a querystring
	if err := s.mailer.SendMessage(email, templates.Success, emailSubject, &sendParams{code, email, getBaseURL(r.Referer()), info}); err != nil {
		return newLoggedError("An email has been sent to the user with instructions on how to reset their password", err)
	}

	return nil
}

func (s *authStore) Register(w http.ResponseWriter, r *http.Request, email string, templates TemplateNames, emailSubject string, info map[string]interface{}) error {
	b := s.b.Clone()
	defer b.Close()
	return s.register(r, b, email, templates, emailSubject, info)
}

func (s *authStore) register(r *http.Request, b Backender, email string, templates TemplateNames, emailSubject string, info map[string]interface{}) error {
	if !isValidEmail(email) {
		return newAuthError("Invalid email", nil)
	}

	user, err := b.GetUser(email)
	if user != nil {
		return newAuthError("User already registered", err)
	}

	verifyCode, err := s.addEmailSession(b, "", email, info)
	if err != nil {
		return newLoggedError("Unable to save user", err)
	}

	code := verifyCode[:len(verifyCode)-1] // drop the "=" at the end of the code since it makes it look like a querystring
	if err := s.mailer.SendMessage(email, templates.Success, emailSubject, &sendParams{code, email, getBaseURL(r.Referer()), info}); err != nil {
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

func (s *authStore) addEmailSession(b Backender, userID, email string, info map[string]interface{}) (string, error) {
	verifyCode, verifyHash, err := generateStringAndHash()
	if err != nil {
		return "", newLoggedError("Problem generating email confirmation code", err)
	}

	csrfToken, err := generateRandomString()
	if err != nil {
		return "", newLoggedError("Problem generating csrf token", err)
	}

	err = b.CreateEmailSession(userID, email, info, verifyHash, csrfToken)
	if err != nil {
		return "", newLoggedError("Problem adding user to database", err)
	}

	return verifyCode, nil
}

func (s *authStore) CreateProfile(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	profile, err := getProfile(r)
	if err != nil {
		return nil, newAuthError("Unable to get profile information from form", err)
	}
	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken == "" {
		return nil, errMissingCSRF
	}
	b := s.b.Clone()
	defer b.Close()
	return s.createProfile(w, r, b, csrfToken, profile.Password)
}

func (s *authStore) createProfile(w http.ResponseWriter, r *http.Request, b Backender, csrfToken, password string) (*LoginSession, error) {
	emailCookie, err := s.getEmailCookie(w, r)
	if err != nil || emailCookie.EmailVerificationCode == "" {
		return nil, newLoggedError("Unable to get email verification cookie", err)
	}

	emailVerifyHash, err := decodeStringToHash(emailCookie.EmailVerificationCode) // base64 decode and hash
	if err != nil {
		return nil, newLoggedError("Invalid email verification cookie", err)
	}

	session, err := b.GetEmailSession(emailVerifyHash)
	if err != nil {
		return nil, newLoggedError("Invalid email verification", err)
	}
	if session.CSRFToken != csrfToken {
		return nil, errInvalidCSRF
	}

	err = b.UpdateUser(session.UserID, password, session.Info)
	if err != nil {
		return nil, newLoggedError("Unable to update user", err)
	}

	err = b.DeleteEmailSession(session.EmailVerifyHash)
	if err != nil {
		return nil, newLoggedError("Error while creating profile", err)
	}

	ls, err := s.createSession(w, r, b, session.UserID, session.Email, session.Info, false)
	if err != nil {
		return nil, err
	}

	s.deleteEmailCookie(w)
	return ls, nil
}

// move to sessionStore
func (s *authStore) VerifyEmail(w http.ResponseWriter, r *http.Request, emailVerificationCode, templateName, emailSubject string) (string, *User, error) {
	b := s.b.Clone()
	defer b.Close()
	return s.verifyEmail(w, r, b, emailVerificationCode, templateName, emailSubject)
}

func (s *authStore) verifyEmail(w http.ResponseWriter, r *http.Request, b Backender, emailVerificationCode, templateName, emailSubject string) (string, *User, error) {
	if !strings.HasSuffix(emailVerificationCode, "=") { // add back the "=" then decode
		emailVerificationCode = emailVerificationCode + "="
	}
	emailVerifyHash, err := decodeStringToHash(emailVerificationCode)
	if err != nil {
		return "", nil, newLoggedError("Invalid verification code", err)
	}

	session, err := b.GetEmailSession(emailVerifyHash)
	if err != nil {
		return "", nil, newLoggedError("Failed to verify email", err)
	}

	userID, err := b.AddUser(session.Email, session.Info)
	if err != nil {
		user, err := b.GetUser(session.Email)
		if err != nil {
			return "", nil, newLoggedError("Failed to get user in database", err)
		}
		userID = user.UserID
	}

	err = b.UpdateEmailSession(emailVerifyHash, userID)
	if err != nil {
		return "", nil, newLoggedError("Failed to update email session", err)
	}

	err = s.saveEmailCookie(w, r, emailVerificationCode, time.Now().UTC().Add(emailExpireDuration))
	if err != nil {
		return "", nil, newLoggedError("Failed to save email cookie", err)
	}

	err = s.mailer.SendMessage(session.Email, templateName, emailSubject, &sendParams{"", session.Email, "", session.Info})
	if err != nil {
		return "", nil, newLoggedError("Failed to send welcome email", err)
	}
	return session.CSRFToken, &User{Email: session.Email, Info: session.Info}, nil
}

func (s *authStore) VerifyPasswordReset(w http.ResponseWriter, r *http.Request, emailVerificationCode string) (string, *User, error) {
	b := s.b.Clone()
	defer b.Close()
	return s.verifyPasswordReset(w, r, b, emailVerificationCode)
}

func (s *authStore) verifyPasswordReset(w http.ResponseWriter, r *http.Request, b Backender, emailVerificationCode string) (string, *User, error) {
	if !strings.HasSuffix(emailVerificationCode, "=") { // add back the "=" then decode
		emailVerificationCode = emailVerificationCode + "="
	}
	emailVerifyHash, err := decodeStringToHash(emailVerificationCode)
	if err != nil {
		return "", nil, newLoggedError("Invalid verification code", err)
	}

	session, err := b.GetEmailSession(emailVerifyHash)
	if err != nil {
		return "", nil, newLoggedError("Failed to verify email", err)
	}

	err = s.saveEmailCookie(w, r, emailVerificationCode, time.Now().UTC().Add(passwordResetEmailExpireDuration))
	if err != nil {
		return "", nil, newLoggedError("Failed to save email cookie", err)
	}

	return session.CSRFToken, &User{Email: session.Email, Info: session.Info}, nil
}

func (s *authStore) CreateSecondaryEmail(w http.ResponseWriter, r *http.Request, templateName, emailSubject string) error {
	// steps to set new primary email address:
	// 1. create new secondary email (this step)
	// 2. send verification email
	// 3. user verifies email
	// 4. user sets email to primary email
	return nil
}

func (s *authStore) SetPrimaryEmail(w http.ResponseWriter, r *http.Request, templateName, emailSubject string) error {
	// be sure to require current email and password (i.e. require login) to change primary email
	// invalidate old sessions?
	return nil
}

func (s *authStore) UpdatePassword(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	profile, err := getProfile(r)
	if err != nil {
		return nil, newAuthError("Unable to get profile information from form", err)
	}
	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken == "" {
		return nil, errMissingCSRF
	}
	b := s.b.Clone()
	defer b.Close()
	return s.updatePassword(w, r, b, csrfToken, profile.Password)
}

func (s *authStore) updatePassword(w http.ResponseWriter, r *http.Request, b Backender, csrfToken, password string) (*LoginSession, error) {
	emailCookie, err := s.getEmailCookie(w, r)
	if err != nil || emailCookie.EmailVerificationCode == "" {
		return nil, newLoggedError("Unable to get email verification cookie", err)
	}

	emailVerifyHash, err := decodeStringToHash(emailCookie.EmailVerificationCode) // base64 decode and hash
	if err != nil {
		return nil, newLoggedError("Invalid email verification cookie", err)
	}

	session, err := b.GetEmailSession(emailVerifyHash)
	if err != nil {
		return nil, newLoggedError("Invalid email verification", err)
	}
	if session.CSRFToken != csrfToken {
		return nil, errInvalidCSRF
	}

	err = b.DeleteEmailSession(session.EmailVerifyHash)
	if err != nil {
		return nil, newLoggedError("Error while updating password", err)
	}

	err = b.DeleteSessions(session.Email)
	if err != nil {
		return nil, newLoggedError("Error while deleting login sessions", err)
	}

	err = b.DeleteRememberMes(session.Email)
	if err != nil {
		return nil, newLoggedError("Error while deleting remember me sessions", err)
	}

	err = b.UpdateUser(session.UserID, password, session.Info)
	if err != nil {
		return nil, newLoggedError("Unable to update password", err)
	}

	ls, err := s.createSession(w, r, b, session.UserID, session.Email, nil, false)
	if err != nil {
		return nil, err
	}

	s.deleteEmailCookie(w)
	if ls.Info == nil {
		ls.Info = make(map[string]interface{})
	}
	ls.Info["destinationURL"] = GetInfoString(session.Info, "destinationURL")
	return ls, nil
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
	s.cookieStore.Delete(w, userCookieName)
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

func (s *authStore) saveUserCookie(w http.ResponseWriter, r *http.Request, info map[string]interface{}) error {
	return s.cookieStore.PutUnsecured(w, r, userCookieName, info)
}

func (s *authStore) saveRememberMeCookie(w http.ResponseWriter, r *http.Request, selector, token string, renewTimeUTC, expireTimeUTC time.Time) error {
	cookie := rememberMeCookie{Selector: selector, Token: token, RenewTimeUTC: renewTimeUTC, ExpireTimeUTC: expireTimeUTC}
	return s.cookieStore.Put(w, r, rememberMeCookieName, &cookie)
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
	Password string
	Info     map[string]interface{}
}

func getProfile(r *http.Request) (*profile, error) {
	profile := &profile{Info: make(map[string]interface{})}
	r.ParseMultipartForm(32 << 20) // 32 MB file

	file, handler, err := r.FormFile("file")
	if err == nil { // received the file, so save it
		defer file.Close()

		f, err := os.OpenFile(handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		io.Copy(f, file)
		profile.Info["filename"] = handler.Filename
	}

	for key := range r.Form { // save form values
		if key == "password" {
			profile.Password = r.FormValue(key)
		} else {
			profile.Info[key] = r.FormValue(key)
		}
	}

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
