package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type AuthStorer interface {
	GetSession() (*UserLoginSession, error)
	GetBasicAuth() (*UserLoginSession, error)
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

type authStore struct {
	backend      BackendQuerier
	sessionStore SessionStorer
	mailer       Mailer
	cookieStore  CookieStorer
	r            *http.Request
}

var emailRegex = regexp.MustCompile(`^(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$`)

func NewAuthStore(backend BackendQuerier, mailer Mailer, w http.ResponseWriter, r *http.Request, cookieKey []byte, cookiePrefix string, secureOnlyCookie bool) AuthStorer {
	sessionStore := NewSessionStore(backend, w, r, cookieKey, cookiePrefix, secureOnlyCookie)
	return &authStore{backend, sessionStore, mailer, NewCookieStore(w, r, cookieKey, secureOnlyCookie), r}
}

func (s *authStore) GetSession() (*UserLoginSession, error) {
	return s.sessionStore.GetSession()
}

func (s *authStore) GetBasicAuth() (*UserLoginSession, error) {
	session, err := s.GetSession()
	if err != nil {
		if email, password, ok := s.r.BasicAuth(); ok {
			session, err = s.login(email, password, false)
			if err != nil {
				return nil, newLoggedError("Unable to login with provided credentials", err)
			}
		} else {
			return nil, newAuthError("Problem decoding credentials from basic auth", nil)
		}
	}
	return session, nil
}

func (s *authStore) Login() error {
	credentials, err := getCredentials(s.r)
	if err != nil {
		return newAuthError("Unable to get credentials", err)
	}
	_, err = s.login(credentials.Email, credentials.Password, credentials.RememberMe)
	return err
}

func (s *authStore) login(email, password string, rememberMe bool) (*UserLoginSession, error) {
	if !isValidEmail(email) {
		return nil, newAuthError("Please enter a valid email address.", nil)
	}
	if !isValidPassword(password) {
		return nil, newAuthError(passwordValidationMessage, nil)
	}

	login, err := s.backend.GetLogin(email, loginProviderDefaultName)
	if err != nil {
		return nil, newLoggedError("Invalid username or password", err)
	}

	decoded, _ := decodeFromString(login.ProviderKey)
	if !hashEquals([]byte(password), decoded) {
		return nil, newLoggedError("Invalid username or password", nil)
	}

	return s.sessionStore.CreateSession(login.LoginID, login.UserID, rememberMe)
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

	emailConfirmCode, err := s.addUser(email)
	if err != nil {
		return newLoggedError("Unable to save user", err)
	}

	code := emailConfirmCode[:len(emailConfirmCode)-1] // drop the "=" at the end of the code since it makes it look like a querystring
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

func (s *authStore) addUser(email string) (string, error) {
	emailConfirmCode, emailConfimHash, err := generateStringAndHash()
	if err != nil {
		return "", newLoggedError("Problem generating email confirmation code", err)
	}

	err = s.backend.AddUser(email, emailConfimHash)
	if err != nil {
		return "", newLoggedError("Problem adding user to database", err)
	}
	return emailConfirmCode, nil
}

func (s *authStore) CreateProfile() error {
	profile, err := getProfile(s.r)
	if err != nil {
		return newAuthError("Unable to get profile information from form", err)
	}
	return s.createProfile(profile.FullName, profile.Organization, profile.Password, profile.PicturePath)
}

func (s *authStore) createProfile(fullName, organization, password, picturePath string) error {
	emailCookie, err := s.getEmailCookie()
	if err != nil || emailCookie.EmailVerificationCode == "" {
		return newLoggedError("Unable to get email verification cookie", err)
	}

	emailVerifyHash, err := decodeStringToHash(emailCookie.EmailVerificationCode) // base64 decode and hash
	if err != nil {
		return newLoggedError("Invalid email verification cookie", err)
	}

	passwordHash := encodeToString(hash([]byte(password)))
	login, err := s.backend.CreateLogin(emailVerifyHash, passwordHash, fullName, organization, picturePath)
	if err != nil {
		return newLoggedError("Unable to create profile", err)
	}

	_, err = s.sessionStore.CreateSession(login.LoginID, login.UserID, false)
	if err != nil {
		return err
	}

	s.deleteEmailCookie()
	return nil
}

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

	email, err := s.backend.VerifyEmail(emailVerifyHash)
	if err != nil {
		return newLoggedError("Failed to verify email", err)
	}

	err = s.saveEmailCookie(emailVerificationCode, time.Now().UTC().Add(emailExpireDuration))
	if err != nil {
		return newLoggedError("Failed to save email cookie", err)
	}

	err = s.mailer.SendWelcome(email, nil)
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

func (s *authStore) deleteEmailCookie() {
	s.cookieStore.Delete(emailCookieName)
}

func (s *authStore) saveEmailCookie(emailVerificationCode string, expireTimeUTC time.Time) error {
	cookie := emailCookie{EmailVerificationCode: emailVerificationCode, ExpireTimeUTC: expireTimeUTC}
	return s.cookieStore.PutWithExpire(emailCookieName, emailExpireMins, &cookie)
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

	profile.FullName = r.FormValue("fullName")
	profile.Organization = r.FormValue("Organization")
	profile.Password = r.FormValue("password")
	profile.PicturePath = handler.Filename

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

const passwordValidationMessage string = "Password must be between 7 and 20 characters"

func isValidPassword(password string) bool {
	return len(password) >= 7 && len(password) <= 20
}

func isValidEmail(email string) bool {
	return len(email) <= 254 && len(email) >= 6 && emailRegex.MatchString(email) == true
}

func decodeStringToHash(token string) (string, error) {
	data, err := decodeFromString(token)
	if err != nil {
		return "", err
	}
	return encodeToString(hash(data)), nil
}

func decodeFromString(token string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(token)
}

func encodeToString(bytes []byte) string {
	return base64.URLEncoding.EncodeToString(bytes)
}

func generateSelectorTokenAndHash() (string, string, string, error) {
	var selector, token, tokenHash string
	selector, err := generateRandomString()
	if err != nil {
		return "", "", "", newLoggedError("Unable to generate rememberMe selector", err)
	}
	token, tokenHash, err = generateStringAndHash()
	if err != nil {
		return "", "", "", newLoggedError("Unable to generate rememberMe token", err)
	}
	return selector, token, tokenHash, nil
}

func generateStringAndHash() (string, string, error) {
	b, err := generateRandomBytes(32)
	if err != nil {
		return "", "", err
	}
	return encodeToString(b), encodeToString(hash(b)), nil
}

func hash(bytes []byte) []byte {
	h := sha256.Sum256(bytes)
	return h[:]
}

// Url decode both the token and the hash and then compare
func encodedHashEquals(token, tokenHash string) bool {
	tokenBytes, _ := decodeFromString(token)
	hashBytes, _ := decodeFromString(tokenHash)
	return hashEquals(tokenBytes, hashBytes)
}

func hashEquals(token, tokenHash []byte) bool {
	return subtle.ConstantTimeCompare(hash(token), tokenHash) == 1
}

func generateRandomString() (string, error) {
	bytes, err := generateRandomBytes(32)
	return encodeToString(bytes), err
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
