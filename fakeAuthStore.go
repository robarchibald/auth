package auth

import "net/http"

type fakeAuthStore struct {
}

func (a *fakeAuthStore) GetSession(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	return &LoginSession{UserID: "1", Email: "test@test.com", Info: map[string]interface{}{"roles": []string{"claims-reprice"}}, CSRFToken: "123456"}, nil
}
func (a *fakeAuthStore) GetBasicAuth(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	return nil, nil
}
func (a *fakeAuthStore) OAuthLogin(w http.ResponseWriter, r *http.Request) (string, error) {
	return "", nil
}
func (a *fakeAuthStore) Login(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	return nil, nil
}
func (a *fakeAuthStore) Register(w http.ResponseWriter, r *http.Request, email string, templates TemplateNames, emailSubject string, info map[string]interface{}) error {
	return nil
}
func (a *fakeAuthStore) RequestPasswordReset(w http.ResponseWriter, r *http.Request, email string, templates TemplateNames, emailSubject string, info map[string]interface{}) error {
	return nil
}
func (a *fakeAuthStore) CreateProfile(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	return nil, nil
}
func (a *fakeAuthStore) VerifyEmail(w http.ResponseWriter, r *http.Request, emailVerificationCode, templateName, emailSubject string) (string, *User, error) {
	return "", nil, nil
}
func (a *fakeAuthStore) VerifyPasswordReset(w http.ResponseWriter, r *http.Request, emailVerificationCode string) (string, *User, error) {
	return "", nil, nil
}
func (a *fakeAuthStore) CreateSecondaryEmail(w http.ResponseWriter, r *http.Request, templateName, emailSubject string) error {
	return nil
}
func (a *fakeAuthStore) SetPrimaryEmail(w http.ResponseWriter, r *http.Request, templateName, emailSubject string) error {
	return nil
}
func (a *fakeAuthStore) UpdatePassword(w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	return nil, nil
}
func (a *fakeAuthStore) Logout(w http.ResponseWriter, r *http.Request) error {
	return nil
}
func (a *fakeAuthStore) UpdateInfo(userID string, info map[string]interface{}) error {
	return nil
}

var _ AuthStorer = &fakeAuthStore{}
