package main

type backendDbUser struct {
}

func NewBackendDbUser() (UserBackender, error) {
	return nil, nil
}

func (u *backendDbUser) GetLogin(email, loginProvider string) (*UserLogin, error) {
	return nil, nil
}

func (u *backendDbUser) AddUser(email, emailVerifyHash string) error {
	return nil
}

func (u *backendDbUser) VerifyEmail(emailVerifyHash string) (string, error) {
	return "", nil
}

func (u *backendDbUser) UpdateUser(emailVerifyHash, fullname string, company string, pictureURL string) (string, error) {
	return "", nil
}

func (u *backendDbUser) Close() error {
	return nil
}
