package main

type LoginStorer interface {
	Login(email, password string, rememberMe bool) (*UserLogin, error)

	CreateLogin(email, fullName, password string) (*UserLogin, error)
	UpdateEmail() error
	UpdatePassword() error
}

type loginStore struct {
	backend Backender
	mailer  Mailer
}

func NewLoginStore(backend Backender, mailer Mailer) LoginStorer {
	return &loginStore{backend, mailer}
}

func (s *loginStore) Login(email, password string, rememberMe bool) (*UserLogin, error) {
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
	return login, nil
}

func (s *loginStore) CreateLogin(email, fullName, password string) (*UserLogin, error) {
	passwordHash := encodeToString(hash([]byte(password)))
	login, err := s.backend.CreateLogin(email, passwordHash, fullName)
	if err != nil {
		return nil, newLoggedError("Unable to create login", err)
	}
	return login, err
}

func (s *loginStore) UpdateEmail() error { return nil }

func (s *loginStore) UpdatePassword() error {
	return nil
}

func isValidPassword(password string) bool {
	return len(password) >= 7 && len(password) <= 20
}
