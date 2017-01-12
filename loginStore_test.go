package main

import (
	"testing"
)

func getLoginStore(mailErr error, backend *MockBackend) LoginStorer {
	return &loginStore{backend, &TextMailer{Err: mailErr}}
}

func TestNewLoginStore(t *testing.T) {
	b := &MockBackend{}
	m := &TextMailer{}
	actual := NewLoginStore(b, m).(*loginStore)
	if actual.backend != b {
		t.Fatal("expected correct init")
	}
}

var loginTests = []struct {
	Scenario            string
	Email               string
	Password            string
	RememberMe          bool
	CreateSessionReturn *SessionReturn
	GetUserLoginReturn  *LoginReturn
	ErrReturn           error
	MethodsCalled       []string
	ExpectedResult      *UserLoginRememberMe
	ExpectedErr         string
}{
	{
		Scenario:    "Invalid email",
		Email:       "invalid@bogus",
		ExpectedErr: "Please enter a valid email address.",
	},
	{
		Scenario:    "Invalid password",
		Email:       "email@example.com",
		Password:    "short",
		ExpectedErr: passwordValidationMessage,
	},
	{
		Scenario:           "Can't get login",
		Email:              "email@example.com",
		Password:           "validPassword",
		GetUserLoginReturn: loginErr(),
		MethodsCalled:      []string{"GetUserLogin"},
		ExpectedErr:        "Invalid username or password",
	},
	{
		Scenario:           "Incorrect password",
		Email:              "email@example.com",
		Password:           "wrongPassword",
		GetUserLoginReturn: &LoginReturn{Login: &UserLogin{LoginID: 1, UserID: 1, ProviderKey: "1234"}},
		MethodsCalled:      []string{"GetUserLogin"},
		ExpectedErr:        "Invalid username or password",
	},
	{
		Scenario:            "Got session",
		Email:               "email@example.com",
		Password:            "correctPassword",
		GetUserLoginReturn:  loginSuccess(),
		CreateSessionReturn: sessionSuccess(futureTime, futureTime),
		MethodsCalled:       []string{"GetUserLogin"},
	},
}

func TestAuthLogin(t *testing.T) {
	for i, test := range loginTests {
		backend := &MockBackend{GetUserLoginReturn: test.GetUserLoginReturn, ErrReturn: test.ErrReturn}
		store := getLoginStore(nil, backend).(*loginStore)
		val, err := store.Login(test.Email, test.Password, test.RememberMe)
		methods := store.backend.(*MockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected val:%v\tactual val:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.ExpectedResult, val, test.MethodsCalled, methods)
		}
	}
}

/****************************************************************************/
type MockLoginStore struct {
	LoginReturn *LoginReturn
}

func NewMockLoginStore() LoginStorer {
	return &MockLoginStore{}
}

func (s *MockLoginStore) Login(email, password string, rememberMe bool) (*UserLogin, error) {
	return s.LoginReturn.Login, s.LoginReturn.Err
}

func (s *MockLoginStore) LoginBasic() (*UserLogin, error) {
	return s.LoginReturn.Login, s.LoginReturn.Err
}

func (s *MockLoginStore) CreateLogin(email, fullName, password string) (*UserLogin, error) {
	return s.LoginReturn.Login, s.LoginReturn.Err
}

func (s *MockLoginStore) UpdateEmail() error {
	return s.LoginReturn.Err
}

func (s *MockLoginStore) UpdatePassword() error {
	return s.LoginReturn.Err
}
