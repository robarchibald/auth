package main

import (
	"testing"
)

func getLoginStore(mailErr error, backend *mockBackend) loginStorer {
	return &loginStore{backend, &TextMailer{Err: mailErr}}
}

func TestNewLoginStore(t *testing.T) {
	b := &mockBackend{}
	m := &TextMailer{}
	actual := newLoginStore(b, m).(*loginStore)
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
	ExpectedResult      *rememberMeSession
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
		GetUserLoginReturn: &LoginReturn{Login: &userLogin{Email: "test@test.com", ProviderKey: "1234"}},
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
	if testing.Short() {
		t.SkipNow()
	}
	for i, test := range loginTests {
		backend := &mockBackend{GetUserLoginReturn: test.GetUserLoginReturn, ErrReturn: test.ErrReturn}
		store := getLoginStore(nil, backend).(*loginStore)
		val, err := store.Login(test.Email, test.Password, test.RememberMe)
		methods := store.backend.(*mockBackend).MethodsCalled
		if (err == nil && test.ExpectedErr != "" || err != nil && test.ExpectedErr != err.Error()) ||
			!collectionEqual(test.MethodsCalled, methods) {
			t.Errorf("Scenario[%d] failed: %s\nexpected err:%v\tactual err:%v\nexpected val:%v\tactual val:%v\nexpected methods: %s\tactual methods: %s", i, test.Scenario, test.ExpectedErr, err, test.ExpectedResult, val, test.MethodsCalled, methods)
		}
	}
}

/****************************************************************************/
type mockLoginStore struct {
	LoginReturn *LoginReturn
}

func newMockLoginStore() loginStorer {
	return &mockLoginStore{}
}

func (s *mockLoginStore) Login(email, password string, rememberMe bool) (*userLogin, error) {
	return s.LoginReturn.Login, s.LoginReturn.Err
}

func (s *mockLoginStore) LoginBasic() (*userLogin, error) {
	return s.LoginReturn.Login, s.LoginReturn.Err
}

func (s *mockLoginStore) CreateLogin(email, fullName, password string, cloudQuota, fileQuota int) (*userLogin, error) {
	return s.LoginReturn.Login, s.LoginReturn.Err
}

func (s *mockLoginStore) UpdateEmail() error {
	return s.LoginReturn.Err
}

func (s *mockLoginStore) UpdatePassword() error {
	return s.LoginReturn.Err
}
