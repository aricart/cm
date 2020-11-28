package cm

import (
	"fmt"
	"strings"

	"github.com/nats-io/jwt"
)

type Backend struct {
	sr       *StaticFileResolver
	dir      string
	accounts *AccountCache
}

func NewBackend(dir string) *Backend {
	b := Backend{dir: dir}
	b.accounts = NewAccountCache()
	return &b
}

func (s *Backend) Start() error {
	var err error
	s.sr, err = NewStaticResolver(s.dir)
	return err
}

func (s *Backend) Stop() error {
	return nil
}

func (s *Backend) UpdateAccountConfig(token []byte) error {
	gc, err := jwt.DecodeGeneric(string(token))
	if err != nil {
		return err
	}
	if gc.Type != DashboardConfigurationType {
		return fmt.Errorf("not supported - %s", gc.Type)
	}
	c, err := s.sr.StoreAccountConfig(token)
	if err != nil {
		return err
	}
	if c.Kind == Generator {
		s.accounts.Update(c.Account, c.ListUsers())
	} else {
		s.accounts.RemoveAll(c.Account)
	}
	return nil
}

func (s *Backend) GetAccountConfig(token []byte) ([]byte, error) {
	gc, err := jwt.DecodeGeneric(string(token))
	if err != nil {
		return nil, err
	}
	if gc.Type != DashboardConfigurationType {
		return nil, fmt.Errorf("bad request")
	}
	return s.sr.GetConfig(gc.Issuer)
}

func (s *Backend) GetUserAccounts(email string) ([]string, error) {
	email = strings.ToUpper(email)
	accounts, err := s.sr.GetUserAccounts(email)
	if err != nil {
		return nil, err
	}
	accounts = append(accounts, s.accounts.Accounts(email)...)
	return accounts, nil
}
func (s *Backend) GetUserJwt(account string, email string) ([]byte, error) {
	cd, err := s.sr.GetConfig(account)
	if err != nil {
		return nil, err
	}

	c, err := ParseConfig(cd)
	if err != nil {
		return nil, err
	}
	switch c.Kind {
	case Static:
		td, err := s.sr.GetUserJwt(email, account)
		if err != nil {
			return nil, err
		}
		if td == nil {
			return nil, nil
		}
		return td, nil
	case Generator:
		return c.GetUserJwt(email)
	default:
		return nil, fmt.Errorf("unknown configuration type - %q", c.Kind)
	}
}

func (s *Backend) AddUserJwt(d []byte) error {
	return s.sr.StoreUserJwt(d)
}
