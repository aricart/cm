package cm

import (
	"fmt"

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

func (s *Backend) UpdateConfig(token []byte) error {
	gc, err := jwt.DecodeGeneric(string(token))
	if err != nil {
		return err
	}
	switch gc.Type {
	case "dashboard-account-configuration":
		c, err := s.sr.StoreAccountConfig(token)
		if err != nil {
			return err
		}
		if c.Kind == Generator {
			s.accounts.Update(c.Account, c.ListUsers())
		} else {
			s.accounts.RemoveAll(c.Account)
		}
		s.accounts.Update(c.Account, c.ListUsers())
	case jwt.UserClaim:
		return s.sr.StoreUserJwt(token)
	default:
		return fmt.Errorf("not supported - %s", gc.Type)
	}
	return nil
}

func (s *Backend) GetAccountList(req UserAccountRequest) UserAccountResponse {
	var resp UserAccountResponse
	resp.UserAccountRequest = req

	accounts, err := s.sr.GetUserAccounts(req.Email)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	// return all accounts found always
	resp.Accounts = accounts
	count := len(accounts)
	switch count {
	case 0:
		resp.Error = "not found"
	case 1:
		d, err := s.sr.GetUserJwt(req.Email, accounts[0])
		if err != nil {
			resp.Error = err.Error()
		}
		resp.Jwt = string(d)
	}
	return resp
}
func (s *Backend) GetUserJwt(req UserJwtRequest) UserJwtResponse {
	var resp UserJwtResponse
	resp.UserJwtRequest = req
	d, err := s.sr.GetUserJwt(req.Email, req.Account)
	if err != nil {
		resp.Error = err.Error()
	}
	if d == nil {
		resp.Error = "not found"
	}
	resp.Jwt = string(d)
	return resp
}

func (s *Backend) RegisterUser(req RegisterUserRequest) RegisterUserResponse {
	var resp RegisterUserResponse
	if err := s.sr.StoreUserJwt([]byte(req.Jwt)); err != nil {
		resp.Error = err.Error()
	}
	return resp
}
