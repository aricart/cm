package cm

type Backend struct {
	static  *StaticFileResolver
	dataDir string
}

func NewBackend(dir string) *Backend {
	return &Backend{dataDir: dir}
}

func (s *Backend) Start() error {
	var err error
	s.static, err = NewStaticResolver(s.dataDir)
	return err
}

func (s *Backend) Stop() error {
	return nil
}

func (s *Backend) deleteUsers(account string, users Users) error {
	for _, i := range users {
		if err := s.static.deleteUser(account, i.Email); err != nil {
			return err
		}
	}
	return nil
}

func (s *Backend) getConfig(account string) (*Config, error) {
	old, err := s.static.GetConfig(account)
	if err != nil {
		return nil, err
	}
	oc, err := ParseConfig(old)
	if err != nil {
		return nil, err
	}
	return oc, nil
}

func (s *Backend) UpdateConfig(token []byte) error {
	nc, err := ParseConfig(token)
	if err != nil {
		return err
	}

	oc, err := s.getConfig(nc.Account)
	if err != nil {
		return err
	}

	// if we have an old static config, but new one is different cleanup
	if oc != nil && oc.Kind == Static {
		// if changed type delete all users
		if oc.Kind != nc.Kind {
			s.deleteUsers(oc.Account, oc.Users)
		} else {
			deleted := nc.Users.Deleted(oc.Users)
			s.deleteUsers(oc.Account, deleted)
		}
	}
	return nil
}

func (s *Backend) GetAccountList(req UserAccountRequest) UserAccountResponse {
	var resp UserAccountResponse
	resp.UserAccountRequest = req

	accounts, err := s.static.GetAccounts(req.Email)
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
		d, err := s.static.GetUser(req.Email, accounts[0])
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
	d, err := s.static.GetUser(req.Email, req.Account)
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
	if err := s.static.Store([]byte(req.Jwt)); err != nil {
		resp.Error = err.Error()
	}
	return resp
}
