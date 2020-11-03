package cm

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nats.go"
)

type CredentialsManager struct {
	NatsHostPort      string
	CredentialsFile   string
	DataDir           string

	nc                *nats.Conn
	emailToAccounts   map[string][]string
	emailAccountToJwt map[string]string
}

func (cm *CredentialsManager) init() error {
	cm.emailToAccounts = make(map[string][]string)
	cm.emailAccountToJwt = make(map[string]string)

	if cm.NatsHostPort == "" {
		log.Fatal("nats hostport is required")
	}
	if cm.DataDir == "" {
		log.Fatal("data dir is required")
	}
	if _, err := os.Stat(cm.DataDir); os.IsNotExist(err) {
		return os.MkdirAll(cm.DataDir, 0755)
	}
	return nil
}

func (cm *CredentialsManager) emailAccountKey(email string, account string) string {
	// FIXME - replace all invalid characters
	return fmt.Sprintf("%s__%s", email, account)
}

func (cm *CredentialsManager) load() error {
	f, err := os.Open(cm.DataDir)
	if err != nil {
		return err
	}
	defer f.Close()

	names, err := f.Readdir(-1)
	for _, fi := range names {
		if !fi.IsDir() && strings.HasSuffix(fi.Name(), ".jwt") {
			fn := filepath.Join(cm.DataDir, fi.Name())
			dat, err := ioutil.ReadFile(fn)
			if err != nil {
				log.Printf("unable to read user JWT %q: %v\n", fn, err)
				continue
			}
			if err := cm.update(string(dat), false); err != nil {
				log.Printf("unable to decode user JWT %q: %v\n", fn, err)
				continue
			}
		}
	}
	return nil
}

func (cm *CredentialsManager) Run() {
	var err error
	if err = cm.init(); err != nil {
		log.Fatal(err)
	}
	if err = cm.load(); err != nil {
		log.Fatal(err)
	}

	var options []nats.Option
	if cm.CredentialsFile != "" {
		options = append(options, nats.UserCredentials(cm.CredentialsFile))
	}
	if cm.nc, err = nats.Connect(cm.NatsHostPort, options...); err != nil {
		log.Fatal(err)
	}

	cm.nc.Subscribe("cm.*.jwt", cm.GetUserJwt)
	cm.nc.Subscribe("cm.*.accounts", cm.GetAccountList)
	cm.nc.Subscribe("cm.*.register", cm.Register)
}

func (cm *CredentialsManager) Stop() {
	cm.nc.Close()
}

type UserJwtRequest struct {
	Email   string `json:"email"`
	Account string `json:"account"`
}

type UserJwtResponse struct {
	UserJwtRequest
	Jwt   string `json:"jwt"`
	Error string `json:"error"`
}

func (cm *CredentialsManager) getUserJwt(req UserJwtRequest) UserJwtResponse {
	var resp UserJwtResponse
	key := cm.emailAccountKey(req.Email, req.Account)
	resp.UserJwtRequest = req
	resp.Jwt = cm.emailAccountToJwt[key]
	if resp.Jwt == "" {
		resp.Error = "not found"
	}
	return resp
}

func (cm *CredentialsManager) GetUserJwt(m *nats.Msg) {
	var req UserJwtRequest
	var resp UserJwtResponse
	if err := json.Unmarshal(m.Data, &req); err != nil {
		resp.Error = "internal server error"
	} else {
		resp = cm.getUserJwt(req)
	}
	if resp.Error != "" {
		log.Printf("Error retrieving user jwt: %v", resp.Error)
	}
	rjson, err := json.Marshal(&resp)
	if err != nil {
		log.Printf("Error serializing JSON: %v", err)
		return
	}
	m.Respond(rjson)
}

type UserAccountRequest struct {
	Email string `json:"email"`
}

type UserAccountResponse struct {
	UserAccountRequest
	UserJwtResponse
	Accounts []string `json:"accounts"`
	Error    string   `json:"error"`
}

func (cm *CredentialsManager) getAccountList(req UserAccountRequest) UserAccountResponse {
	var resp UserAccountResponse
	resp.UserAccountRequest = req
	resp.Accounts = cm.emailToAccounts[req.Email]
	switch len(resp.Accounts) {
	case 0:
		resp.Error = "not found"
	case 1:
		resp.UserJwtResponse = cm.getUserJwt(UserJwtRequest{Email: req.Email, Account: resp.Accounts[0]})
	}
	return resp
}

func (cm *CredentialsManager) GetAccountList(m *nats.Msg) {
	var resp UserAccountResponse
	var req UserAccountRequest
	if err := json.Unmarshal(m.Data, &req); err != nil {
		resp.Error = "internal server error"
	} else {
		resp = cm.getAccountList(req)
	}
	if resp.Error != "" {
		log.Printf("Error retrieving account list: %v", resp.Error)
	}
	rjson, err := json.Marshal(&resp)
	if err != nil {
		log.Printf("Error serializing JSON: %v", err)
		return
	}
	m.Respond(rjson)
}

type RegisterUserRequest struct {
	Jwt string `json:"jwt"`
}

type RegisterUserResponse struct {
	Error string `json:"error"`
}

func (cm *CredentialsManager) update(sjwt string, store bool) error {
	uc, err := jwt.DecodeUserClaims(sjwt)
	if err != nil {
		return fmt.Errorf("unable to decode user JWT: %v", err)
	}
	// associate the user with the account that generated the JWT
	account := uc.Issuer
	if uc.IssuerAccount != "" {
		account = uc.IssuerAccount
	}
	// the "email" should be the uc.Name
	cm.emailToAccounts[uc.Name] = append(cm.emailToAccounts[uc.Name], account)
	cm.emailAccountToJwt[cm.emailAccountKey(uc.Name, account)] = sjwt

	if store {
		key := cm.emailAccountKey(uc.Name, account)
		fn := fmt.Sprintf("%s.jwt", key)
		return ioutil.WriteFile(filepath.Join(cm.DataDir, fn), []byte(sjwt), 0644)
	}
	return nil
}

func (cm *CredentialsManager) register(req RegisterUserRequest) RegisterUserResponse {
	var resp RegisterUserResponse
	if err := cm.update(req.Jwt, true); err != nil {
		resp.Error = err.Error()
	}
	return resp
}

func (cm *CredentialsManager) Register(m *nats.Msg) {
	var resp RegisterUserResponse
	var req RegisterUserRequest
	if err := json.Unmarshal(m.Data, &req); err != nil {
		resp.Error = "internal server error"
	} else {
		resp = cm.register(req)
	}
	if resp.Error != "" {
		log.Printf("Error registering user: %v", resp.Error)
	}
	rjson, err := json.Marshal(&resp)
	if err != nil {
		log.Printf("Error serializing JSON: %v", err)
		return
	}
	m.Respond(rjson)
}
