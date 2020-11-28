package cm

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/nats-io/nats-server/v2/logger"
	natsserver "github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
)

type CredentialsManager struct {
	NatsHostPort    string
	CredentialsFile string
	DataDir         string
	nc              *nats.Conn
	backend         *Backend
	logger          natsserver.Logger
}

func (cm *CredentialsManager) init() error {
	cm.logger = logger.NewStdLogger(true, true, true, true, true)
	if cm.NatsHostPort == "" {
		log.Fatal("nats hostport is required")
	}
	if cm.DataDir == "" {
		log.Fatal("data dir is required")
	}
	cm.backend = NewBackend(cm.DataDir)
	return cm.backend.Start()
}

const SubjGetUserJwt = "cm.get.user.jwt"
const SubjUserAccounts = "cm.get.user.accounts"
const SubjAddUserJwt = "cm.add.user.jwt"
const SubjUpdateAccountConfig = "cm.update.account.config"
const SubjGetAccountConfig = "cm.get.account.config"

func (cm *CredentialsManager) Run() error {
	var err error
	if err = cm.init(); err != nil {
		return err
	}

	var options []nats.Option
	options = append(options, nats.MaxReconnects(-1))
	options = append(options, nats.RetryOnFailedConnect(true))

	if cm.CredentialsFile != "" {
		options = append(options, nats.UserCredentials(cm.CredentialsFile))
	}
	if cm.nc, err = nats.Connect(cm.NatsHostPort, options...); err != nil {
		return err
	}
	// FIXME: check errors
	// FIXME: add handlers
	cm.nc.Subscribe(SubjGetUserJwt, cm.GetUserJwt)
	cm.nc.Subscribe(SubjUserAccounts, cm.GetUserAccounts)
	cm.nc.Subscribe(SubjAddUserJwt, cm.AddUserJwt)
	cm.nc.Subscribe(SubjUpdateAccountConfig, cm.UpdateAccountConfig)
	cm.nc.Subscribe(SubjGetAccountConfig, cm.GetAccountConfig)
	cm.nc.Flush()
	return nil
}

func (cm *CredentialsManager) Stop() {
	cm.nc.Close()
}

type RequestResponse struct {
	Error string `json:"error"`
}

type UserRequest struct {
	Email   string `json:"email"`
	Account string `json:"account"`
}

type UserResponse struct {
	UserRequest
	RequestResponse
	Jwt string `json:"jwt"`
}

func (cm *CredentialsManager) GetUserJwt(m *nats.Msg) {
	var req UserRequest
	if err := cm.ParseRequest(m, &req); err != nil {
		return
	}
	var resp UserResponse
	resp.UserRequest = req
	d, err := cm.backend.GetUserJwt(req.Account, req.Email)
	if err != nil {
		em := fmt.Sprintf("error retrieving user %q for account %s", req.Account, req.Email)
		cm.RespondError(m, http.StatusInternalServerError, em, err)
		return
	}
	resp.Jwt = string(d)
	cm.Respond(m, resp)
}

type UserAccountsRequest struct {
	Email string `json:"email"`
}

type UserAccountsResponse struct {
	UserAccountsRequest
	UserResponse
	RequestResponse
	Accounts []string `json:"accounts"`
}

func (cm *CredentialsManager) GetUserAccounts(m *nats.Msg) {
	var req UserAccountsRequest
	if err := cm.ParseRequest(m, &req); err != nil {
		return
	}

	var resp UserAccountsResponse
	resp.UserAccountsRequest = req
	accounts, err := cm.backend.GetUserAccounts(req.Email)
	if err != nil {
		em := fmt.Sprintf("error getting account list for %q", req.Email)
		cm.RespondError(m, http.StatusInternalServerError, em, err)
		return
	}
	resp.Accounts = accounts
	switch len(accounts) {
	case 0:
		cm.RespondError(m, http.StatusNotFound, "account not found", nil)
		return
	case 1:
		resp.Account = accounts[0]
		d, err := cm.backend.GetUserJwt(accounts[0], req.Email)
		if err != nil {
			em := fmt.Sprintf("error retrieving user %q for account %s", req.Email, accounts[0])
			cm.RespondError(m, http.StatusInternalServerError, em, err)
			return
		} else {
			resp.Jwt = string(d)
		}
	}
	cm.Respond(m, resp)
}

type UpdateUserRequest struct {
	Jwt string `json:"jwt"`
}

type UpdateUserResponse struct {
	RequestResponse
}

func (cm *CredentialsManager) AddUserJwt(m *nats.Msg) {
	var req UpdateUserRequest
	if err := cm.ParseRequest(m, &req); err != nil {
		return
	}
	var resp UpdateUserResponse
	if err := cm.backend.AddUserJwt([]byte(req.Jwt)); err != nil {
		cm.RespondError(m, http.StatusInternalServerError, "error registering user", err)
		return
	}
	cm.Respond(m, resp)
}

type UpdateAccountRequest struct {
	Jwt string `json:"jwt"`
}

type UpdateAccountResponse struct {
	RequestResponse
}

func (cm *CredentialsManager) UpdateAccountConfig(m *nats.Msg) {
	var req UpdateAccountRequest
	if err := cm.ParseRequest(m, &req); err != nil {
		return
	}
	if err := cm.backend.UpdateAccountConfig([]byte(req.Jwt)); err != nil {
		cm.RespondError(m, http.StatusInternalServerError, "error updating account config", err)
		return
	}
	cm.Respond(m, RequestResponse{})
}

type AccountRequest struct {
	Token string `json:"jwt"`
}

type AccountRequestResponse struct {
	RequestResponse
	Jwt string `json:"jwt"`
}

func (cm *CredentialsManager) GetAccountConfig(m *nats.Msg) {
	var req AccountRequest
	if err := cm.ParseRequest(m, &req); err != nil {
		return
	}
	d, err := cm.backend.GetAccountConfig([]byte(req.Token))
	if err != nil {
		cm.RespondError(m, http.StatusInternalServerError, "error getting account config", err)
		return
	}
	var resp AccountRequestResponse
	resp.Jwt = string(d)
	cm.Respond(m, resp)
}

func (cm *CredentialsManager) Respond(ctx *nats.Msg, o interface{}) {
	d, err := json.MarshalIndent(o, "", "\t")
	if err != nil {
		cm.RespondError(ctx, http.StatusInternalServerError, "error serializing response", err)
		return
	}
	if err := ctx.Respond(d); err != nil {
		cm.logger.Errorf("[cm] error responding: %v", err)
		return
	}
}

func (cm *CredentialsManager) RespondError(ctx *nats.Msg, status int, msg string, err error) {
	em := fmt.Sprintf("[cm] %s", msg)
	if err != nil {
		em = fmt.Sprintf("[cm] %s: %v", msg, err)
	}
	cm.logger.Errorf(em)
	cm.Respond(ctx, RequestResponse{Error: http.StatusText(status)})
}

func (cm *CredentialsManager) ParseRequest(ctx *nats.Msg, o interface{}) error {
	err := json.Unmarshal(ctx.Data, &o)
	if err != nil {
		cm.logger.Errorf("[cm] error unmarshalling: %v", err)
		cm.Respond(ctx, RequestResponse{Error: "bad request"})
		return err
	}
	return nil
}
