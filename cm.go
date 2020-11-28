package cm

import (
	"encoding/json"
	"log"

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
	cm.nc.Subscribe("cm.jwt", cm.GetUserJwt)
	cm.nc.Subscribe("cm.accounts", cm.GetAccountList)
	cm.nc.Subscribe("cm.register", cm.Register)
	cm.nc.Subscribe("cm.config", cm.UpdateConfig)
	cm.nc.Flush()
	return nil
}

func (cm *CredentialsManager) Stop() {
	cm.nc.Close()
}

func (cm *CredentialsManager) RespondJSON(ctx *nats.Msg, o interface{}) {
	d, err := json.Marshal(o)
	if err != nil {
		cm.logger.Errorf("[cm] error serializing response: %v", err)
		return
	}
	if err := ctx.Respond(d); err != nil {
		cm.logger.Errorf("[cm] error responding: %v", err)
		return
	}
}

func (cm *CredentialsManager) GetUserJwt(m *nats.Msg) {
	var req UserJwtRequest
	var resp UserJwtResponse
	if err := json.Unmarshal(m.Data, &req); err != nil {
		cm.logger.Errorf("[cm] error unmarshalling: %v", err)
		resp.Error = "internal server error"
	} else {
		resp.UserJwtRequest = req
		d, err := cm.backend.GetUserJwt(req.Account, req.Email)
		if err != nil {
			cm.logger.Errorf("[cm] error retrieving user %q for account %s: %v", req.Account, req.Email, err)
			resp.Error = "internal server error"
			cm.RespondJSON(m, resp)
			return
		}
		resp.Jwt = string(d)
	}
	cm.RespondJSON(m, resp)
}

func (cm *CredentialsManager) GetAccountList(m *nats.Msg) {
	var req UserAccountRequest
	var resp UserAccountResponse
	if err := json.Unmarshal(m.Data, &req); err != nil {
		cm.logger.Errorf("[cm] error unmarshalling: %v", err)
		resp.Error = "internal server error"
	} else {
		resp.UserAccountRequest = req
		accounts, err := cm.backend.GetAccountList(req.Email)
		if err != nil {
			cm.logger.Errorf("[cm] error getting account list for %q: %v", req.Email, err)
			resp.Error = "internal server error"
		}
		resp.Accounts = accounts
		switch len(accounts) {
		case 0:
			resp.Error = "not found"
		case 1:
			resp.Account = accounts[0]
			d, err := cm.backend.GetUserJwt(accounts[0], req.Email)
			if err != nil {
				cm.logger.Errorf("[cm] error retrieving user %q for account %s: %v", accounts[0], req.Email, err)
				resp.Error = "internal server error"
			} else {
				resp.Jwt = string(d)
			}
		}
	}
	cm.RespondJSON(m, resp)
}

func (cm *CredentialsManager) Register(m *nats.Msg) {
	var resp RegisterUserResponse
	var req RegisterUserRequest
	if err := json.Unmarshal(m.Data, &req); err != nil {
		cm.logger.Errorf("[cm] error unmarshalling: %v", err)
		resp.Error = "internal server error"
	} else if err := cm.backend.RegisterUser([]byte(req.Jwt)); err != nil {
		cm.logger.Errorf("[cm] error registering user: %v", err)
		resp.Error = "internal server error"
	}
	if resp.Error != "" {
		log.Printf("Error registering user: %v", resp.Error)
	}
	cm.RespondJSON(m, resp)
}

func (cm *CredentialsManager) UpdateConfig(m *nats.Msg) {
	if err := cm.backend.UpdateConfig(m.Data); err != nil {
		m.Respond([]byte(err.Error()))
	} else {
		m.Respond(nil)
	}
}
