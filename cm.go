package cm

import (
	"encoding/json"
	"log"

	"github.com/nats-io/nats.go"
)

type CredentialsManager struct {
	NatsHostPort    string
	CredentialsFile string
	DataDir         string
	nc              *nats.Conn
	backend         *Backend
}

func (cm *CredentialsManager) init() error {
	if cm.NatsHostPort == "" {
		log.Fatal("nats hostport is required")
	}
	if cm.DataDir == "" {
		log.Fatal("data dir is required")
	}
	cm.backend = NewBackend(cm.DataDir)
	return cm.backend.Start()
}

func (cm *CredentialsManager) Run() {
	var err error
	if err = cm.init(); err != nil {
		log.Fatal(err)
	}

	var options []nats.Option
	if cm.CredentialsFile != "" {
		options = append(options, nats.UserCredentials(cm.CredentialsFile))
	}
	if cm.nc, err = nats.Connect(cm.NatsHostPort, options...); err != nil {
		log.Fatal(err)
	}

	cm.nc.Subscribe("cm.jwt", cm.GetUserJwt)
	cm.nc.Subscribe("cm.accounts", cm.GetAccountList)
	cm.nc.Subscribe("cm.register", cm.Register)
	cm.nc.Subscribe("cm.config", cm.UpdateConfig)
}

func (cm *CredentialsManager) Stop() {
	cm.nc.Close()
}

func (cm *CredentialsManager) GetUserJwt(m *nats.Msg) {
	var req UserJwtRequest
	var resp UserJwtResponse
	if err := json.Unmarshal(m.Data, &req); err != nil {
		resp.Error = "internal server error"
	} else {
		resp = cm.backend.GetUserJwt(req)
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

func (cm *CredentialsManager) GetAccountList(m *nats.Msg) {
	var resp UserAccountResponse
	var req UserAccountRequest
	if err := json.Unmarshal(m.Data, &req); err != nil {
		resp.Error = "internal server error"
	} else {
		resp = cm.backend.GetAccountList(req)
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

func (cm *CredentialsManager) Register(m *nats.Msg) {
	var resp RegisterUserResponse
	var req RegisterUserRequest
	if err := json.Unmarshal(m.Data, &req); err != nil {
		resp.Error = "internal server error"
	} else {
		resp = cm.backend.RegisterUser(req)
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

func (cm *CredentialsManager) UpdateConfig(m *nats.Msg) {
	cm.backend.UpdateConfig(m.Data)
}
