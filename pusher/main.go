package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/nats-io/jwt"

	"github.com/aricart/cm"
	"github.com/nats-io/nats.go"
)

type client struct {
	hostport  string
	credsFile string
	userFile  string
	verb      string
	email     string
	account   string
	options   []nats.Option
}

func (c *client) fetchJWT() error {
	if c.email == "" {
		panic("email is required")
	}
	if c.account == "" {
		panic("account is required")
	}
	nc, err := nats.Connect(c.hostport, c.options...)
	if err != nil {
		panic(err)
	}
	req := cm.UserJwtRequest{Email: c.email, Account: c.account}
	data, err := json.Marshal(&req)
	if err != nil {
		panic(err)
	}
	msg, err := nc.Request("ngs.cm.jwt", data, time.Second)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(msg.Data))
	return nc.Drain()
}

func (c *client) fetchAccounts() error {
	if c.email == "" {
		panic("email is required")
	}
	nc, err := nats.Connect(c.hostport, c.options...)
	if err != nil {
		panic(err)
	}
	req := cm.UserAccountRequest{Email: c.email}
	data, err := json.Marshal(&req)
	if err != nil {
		panic(err)
	}
	msg, err := nc.Request("ngs.cm.accounts", data, time.Second)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(msg.Data))
	return nc.Drain()
}

func (c *client) register() error {
	if c.userFile == "" {
		panic("user jwt is required")
	}
	dat, err := ioutil.ReadFile(c.userFile)
	if err != nil {
		panic(err)
	}
	_, err = jwt.DecodeUserClaims(string(dat))
	if err != nil {
		panic(fmt.Sprintf("error parsing user jwt: %v", err))
	}
	nc, err := nats.Connect(c.hostport, c.options...)
	if err != nil {
		panic(err)
	}
	req := cm.RegisterUserRequest{Jwt: string(dat)}
	data, err := json.Marshal(&req)
	if err != nil {
		panic(err)
	}
	msg, err := nc.Request("cm.register", data, time.Second)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(msg.Data))
	return nc.Drain()
}

func main() {
	var c client
	flag.StringVar(&c.hostport, "nats hostport", "localhost:4222", "NATS hostport")
	flag.StringVar(&c.credsFile, "creds", "", "NATS credentials file")
	flag.StringVar(&c.userFile, "jwt", "", "user jwt file")
	flag.StringVar(&c.verb, "verb", "", "[jwt, accounts, register]")
	flag.StringVar(&c.email, "email", "", "associated email - for jwt or accounts")
	flag.StringVar(&c.account, "account", "", "associated account - for jwt")
	flag.Parse()

	if c.credsFile != "" {
		c.options = append(c.options, nats.UserCredentials(c.credsFile))
	}

	switch c.verb {
	case "jwt":
		c.fetchJWT()
	case "accounts":
		c.fetchAccounts()
	case "register":
		c.register()
	default:
		panic("verb is required")
	}
}
