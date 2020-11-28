package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/aricart/cm"
	nats "github.com/nats-io/nats.go"
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

func (c *client) request(subj string, req interface{}) string {
	nc, err := nats.Connect(c.hostport, c.options...)
	if err != nil {
		panic(err)
	}
	data, err := json.Marshal(req)
	if err != nil {
		panic(err)
	}
	r, err := nc.Request(subj, data, time.Second)
	if err != nil {
		panic(err)
	}
	nc.Close()
	return string(r.Data)
}

func (c *client) getUser() {
	if c.email == "" {
		panic("email is required")
	}
	if c.account == "" {
		panic("account is required")
	}
	req := cm.UserRequest{Email: c.email, Account: c.account}
	fmt.Println(c.request(cm.SubjGetUserJwt, req))
}

func (c *client) getAccounts() {
	if c.email == "" {
		panic("email is required")
	}
	req := cm.UserAccountsRequest{Email: c.email}
	fmt.Println(c.request(cm.SubjUserAccounts, req))
}

func (c *client) updateUser() {
	if c.userFile == "" {
		panic("user jwt is required")
	}
	dat, err := ioutil.ReadFile(c.userFile)
	if err != nil {
		panic(err)
	}
	req := cm.UpdateUserRequest{Jwt: string(dat)}
	fmt.Println(c.request(cm.SubjAddUserJwt, req))
}

func main() {
	var c client
	flag.StringVar(&c.hostport, "nats hostport", "localhost:4222", "NATS hostport")
	flag.StringVar(&c.credsFile, "creds", "", "NATS credentials file")
	flag.StringVar(&c.userFile, "jwt", "", "user jwt file")
	flag.StringVar(&c.verb, "verb", "", "[get-user, get-accounts, update-user]")
	flag.StringVar(&c.email, "email", "", "associated email - for jwt or accounts")
	flag.StringVar(&c.account, "account", "", "associated account - for jwt")
	flag.Parse()

	if c.credsFile != "" {
		c.options = append(c.options, nats.UserCredentials(c.credsFile))
	}

	switch c.verb {
	case "get-user":
		c.getUser()
	case "get-accounts":
		c.getAccounts()
	case "update-user":
		c.updateUser()
	default:
		panic("verb is required")
	}
}
