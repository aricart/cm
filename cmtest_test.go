package cm

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	natsservertest "github.com/nats-io/nats-server/v2/test"

	"github.com/nats-io/jwt"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

type CredentialsTestSetup struct {
	dir         string
	ns          *natsserver.Server
	connections []*nats.Conn
}

func NewCredentialsTestSetup(t *testing.T) *CredentialsTestSetup {
	var err error
	var ts CredentialsTestSetup
	ts.dir, err = ioutil.TempDir(os.TempDir(), "cm_")
	require.NoError(t, err)

	opts := natsservertest.DefaultTestOptions
	opts.Port = -1
	ts.ns = natsservertest.RunServer(&opts)

	return &ts
}

func (ts *CredentialsTestSetup) NatsClient(t *testing.T, name string) *nats.Conn {
	opts := nats.Options{}
	opts.Url = ts.ns.ClientURL()
	if name != "" {
		opts.Name = name
	}
	nc, err := opts.Connect()
	require.NoError(t, err)
	ts.connections = append(ts.connections, nc)
	if name != "" {
		t.Log(fmt.Printf("client %q connected to %s", name, nc.ConnectedUrl()))
	}
	return nc
}

func (ts *CredentialsTestSetup) Cleanup(t *testing.T) {
	for _, nc := range ts.connections {
		nc.Close()
	}
	if ts.ns != nil {
		ts.ns.Shutdown()
	}
	if t.Failed() {
		t.Log("test files", ts.dir)
	} else {
		require.NoError(t, os.RemoveAll(ts.dir))
	}
}

func (ts *CredentialsTestSetup) PublicKey(t *testing.T, kp nkeys.KeyPair) string {
	pk, err := kp.PublicKey()
	require.NoError(t, err)
	return pk
}

func (ts *CredentialsTestSetup) SeedKey(t *testing.T, kp nkeys.KeyPair) string {
	pk, err := kp.Seed()
	require.NoError(t, err)
	return string(pk)
}

func (ts *CredentialsTestSetup) SerializableKeys(t *testing.T, kp nkeys.KeyPair) (string, []byte) {
	pk, err := kp.PublicKey()
	require.NoError(t, err)
	seed, err := kp.Seed()
	require.NoError(t, err)
	return pk, seed
}

func (ts *CredentialsTestSetup) CreateAccountPair(t *testing.T) nkeys.KeyPair {
	kp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	return kp
}

func (ts *CredentialsTestSetup) CreateUserPair(t *testing.T) nkeys.KeyPair {
	kp, err := nkeys.CreateUser()
	require.NoError(t, err)
	return kp
}

func (ts *CredentialsTestSetup) MakeUserConfig(email string, role UserRole) User {
	return User{Email: email, Role: role}
}

func (ts *CredentialsTestSetup) MakeRolePerm(t *testing.T, role UserRole, subj []string) RolePerms {
	var r RolePerms
	r.Role = role
	r.SigningKey = ts.SeedKey(t, ts.CreateAccountPair(t))
	r.Pub = subj
	r.Sub = subj
	return r
}

func (ts *CredentialsTestSetup) Encode(t *testing.T, c jwt.Claims, kp nkeys.KeyPair) string {
	token, err := c.Encode(kp)
	require.NoError(t, err)
	return token
}

func (ts *CredentialsTestSetup) EncodeResolverConfig(t *testing.T, rc ResolverConfig, kp nkeys.KeyPair) string {
	token, err := rc.Encode(kp)
	require.NoError(t, err)
	return token
}

func (ts *CredentialsTestSetup) CreateResolverConfig(t *testing.T, kind ResolverType) ResolverConfig {
	var rc ResolverConfig
	rc.Kind = kind
	if kind == Generator {
		var gc GeneratorConfig
		gc.AddRole(ts.MakeRolePerm(t, Owner, []string{"dashboard.>"}))
		gc.AddRole(ts.MakeRolePerm(t, Manager, []string{"dashboard.manager.>"}))
		gc.AddRole(ts.MakeRolePerm(t, Monitor, []string{"dashboard.monitor.>"}))
		rc.ResolverOptions = gc
	}
	return rc
}

func (ts *CredentialsTestSetup) CreateUser(t *testing.T, email string, akp nkeys.KeyPair) string {
	uc := jwt.NewUserClaims(ts.PublicKey(t, ts.CreateUserPair(t)))
	uc.Name = email
	uc.BearerToken = true
	token, err := uc.Encode(akp)
	require.NoError(t, err)
	return token
}

func (ts *CredentialsTestSetup) ToJSON(t *testing.T, o interface{}) []byte {
	d, err := json.Marshal(o)
	require.NoError(t, err)
	return d
}

func (ts *CredentialsTestSetup) FromJSON(t *testing.T, d []byte, o interface{}) {
	err := json.Unmarshal(d, o)
	require.NoError(t, err)
}
