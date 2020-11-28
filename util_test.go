package cm

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/nats-io/jwt"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

type TestSetup struct {
	dir string
}

func NewTestSetup(t *testing.T) *TestSetup {
	var err error
	var ts TestSetup
	ts.dir, err = ioutil.TempDir(os.TempDir(), "cm_")
	require.NoError(t, err)
	return &ts
}

func (ts *TestSetup) Cleanup(t *testing.T) {
	if t.Failed() {
		t.Log("test files", ts.dir)
	} else {
		require.NoError(t, os.RemoveAll(ts.dir))
	}
}

func (ts *TestSetup) PublicKey(t *testing.T, kp nkeys.KeyPair) string {
	pk, err := kp.PublicKey()
	require.NoError(t, err)
	return pk
}

func (ts *TestSetup) SeedKey(t *testing.T, kp nkeys.KeyPair) string {
	pk, err := kp.Seed()
	require.NoError(t, err)
	return string(pk)
}

func (ts *TestSetup) SerializableKeys(t *testing.T, kp nkeys.KeyPair) (string, []byte) {
	pk, err := kp.PublicKey()
	require.NoError(t, err)
	seed, err := kp.Seed()
	require.NoError(t, err)
	return pk, seed
}

func (ts *TestSetup) CreateAccountPair(t *testing.T) nkeys.KeyPair {
	kp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	return kp
}

func (ts *TestSetup) CreateUserPair(t *testing.T) nkeys.KeyPair {
	kp, err := nkeys.CreateUser()
	require.NoError(t, err)
	return kp
}

func (ts *TestSetup) MakeUserConfig(email string, role UserRole) User {
	return User{Email: email, Role: role}
}

func (ts *TestSetup) MakeRolePerm(t *testing.T, role UserRole, subj []string) RolePerms {
	var r RolePerms
	r.Role = role
	r.SigningKey = ts.SeedKey(t, ts.CreateAccountPair(t))
	r.Pub = subj
	r.Sub = subj
	return r
}

func (ts *TestSetup) Encode(t *testing.T, rc ResolverConfig, kp nkeys.KeyPair) string {
	token, err := rc.Encode(kp)
	require.NoError(t, err)
	return token
}

func (ts *TestSetup) CreateResolverConfig(t *testing.T, kind ResolverType) ResolverConfig {
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

func (ts *TestSetup) CreateUser(t *testing.T, email string, akp nkeys.KeyPair) string {
	uc := jwt.NewUserClaims(ts.PublicKey(t, ts.CreateUserPair(t)))
	uc.Name = email
	uc.BearerToken = true
	token, err := uc.Encode(akp)
	require.NoError(t, err)
	return token
}
