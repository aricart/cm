package cm

import (
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"os"
	"testing"
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

func (ts *TestSetup) serializableKeys(t *testing.T, kp nkeys.KeyPair) (string, []byte) {
	pk, err := kp.PublicKey()
	require.NoError(t, err)
	seed, err := kp.Seed()
	require.NoError(t, err)
	return pk, seed
}

func (ts *TestSetup) createAccount(t *testing.T) nkeys.KeyPair {
	kp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	return kp
}

func (ts *TestSetup) createUser(t *testing.T) nkeys.KeyPair {
	kp, err := nkeys.CreateUser()
	require.NoError(t, err)
	return kp
}

func (ts *TestSetup) makeUserConfig(email string, role UserRole) User {
	return User{Email: email, Role: role}
}

func (ts *TestSetup) makeRolePerm(role UserRole, sk string, pub []string, sub []string) RolePerms {
	var r RolePerms
	r.Role = role
	r.SigningKey = sk
	r.Pub = pub
	r.Sub = sub
	return r
}

func (ts *TestSetup) createConfig(t *testing.T, kp nkeys.KeyPair, rc ResolverConfig) (string, error) {
	var err error
	pk, _ := ts.serializableKeys(t, kp)
	gc := jwt.NewGenericClaims(pk)
	gc.Data, err = rc.Map()
	require.NoError(t, err)
	return gc.Encode(kp)
}
