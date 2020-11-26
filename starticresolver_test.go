package cm

import (
	"github.com/nats-io/jwt"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmpty(t *testing.T) {
	ts := NewTestSetup(t)
	defer ts.Cleanup(t)

	r, err := NewStaticResolver(ts.dir)
	require.NoError(t, err)
	require.NotNil(t, r)

	kp := ts.createAccount(t)
	pk, _ := ts.serializableKeys(t, kp)
	d, err := r.GetConfig(pk)
	require.NoError(t, err)
	require.Nil(t, d)

	d, err = r.GetUser("me@x.y.z", pk)
	require.NoError(t, err)
	require.Nil(t, d)
}

func TestGetAccount(t *testing.T) {
	ts := NewTestSetup(t)
	defer ts.Cleanup(t)

	akp := ts.createAccount(t)
	ukp := ts.createUser(t)
	upk, _ := ts.serializableKeys(t, ukp)
	uc := jwt.NewUserClaims(upk)
	uc.Name = "me@x.y.z"
	userToken, err := uc.Encode(akp)

	r, err := NewStaticResolver(ts.dir)
	require.NoError(t, err)
	require.NotNil(t, r)
	err = r.Store([]byte(userToken))
	require.NoError(t, err)

	// get check the file we wrote
	fp := filepath.Join(r.calcUserDir(uc.Name), uc.Issuer)
	require.FileExists(t, fp)
	require.True(t, strings.HasPrefix(fp, ts.dir))
	// try reading it directly
	d, err := ioutil.ReadFile(fp)
	require.NoError(t, err)
	require.Equal(t, string(d), userToken)
	// now read it with the resolver - shouldn't be able to get it
	d, err = r.GetUser(uc.Name, uc.Issuer)
	require.NoError(t, err)
	require.Nil(t, d)

	// create a config for the account
	var rc ResolverConfig
	rc.Users = append(rc.Users, ts.makeUserConfig(uc.Name, Owner))
	config, err := ts.createConfig(t, akp, rc)
	require.NoError(t, err)
	err = r.Store([]byte(config))
	require.NoError(t, err)

	// now try to read the file again
	d, err = r.GetUser(uc.Name, uc.Issuer)
	require.NoError(t, err)
	require.Equal(t, string(d), userToken)
}
