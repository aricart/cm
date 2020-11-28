package cm

import (
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/jwt"
	"github.com/stretchr/testify/require"
)

func TestEmpty(t *testing.T) {
	ts := NewTestSetup(t)
	defer ts.Cleanup(t)

	r, err := NewStaticResolver(ts.dir)
	require.NoError(t, err)
	require.NotNil(t, r)

	kp := ts.CreateAccountPair(t)
	pk := ts.PublicKey(t, kp)
	d, err := r.GetConfig(pk)
	require.NoError(t, err)
	require.Nil(t, d)

	d, err = r.GetUserJwt("me@x.y.z", pk)
	require.NoError(t, err)
	require.Nil(t, d)
}

func TestGetAccount(t *testing.T) {
	ts := NewTestSetup(t)
	defer ts.Cleanup(t)

	akp := ts.CreateAccountPair(t)
	ukp := ts.CreateUserPair(t)
	uc := jwt.NewUserClaims(ts.PublicKey(t, ukp))
	uc.Name = "me@x.y.z"
	userToken, err := uc.Encode(akp)
	require.NoError(t, err)

	r, err := NewStaticResolver(ts.dir)
	require.NoError(t, err)
	require.NotNil(t, r)
	err = r.StoreUserJwt([]byte(userToken))
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
	d, err = r.GetUserJwt(uc.Name, uc.Issuer)
	require.NoError(t, err)
	require.Nil(t, d)

	// create a config for the account
	var rc ResolverConfig
	rc.Users = append(rc.Users, ts.MakeUserConfig(uc.Name, Owner))
	config := ts.Encode(t, rc, akp)
	require.NoError(t, err)
	_, err = r.StoreAccountConfig([]byte(config))
	require.NoError(t, err)

	accounts, err := r.GetUserAccounts(uc.Name)
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	require.Equal(t, accounts[0], uc.Issuer)

	// now try to read the file again
	d, err = r.GetUserJwt(uc.Name, uc.Issuer)
	require.NoError(t, err)
	require.Equal(t, string(d), userToken)
}

func TestRemoveUser(t *testing.T) {
	ts := NewTestSetup(t)
	defer ts.Cleanup(t)

	akp := ts.CreateAccountPair(t)
	ukp := ts.CreateUserPair(t)
	uc := jwt.NewUserClaims(ts.PublicKey(t, ukp))
	uc.Name = "me@x.y.z"
	userToken, err := uc.Encode(akp)
	require.NoError(t, err)

	r, err := NewStaticResolver(ts.dir)
	require.NoError(t, err)
	// create a config for the account
	var rc ResolverConfig
	rc.Users = append(rc.Users, ts.MakeUserConfig(uc.Name, Owner))
	config := ts.Encode(t, rc, akp)
	require.NoError(t, err)
	_, err = r.StoreAccountConfig([]byte(config))
	require.NoError(t, err)

	fp := filepath.Join(r.calcUserDir(uc.Name), uc.Issuer)
	require.NoFileExists(t, fp)

	require.NoError(t, err)
	require.NotNil(t, r)
	err = r.StoreUserJwt([]byte(userToken))
	require.NoError(t, err)
	require.FileExists(t, fp)

	// remove the user
	rc.Users = nil
	config = ts.Encode(t, rc, akp)
	require.NoError(t, err)
	_, err = r.StoreAccountConfig([]byte(config))
	require.NoError(t, err)
	require.NoFileExists(t, fp)

	// now try to read the user
	d, err := r.GetUserJwt(uc.Name, uc.Issuer)
	require.NoError(t, err)
	require.Nil(t, d)
}

func TestRequiredDirCreated(t *testing.T) {
	ts := NewTestSetup(t)
	defer ts.Cleanup(t)

	dir := filepath.Join(ts.dir, "xxx")
	_, err := NewStaticResolver(dir)
	require.NoError(t, err)
	require.DirExists(t, dir)
}

func TestUnsuportedStoreErrors(t *testing.T) {
	ts := NewTestSetup(t)
	defer ts.Cleanup(t)

	r, err := NewStaticResolver(ts.dir)
	require.NoError(t, err)

	akp := ts.CreateAccountPair(t)
	ac := jwt.NewAccountClaims(ts.PublicKey(t, akp))
	badToken, err := ac.Encode(akp)
	require.NoError(t, err)

	_, err = r.StoreAccountConfig([]byte(badToken))
	require.Error(t, err)
	require.Contains(t, err.Error(), "bad claim type")

	gc := jwt.NewGenericClaims(ts.PublicKey(t, akp))
	gc.Type = DashboardConfigurationType
	badToken, err = gc.Encode(akp)
	require.NoError(t, err)

	_, err = r.StoreAccountConfig([]byte(badToken))
	require.Error(t, err)
	require.Contains(t, err.Error(), "bad configuration")
}
