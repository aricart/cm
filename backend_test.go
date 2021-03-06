package cm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBackendSimple(t *testing.T) {
	ts := NewCredentialsTestSetup(t)
	defer ts.Cleanup(t)

	be := NewBackend(ts.dir)
	require.NoError(t, be.Start())

	// add a generator configuration
	akp := ts.CreateAccountPair(t)
	t.Log("Generator Account", ts.PublicKey(t, akp))
	rc := ts.CreateResolverConfig(t, Generator)
	rc.Users = append(rc.Users, ts.MakeUserConfig("a@x.y.c", Owner))
	rc.Users = append(rc.Users, ts.MakeUserConfig("b@x.y.c", Manager))
	require.NoError(t, be.UpdateAccountConfig([]byte(ts.EncodeResolverConfig(t, rc, akp))))

	// add a static configuration
	a2kp := ts.CreateAccountPair(t)
	t.Log("Static Account", ts.PublicKey(t, a2kp))
	src := ts.CreateResolverConfig(t, Static)
	src.Users = append(src.Users, ts.MakeUserConfig("a@a.b.c", Owner))
	src.Users = append(src.Users, ts.MakeUserConfig("b@a.b.c", Manager))
	require.NoError(t, be.UpdateAccountConfig([]byte(ts.EncodeResolverConfig(t, src, a2kp))))
	// seed user a+b
	a := ts.CreateUser(t, "a@a.b.c", a2kp)
	require.NoError(t, be.AddUserJwt([]byte(a)))
	b := ts.CreateUser(t, "b@a.b.c", a2kp)
	require.NoError(t, be.AddUserJwt([]byte(b)))

	// get a generated user
	accounts, err := be.GetUserAccounts("a@x.y.c")
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	require.Equal(t, accounts[0], ts.PublicKey(t, akp))

	// get a static user
	accounts, err = be.GetUserAccounts("a@a.b.c")
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	require.Equal(t, accounts[0], ts.PublicKey(t, a2kp))

	d, err := be.GetUserJwt(accounts[0], "a@a.b.c")
	require.NoError(t, err)
	require.Equal(t, a, string(d))
}
