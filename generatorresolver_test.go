package cm

import (
	"testing"

	"github.com/nats-io/jwt"
	"github.com/stretchr/testify/require"
)

func TestGeneratorResolver(t *testing.T) {
	ts := NewCredentialsTestSetup(t)
	defer ts.Cleanup(t)

	be := NewBackend(ts.dir)
	require.NoError(t, be.Start())

	var rc ResolverConfig
	rc.Kind = Generator
	rc.Users = append(rc.Users, ts.MakeUserConfig("a@x.y.c", Owner))
	rc.Users = append(rc.Users, ts.MakeUserConfig("b@x.y.c", Manager))

	var gc GeneratorConfig
	owner := ts.MakeRolePerm(t, Owner, []string{"dashboard.>"})
	manager := ts.MakeRolePerm(t, Manager, []string{"dashboard.manager.>"})
	gc.AddRole(owner)
	gc.AddRole(manager)
	rc.ResolverOptions = gc

	akp := ts.CreateAccountPair(t)

	cd := ts.EncodeResolverConfig(t, rc, akp)
	require.NoError(t, be.UpdateAccountConfig([]byte(cd)))

	config, err := ParseConfig([]byte(cd))
	require.NoError(t, err)

	token, err := config.GetUserJwt("a@x.y.c")
	require.NoError(t, err)
	uc, err := jwt.DecodeUserClaims(string(token))
	require.NoError(t, err)
	okp, err := owner.KeyPair()
	require.NoError(t, err)
	require.Equal(t, ts.PublicKey(t, okp), uc.Issuer)
	require.Equal(t, ts.PublicKey(t, akp), uc.IssuerAccount)

	token, err = config.GetUserJwt("b@x.y.c")
	require.NoError(t, err)
	uc, err = jwt.DecodeUserClaims(string(token))
	require.NoError(t, err)
	okp, err = manager.KeyPair()
	require.NoError(t, err)
	require.Equal(t, ts.PublicKey(t, okp), uc.Issuer)
	require.Equal(t, ts.PublicKey(t, akp), uc.IssuerAccount)
}
