package cm

import (
	"github.com/nats-io/jwt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGeneratorResolver(t *testing.T) {
	ts := NewTestSetup(t)
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

	akp := ts.CreateAccount(t)

	config, err := ts.CreateConfig(t, akp, rc)
	require.NoError(t, err)
	be.UpdateConfig([]byte(config))
	require.NoError(t, err)

	var req UserAccountRequest
	req.Email = "a@x.y.c"
	res := be.GetAccountList(req)
	require.Empty(t, res.Error)
	require.Len(t, res.Accounts, 1)
	require.Equal(t, res.Account, ts.PublicKey(t, akp))
	require.NotEmpty(t, res.Jwt)

	uc, err := jwt.DecodeUserClaims(res.Jwt)
	require.NoError(t, err)
	okp, err := owner.KeyPair()
	require.NoError(t, err)
	require.Equal(t, ts.PublicKey(t, okp), uc.Issuer)
	require.Equal(t, ts.PublicKey(t, akp), uc.IssuerAccount)

}
