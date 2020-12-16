package cm

import (
	"testing"
	"time"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"

	"github.com/stretchr/testify/require"
)

func TestBackend_UpdateAccount(t *testing.T) {
	ts := NewCredentialsTestSetup(t)
	defer ts.Cleanup(t)

	var cm CredentialsManager
	cm.NatsHostPort = ts.ns.ClientURL()
	cm.DataDir = ts.dir
	require.NoError(t, cm.Run())

	// add a generator configuration
	akp := ts.CreateAccountPair(t)
	rc := ts.CreateResolverConfig(t, Generator)
	rc.Users = append(rc.Users, ts.MakeUserConfig("a@x.y.z", Owner))
	rc.Users = append(rc.Users, ts.MakeUserConfig("b@x.y.z", Manager))

	nc := ts.NatsClient(t, "driver")

	// send the configuration
	var uac UpdateAccountRequest
	uac.Jwt = ts.EncodeResolverConfig(t, rc, akp)
	r, err := nc.Request(SubjUpdateAccountConfig, ts.ToJSON(t, uac), time.Second)
	require.NoError(t, err)
	var uar UpdateAccountResponse
	ts.FromJSON(t, r.Data, &uar)
	require.Empty(t, uar.Error)

	// get the configuration
	// generate the request token signed by the account
	gc := jwt.NewGenericClaims(ts.PublicKey(t, akp))
	gc.Type = DashboardConfigurationType

	payload := ts.ToJSON(t, AccountRequest{Token: ts.Encode(t, gc, akp)})
	r, err = nc.Request(SubjGetAccountConfig, payload, time.Second)
	require.NoError(t, err)
	var gacr AccountRequestResponse
	ts.FromJSON(t, r.Data, &gacr)
	require.Equal(t, uac.Jwt, gacr.Jwt)
}

func TestBackend_GetUserJwt(t *testing.T) {
	ts := NewCredentialsTestSetup(t)
	defer ts.Cleanup(t)

	c, akp := setupAccount(t, ts, Generator)

	nc := ts.NatsClient(t, "client")
	ureq := UserRequest{Email: "a@x.y.z", Account: ts.PublicKey(t, akp)}
	r, err := nc.Request(SubjGetUserJwt, ts.ToJSON(t, ureq), time.Second)
	require.NoError(t, err)
	var uresp UserResponse
	ts.FromJSON(t, r.Data, &uresp)
	require.Equal(t, "a@x.y.z", uresp.Email)

	require.NotEmpty(t, uresp.Jwt)
	uc, err := jwt.DecodeUserClaims(uresp.Jwt)
	require.NoError(t, err)
	require.Equal(t, uc.IssuerAccount, ts.PublicKey(t, akp))
	gc := c.OptionsAsGeneratorConfig()
	owner := gc.GetRole(Owner)
	okp, err := owner.KeyPair()
	require.NoError(t, err)
	require.Equal(t, uc.Issuer, ts.PublicKey(t, okp))
	require.Equal(t, uc.Name, "a@x.y.z")
}

func TestBackend_GetStaticUserJwt(t *testing.T) {
	ts := NewCredentialsTestSetup(t)
	defer ts.Cleanup(t)

	_, akp := setupAccount(t, ts, Static)

	nc := ts.NatsClient(t, "client")
	ureq := UserRequest{Email: "a@x.y.z", Account: ts.PublicKey(t, akp)}
	r, err := nc.Request(SubjGetUserJwt, ts.ToJSON(t, ureq), time.Second)
	require.NoError(t, err)
	var uresp UserResponse
	ts.FromJSON(t, r.Data, &uresp)
	require.Equal(t, "a@x.y.z", uresp.Email)
	require.Equal(t, "", uresp.Jwt)

	token := ts.CreateUser(t, "a@x.y.z", akp)
	var uur UpdateUserRequest
	uur.Jwt = token
	r, err = nc.Request(SubjAddUserJwt, ts.ToJSON(t, uur), time.Second)
	require.NoError(t, err)
	var uuresp UpdateUserResponse
	ts.FromJSON(t, r.Data, &uuresp)
	require.Empty(t, uuresp.Error)

	r, err = nc.Request(SubjGetUserJwt, ts.ToJSON(t, ureq), time.Second)
	require.NoError(t, err)
	ts.FromJSON(t, r.Data, &uresp)
	require.Equal(t, "a@x.y.z", uresp.Email)
	require.Equal(t, token, uresp.Jwt)
}

func TestBackend_ListAccounts(t *testing.T) {
	ts := NewCredentialsTestSetup(t)
	defer ts.Cleanup(t)

	_, akp := setupAccount(t, ts, Generator)

	nc := ts.NatsClient(t, "client")
	ureq := UserAccountsRequest{Email: "a@x.y.z"}
	r, err := nc.Request(SubjUserAccounts, ts.ToJSON(t, ureq), time.Second)
	require.NoError(t, err)
	var uresp UserAccountsResponse
	ts.FromJSON(t, r.Data, &uresp)
	require.Equal(t, "a@x.y.z", uresp.Email)
	require.Equal(t, ts.PublicKey(t, akp), uresp.Account)
	require.Len(t, uresp.Accounts, 1)
	require.Equal(t, ts.PublicKey(t, akp), uresp.Accounts[0])
}

func setupAccount(t *testing.T, ts *CredentialsTestSetup, kind ResolverType) (*ResolverConfig, nkeys.KeyPair) {
	var cm CredentialsManager
	cm.NatsHostPort = ts.ns.ClientURL()
	cm.DataDir = ts.dir
	require.NoError(t, cm.Run())

	// add a generator configuration
	akp := ts.CreateAccountPair(t)
	rc := ts.CreateResolverConfig(t, kind)
	rc.Users = append(rc.Users, ts.MakeUserConfig("a@x.y.z", Owner))
	rc.Users = append(rc.Users, ts.MakeUserConfig("b@x.y.z", Manager))
	rc.Users = append(rc.Users, ts.MakeUserConfig("c@x.y.z", Monitor))

	nc := ts.NatsClient(t, "driver")

	// send the configuration
	var uac UpdateAccountRequest
	uac.Jwt = ts.EncodeResolverConfig(t, rc, akp)
	r, err := nc.Request(SubjUpdateAccountConfig, ts.ToJSON(t, uac), time.Second)
	require.NoError(t, err)
	var uar UpdateAccountResponse
	ts.FromJSON(t, r.Data, &uar)
	require.Empty(t, uar.Error)

	nc.Flush()

	return &rc, akp
}
