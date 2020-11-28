package cm

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestCm(t *testing.T) {
	ts := NewTestSetup(t)
	defer ts.Cleanup(t)

	var cm CredentialsManager
	cm.NatsHostPort = ts.ns.ClientURL()
	cm.DataDir = ts.dir
	require.NoError(t, cm.Run())

	// add a generator configuration
	akp := ts.CreateAccountPair(t)
	rc := ts.CreateResolverConfig(t, Generator)
	rc.Users = append(rc.Users, ts.MakeUserConfig("a@x.y.c", Owner))
	rc.Users = append(rc.Users, ts.MakeUserConfig("b@x.y.c", Manager))

	nc := ts.NatsClient(t, "driver")
	r, err := nc.Request("cm.config", []byte(ts.Encode(t, rc, akp)), time.Second)
	require.NoError(t, err)
	require.Empty(t, string(r.Data))
}
