package cm

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestStaticEmptyConfig(t *testing.T) {
	ts := NewTestSetup(t)
	defer ts.Cleanup(t)

	var err error
	var rc ResolverConfig
	rc.Kind = Static
	rc.Users = append(rc.Users, ts.makeUserConfig("me@x.y.z", Owner))

	akp := ts.createAccount(t)
	token, err := ts.createConfig(t, akp, rc)

	c, err := ParseConfig([]byte(token))
	require.NoError(t, err)
	require.NoError(t, c.Validate())

	require.Equal(t, rc.Kind, c.Kind)
	require.Len(t, c.Users, 1)
	require.Equal(t, c.Users[0].Role, rc.Users[0].Role)
	require.Equal(t, c.Users[0].Email, rc.Users[0].Email)
}
