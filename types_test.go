package cm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStaticEmptyConfig(t *testing.T) {
	ts := NewTestSetup(t)
	defer ts.Cleanup(t)

	var err error
	var rc ResolverConfig
	rc.Kind = Static
	rc.Users = append(rc.Users, ts.MakeUserConfig("me@x.y.z", Owner))

	akp := ts.CreateAccountPair(t)
	token := ts.Encode(t, rc, akp)
	t.Log(token)
	require.NoError(t, err)

	c, err := ParseConfig([]byte(token))
	require.NoError(t, err)
	require.NoError(t, c.Validate())

	require.Equal(t, rc.Kind, c.Kind)
	require.Len(t, c.Users, 1)
	require.Equal(t, c.Users[0].Role, rc.Users[0].Role)
	require.Equal(t, c.Users[0].Email, rc.Users[0].Email)
}
