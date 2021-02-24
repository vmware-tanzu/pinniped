package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConciergeModeFlag(t *testing.T) {
	var m conciergeMode
	require.Equal(t, "mode", m.Type())
	require.Equal(t, modeTokenCredentialRequestAPI, m)
	require.EqualError(t, m.Set("foo"), `invalid mode "foo", valid modes are TokenCredentialRequestAPI and ImpersonationProxy`)

	require.NoError(t, m.Set("TokenCredentialRequestAPI"))
	require.Equal(t, modeTokenCredentialRequestAPI, m)
	require.Equal(t, "TokenCredentialRequestAPI", m.String())

	require.NoError(t, m.Set("tokencredentialrequestapi"))
	require.Equal(t, modeTokenCredentialRequestAPI, m)
	require.Equal(t, "TokenCredentialRequestAPI", m.String())

	require.NoError(t, m.Set("ImpersonationProxy"))
	require.Equal(t, modeImpersonationProxy, m)
	require.Equal(t, "ImpersonationProxy", m.String())

	require.NoError(t, m.Set("impersonationproxy"))
	require.Equal(t, modeImpersonationProxy, m)
	require.Equal(t, "ImpersonationProxy", m.String())
}
