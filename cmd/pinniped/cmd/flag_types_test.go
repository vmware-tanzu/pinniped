// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
)

func TestConciergeModeFlag(t *testing.T) {
	var m conciergeMode
	require.Equal(t, "mode", m.Type())
	require.Equal(t, modeUnknown, m)
	require.NoError(t, m.Set(""))
	require.Equal(t, modeUnknown, m)
	require.EqualError(t, m.Set("foo"), `invalid mode "foo", valid modes are TokenCredentialRequestAPI and ImpersonationProxy`)
	require.True(t, m.MatchesFrontend(&configv1alpha1.CredentialIssuerFrontend{Type: configv1alpha1.TokenCredentialRequestAPIFrontendType}))
	require.True(t, m.MatchesFrontend(&configv1alpha1.CredentialIssuerFrontend{Type: configv1alpha1.ImpersonationProxyFrontendType}))

	require.NoError(t, m.Set("TokenCredentialRequestAPI"))
	require.Equal(t, modeTokenCredentialRequestAPI, m)
	require.Equal(t, "TokenCredentialRequestAPI", m.String())
	require.True(t, m.MatchesFrontend(&configv1alpha1.CredentialIssuerFrontend{Type: configv1alpha1.TokenCredentialRequestAPIFrontendType}))
	require.False(t, m.MatchesFrontend(&configv1alpha1.CredentialIssuerFrontend{Type: configv1alpha1.ImpersonationProxyFrontendType}))

	require.NoError(t, m.Set("tokencredentialrequestapi"))
	require.Equal(t, modeTokenCredentialRequestAPI, m)
	require.Equal(t, "TokenCredentialRequestAPI", m.String())

	require.NoError(t, m.Set("ImpersonationProxy"))
	require.Equal(t, modeImpersonationProxy, m)
	require.Equal(t, "ImpersonationProxy", m.String())
	require.False(t, m.MatchesFrontend(&configv1alpha1.CredentialIssuerFrontend{Type: configv1alpha1.TokenCredentialRequestAPIFrontendType}))
	require.True(t, m.MatchesFrontend(&configv1alpha1.CredentialIssuerFrontend{Type: configv1alpha1.ImpersonationProxyFrontendType}))

	require.NoError(t, m.Set("impersonationproxy"))
	require.Equal(t, modeImpersonationProxy, m)
	require.Equal(t, "ImpersonationProxy", m.String())
}
