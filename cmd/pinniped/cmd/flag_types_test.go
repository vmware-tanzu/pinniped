// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	"go.pinniped.dev/internal/certauthority"
)

func TestConciergeModeFlag(t *testing.T) {
	var f conciergeModeFlag
	require.Equal(t, "mode", f.Type())
	require.Equal(t, modeUnknown, f)
	require.NoError(t, f.Set(""))
	require.Equal(t, modeUnknown, f)
	require.EqualError(t, f.Set("foo"), `invalid mode "foo", valid modes are TokenCredentialRequestAPI and ImpersonationProxy`)
	require.True(t, f.MatchesFrontend(&configv1alpha1.CredentialIssuerFrontend{Type: configv1alpha1.TokenCredentialRequestAPIFrontendType}))
	require.True(t, f.MatchesFrontend(&configv1alpha1.CredentialIssuerFrontend{Type: configv1alpha1.ImpersonationProxyFrontendType}))

	require.NoError(t, f.Set("TokenCredentialRequestAPI"))
	require.Equal(t, modeTokenCredentialRequestAPI, f)
	require.Equal(t, "TokenCredentialRequestAPI", f.String())
	require.True(t, f.MatchesFrontend(&configv1alpha1.CredentialIssuerFrontend{Type: configv1alpha1.TokenCredentialRequestAPIFrontendType}))
	require.False(t, f.MatchesFrontend(&configv1alpha1.CredentialIssuerFrontend{Type: configv1alpha1.ImpersonationProxyFrontendType}))

	require.NoError(t, f.Set("tokencredentialrequestapi"))
	require.Equal(t, modeTokenCredentialRequestAPI, f)
	require.Equal(t, "TokenCredentialRequestAPI", f.String())

	require.NoError(t, f.Set("ImpersonationProxy"))
	require.Equal(t, modeImpersonationProxy, f)
	require.Equal(t, "ImpersonationProxy", f.String())
	require.False(t, f.MatchesFrontend(&configv1alpha1.CredentialIssuerFrontend{Type: configv1alpha1.TokenCredentialRequestAPIFrontendType}))
	require.True(t, f.MatchesFrontend(&configv1alpha1.CredentialIssuerFrontend{Type: configv1alpha1.ImpersonationProxyFrontendType}))

	require.NoError(t, f.Set("impersonationproxy"))
	require.Equal(t, modeImpersonationProxy, f)
	require.Equal(t, "ImpersonationProxy", f.String())
}

func TestCABundleFlag(t *testing.T) {
	testCA, err := certauthority.New("Test CA", 1*time.Hour)
	require.NoError(t, err)
	tmpdir := t.TempDir()
	emptyFilePath := filepath.Join(tmpdir, "empty")
	require.NoError(t, os.WriteFile(emptyFilePath, []byte{}, 0600))

	testCAPath := filepath.Join(tmpdir, "testca.pem")
	require.NoError(t, os.WriteFile(testCAPath, testCA.Bundle(), 0600))

	f := caBundleFlag{}
	require.Equal(t, "path", f.Type())
	require.Equal(t, "", f.String())
	require.EqualError(t, f.Set("./does/not/exist"), "could not read CA bundle path: open ./does/not/exist: no such file or directory")
	require.EqualError(t, f.Set(emptyFilePath), fmt.Sprintf("failed to load any CA certificates from %q", emptyFilePath))

	require.NoError(t, f.Set(testCAPath))
	require.Equal(t, 1, bytes.Count(f, []byte("BEGIN CERTIFICATE")))

	require.NoError(t, f.Set(testCAPath))
	require.Equal(t, 2, bytes.Count(f, []byte("BEGIN CERTIFICATE")))
}
