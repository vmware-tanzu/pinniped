// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/testutil"
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

func TestCABundleFlag(t *testing.T) {
	testCA, err := certauthority.New(pkix.Name{CommonName: "Test CA"}, 1*time.Hour)
	require.NoError(t, err)
	tmpdir := testutil.TempDir(t)
	emptyFilePath := filepath.Join(tmpdir, "empty")
	require.NoError(t, ioutil.WriteFile(emptyFilePath, []byte{}, 0600))

	testCAPath := filepath.Join(tmpdir, "testca.pem")
	require.NoError(t, ioutil.WriteFile(testCAPath, testCA.Bundle(), 0600))

	c := caBundleVar{}
	require.Equal(t, "path", c.Type())
	require.Equal(t, "", c.String())
	require.EqualError(t, c.Set("./does/not/exist"), "could not read CA bundle path: open ./does/not/exist: no such file or directory")
	require.EqualError(t, c.Set(emptyFilePath), fmt.Sprintf("failed to load any CA certificates from %q", emptyFilePath))

	require.NoError(t, c.Set(testCAPath))
	require.Equal(t, 1, bytes.Count(c, []byte("BEGIN CERTIFICATE")))

	require.NoError(t, c.Set(testCAPath))
	require.Equal(t, 2, bytes.Count(c, []byte("BEGIN CERTIFICATE")))
}
