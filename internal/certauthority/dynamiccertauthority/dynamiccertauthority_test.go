// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dynamiccertauthority

import (
	"crypto/x509/pkix"
	"io/ioutil"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/testutil"
)

func TestCAIssuePEM(t *testing.T) {
	t.Parallel()

	provider := dynamiccert.New()
	ca := New(provider)

	steps := []struct {
		name                 string
		caCrtPath, caKeyPath string
		wantError            string
	}{
		{
			name:      "no cert+key",
			wantError: "could not load CA: tls: failed to find any PEM data in certificate input",
		},
		{
			name:      "only cert",
			caCrtPath: "testdata/ca-0.crt",
			wantError: "could not load CA: tls: failed to find any PEM data in key input",
		},
		{
			name:      "only key",
			caKeyPath: "testdata/ca-0.key",
			wantError: "could not load CA: tls: failed to find any PEM data in certificate input",
		},
		{
			name:      "new cert+key",
			caCrtPath: "testdata/ca-0.crt",
			caKeyPath: "testdata/ca-0.key",
		},
		{
			name: "same cert+key",
		},
		{
			name:      "another new cert+key",
			caCrtPath: "testdata/ca-1.crt",
			caKeyPath: "testdata/ca-1.key",
		},
		{
			name:      "bad cert",
			caCrtPath: "testdata/ca-bad.crt",
			caKeyPath: "testdata/ca-0.key",
			wantError: "could not load CA: tls: failed to find any PEM data in certificate input",
		},
		{
			name:      "bad key",
			caCrtPath: "testdata/ca-0.crt",
			caKeyPath: "testdata/ca-bad.key",
			wantError: "could not load CA: tls: failed to find any PEM data in key input",
		},
		{
			name:      "mismatch cert+key",
			caCrtPath: "testdata/ca-0.crt",
			caKeyPath: "testdata/ca-1.key",
			wantError: "could not load CA: tls: private key does not match public key",
		},
		{
			name:      "good cert+key again",
			caCrtPath: "testdata/ca-1.crt",
			caKeyPath: "testdata/ca-1.key",
		},
	}
	for _, step := range steps {
		step := step
		t.Run(step.name, func(t *testing.T) {
			var caCrtPEM, caKeyPEM []byte
			var err error
			if step.caCrtPath != "" {
				caCrtPEM, err = ioutil.ReadFile(step.caCrtPath)
				require.NoError(t, err)
			}

			if step.caKeyPath != "" {
				caKeyPEM, err = ioutil.ReadFile(step.caKeyPath)
				require.NoError(t, err)
			}

			if step.caCrtPath != "" || step.caKeyPath != "" {
				provider.Set(caCrtPEM, caKeyPEM)
			} else {
				caCrtPEM, _ = provider.CurrentCertKeyContent()
			}

			crtPEM, keyPEM, err := ca.IssuePEM(
				pkix.Name{
					CommonName: "some-common-name",
				},
				[]string{"some-dns-name", "some-other-dns-name"},
				time.Hour*24,
			)

			if step.wantError != "" {
				require.EqualError(t, err, step.wantError)
				require.Empty(t, crtPEM)
				require.Empty(t, keyPEM)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, crtPEM)
				require.NotEmpty(t, keyPEM)

				crtAssertions := testutil.ValidateCertificate(t, string(caCrtPEM), string(crtPEM))
				crtAssertions.RequireCommonName("some-common-name")
				crtAssertions.RequireDNSName("some-dns-name")
				crtAssertions.RequireDNSName("some-other-dns-name")
				crtAssertions.RequireLifetime(time.Now(), time.Now().Add(time.Hour*24), time.Minute*10)
				crtAssertions.RequireMatchesPrivateKey(string(keyPEM))
			}
		})
	}
}
