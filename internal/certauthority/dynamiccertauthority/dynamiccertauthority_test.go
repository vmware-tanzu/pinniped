// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dynamiccertauthority

import (
	"crypto/x509/pkix"
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

	goodCACrtPEM0, goodCAKeyPEM0, err := testutil.CreateCertificate(
		time.Now().Add(-time.Hour),
		time.Now().Add(time.Hour),
	)
	require.NoError(t, err)

	goodCACrtPEM1, goodCAKeyPEM1, err := testutil.CreateCertificate(
		time.Now().Add(-time.Hour),
		time.Now().Add(time.Hour),
	)
	require.NoError(t, err)

	steps := []struct {
		name               string
		caCrtPEM, caKeyPEM []byte
		wantError          string
	}{
		{
			name:      "no cert+key",
			wantError: "could not load CA: tls: failed to find any PEM data in certificate input",
		},
		{
			name:      "only cert",
			caCrtPEM:  goodCACrtPEM0,
			wantError: "could not load CA: tls: failed to find any PEM data in key input",
		},
		{
			name:      "only key",
			caKeyPEM:  goodCAKeyPEM0,
			wantError: "could not load CA: tls: failed to find any PEM data in certificate input",
		},
		{
			name:     "new cert+key",
			caCrtPEM: goodCACrtPEM0,
			caKeyPEM: goodCAKeyPEM0,
		},
		{
			name: "same cert+key",
		},
		{
			name:     "another new cert+key",
			caCrtPEM: goodCACrtPEM1,
			caKeyPEM: goodCAKeyPEM1,
		},
		{
			name:      "bad cert",
			caCrtPEM:  []byte("this is not a cert"),
			caKeyPEM:  goodCAKeyPEM0,
			wantError: "could not load CA: tls: failed to find any PEM data in certificate input",
		},
		{
			name:      "bad key",
			caCrtPEM:  goodCACrtPEM0,
			caKeyPEM:  []byte("this is not a key"),
			wantError: "could not load CA: tls: failed to find any PEM data in key input",
		},
		{
			name:      "mismatch cert+key",
			caCrtPEM:  goodCACrtPEM0,
			caKeyPEM:  goodCAKeyPEM1,
			wantError: "could not load CA: tls: private key does not match public key",
		},
		{
			name:     "good cert+key again",
			caCrtPEM: goodCACrtPEM0,
			caKeyPEM: goodCAKeyPEM0,
		},
	}
	for _, step := range steps {
		step := step
		t.Run(step.name, func(t *testing.T) {
			// Can't run these steps in parallel, because each one depends on the previous steps being
			// run.

			if step.caCrtPEM != nil || step.caKeyPEM != nil {
				provider.Set(step.caCrtPEM, step.caKeyPEM)
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

				caCrtPEM, _ := provider.CurrentCertKeyContent()
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
