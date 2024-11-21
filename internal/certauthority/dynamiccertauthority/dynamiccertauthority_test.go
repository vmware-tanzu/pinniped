// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dynamiccertauthority

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/cert"
	"go.pinniped.dev/internal/clientcertissuer"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/testutil"
)

func TestCAIssuePEM(t *testing.T) {
	t.Parallel()

	provider := dynamiccert.NewCA(t.Name())
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
			wantError: "TestCAIssuePEM: attempt to set invalid key pair: tls: failed to find any PEM data in key input",
		},
		{
			name:      "only key",
			caKeyPEM:  goodCAKeyPEM0,
			wantError: "TestCAIssuePEM: attempt to set invalid key pair: tls: failed to find any PEM data in certificate input",
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
			wantError: "TestCAIssuePEM: attempt to set invalid key pair: tls: failed to find any PEM data in certificate input",
		},
		{
			name:      "bad key",
			caCrtPEM:  goodCACrtPEM0,
			caKeyPEM:  []byte("this is not a key"),
			wantError: "TestCAIssuePEM: attempt to set invalid key pair: tls: failed to find any PEM data in key input",
		},
		{
			name:      "mismatch cert+key",
			caCrtPEM:  goodCACrtPEM0,
			caKeyPEM:  goodCAKeyPEM1,
			wantError: "TestCAIssuePEM: attempt to set invalid key pair: tls: private key does not match public key",
		},
		{
			name:     "good cert+key again",
			caCrtPEM: goodCACrtPEM0,
			caKeyPEM: goodCAKeyPEM0,
		},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			// Can't run these steps in parallel, because each one depends on the previous steps being
			// run.

			pem, err := issuePEM(provider, ca, step.caCrtPEM, step.caKeyPEM)

			if step.wantError != "" {
				require.EqualError(t, err, step.wantError)
				require.Nil(t, pem)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, pem.CertPEM)
				require.NotEmpty(t, pem.KeyPEM)

				caCrtPEM, _ := provider.CurrentCertKeyContent()
				crtAssertions := testutil.ValidateClientCertificate(t, string(caCrtPEM), string(pem.CertPEM))
				crtAssertions.RequireCommonName("some-username")
				crtAssertions.RequireOrganizations([]string{"some-group1", "some-group2"})
				crtAssertions.RequireLifetime(time.Now(), time.Now().Add(time.Hour*24), time.Minute*10)
				crtAssertions.RequireMatchesPrivateKey(string(pem.KeyPEM))
			}
		})
	}
}

func issuePEM(provider dynamiccert.Provider, ca clientcertissuer.ClientCertIssuer, caCrt, caKey []byte) (*cert.PEM, error) {
	// if setting fails, look at that error
	if caCrt != nil || caKey != nil {
		if err := provider.SetCertKeyContent(caCrt, caKey); err != nil {
			return nil, err
		}
	}

	// otherwise check to see if there is an issuing error
	return ca.IssueClientCertPEM("some-username", []string{"some-group1", "some-group2"}, time.Hour*24)
}
