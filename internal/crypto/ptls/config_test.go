// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetAllowedCiphersForTLSOneDotTwo(t *testing.T) {
	t.Run("SetAllowedCiphersForTLSOneDotTwo calls validateAllowedCiphers and returns error", func(t *testing.T) {
		err := SetAllowedCiphersForTLSOneDotTwo([]string{"foo"})
		require.Regexp(t, regexp.QuoteMeta("unrecognized ciphers [foo], ciphers must be from list [TLS")+".*"+regexp.QuoteMeta("]"), err.Error())
	})
}

// TestTLSSecureCipherSuites checks whether golang has changed the list of secure ciphers.
// This was written against golang 1.22.2.
// Pinniped has chosen to use only secure ciphers returned by tls.CipherSuites, so in the future we want to be aware of
// changes to this list of ciphers (additions or removals).
//
// If golang adds ciphers, we should consider adding them to the list of possible ciphers for Pinniped's profiles.
// If golang removes ciphers, we should consider removing them from the list of possible ciphers for Pinniped's profiles.
// Any cipher modifications should be added to release notes so that Pinniped admins can choose to modify their
// allowedCiphers accordingly.
func TestTLSSecureCipherSuites(t *testing.T) {
	expectedCipherSuites := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	tlsSecureCipherSuites := tls.CipherSuites()
	require.Equal(t, len(expectedCipherSuites), len(tlsSecureCipherSuites))
	for _, suite := range tlsSecureCipherSuites {
		require.False(t, suite.Insecure)
		require.Contains(t, expectedCipherSuites, suite.ID)
	}
}

func TestBuildTLSConfig(t *testing.T) {
	aCertPool := x509.NewCertPool()

	tests := []struct {
		name                   string
		rootCAs                *x509.CertPool
		configuredCipherSuites []*tls.CipherSuite
		allowedCipherIDs       []uint16
		wantConfig             *tls.Config
	}{
		{
			name:                   "happy path",
			rootCAs:                aCertPool,
			configuredCipherSuites: tls.CipherSuites(),
			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, //nolint:gosec // this is for testing purposes
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				},
				NextProtos: []string{"h2", "http/1.1"},
				RootCAs:    aCertPool,
			},
		},
		{
			name: "with no allowedCipherSuites, returns configuredCipherSuites",
			configuredCipherSuites: func() []*tls.CipherSuite {
				result := tls.CipherSuites()
				return result[:2]
			}(),
			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
				},
				NextProtos: []string{"h2", "http/1.1"},
			},
		},
		{
			name:                   "with allowed Ciphers, restricts CipherSuites to just those ciphers",
			rootCAs:                aCertPool,
			configuredCipherSuites: tls.CipherSuites(),
			allowedCipherIDs: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, //nolint:gosec // this is a test
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				},
				NextProtos: []string{"h2", "http/1.1"},
				RootCAs:    aCertPool,
			},
		},
		{
			name:                   "with allowed ciphers in random order, returns ciphers in the order from configuredCipherSuites",
			configuredCipherSuites: tls.CipherSuites(),
			allowedCipherIDs: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, //nolint:gosec // this is for testing purposes
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				},
				NextProtos: []string{"h2", "http/1.1"},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			allowedCipherSuites := make([]*tls.CipherSuite, 0)
			for _, allowedCipher := range tt.allowedCipherIDs {
				for _, cipherSuite := range tls.CipherSuites() {
					if allowedCipher == cipherSuite.ID {
						allowedCipherSuites = append(allowedCipherSuites, cipherSuite)
					}
				}
			}

			actualConfig := buildTLSConfig(tt.rootCAs, tt.configuredCipherSuites, allowedCipherSuites)
			require.Equal(t, tt.wantConfig, actualConfig)
		})
	}
}
