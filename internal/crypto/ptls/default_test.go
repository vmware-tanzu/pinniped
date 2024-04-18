// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTLSSecureCipherSuites checks whether golang has changed the list of secure ciphers.
// This was written against golang 1.22.2.
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
			configuredCipherSuites: cipherSuitesForDefault(),
			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				},
				NextProtos: []string{"h2", "http/1.1"},
				RootCAs:    aCertPool,
			},
		},
		{
			name:                   "with empty inputs, returns configured cipher suites",
			configuredCipherSuites: cipherSuitesForDefault(),
			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
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
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				},
				NextProtos: []string{"h2", "http/1.1"},
				RootCAs:    aCertPool,
			},
		},
		{
			name:                   "with allowed ciphers in random order, returns ciphers in the order from configuredCipherSuites",
			configuredCipherSuites: cipherSuitesForDefaultLDAP(),
			allowedCipherIDs: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			wantConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
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

func TestDefault(t *testing.T) {
	aCertPool := x509.NewCertPool()

	actual := Default(aCertPool)
	expected := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		NextProtos: []string{"h2", "http/1.1"},
		RootCAs:    aCertPool,
	}

	require.Equal(t, expected, actual)
}

func TestDefaultLDAP(t *testing.T) {
	aCertPool := x509.NewCertPool()

	actual := DefaultLDAP(aCertPool)
	expected := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
		NextProtos: []string{"h2", "http/1.1"},
		RootCAs:    aCertPool,
	}

	require.Equal(t, expected, actual)
}

func TestValidateAllowedCiphers(t *testing.T) {
	tests := []struct {
		name               string
		allowedCipherNames []string
		wantCipherSuites   []*tls.CipherSuite
		wantErr            string
	}{
		{
			name: "empty inputs result in empty outputs",
		},
		{
			name: "with all valid inputs, returns the ciphers",
			allowedCipherNames: []string{
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			},
			wantCipherSuites: func() []*tls.CipherSuite {
				suites := cipherSuitesForDefaultLDAP()

				var result []*tls.CipherSuite
				for _, suite := range suites {
					switch suite.Name {
					case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
						"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
						"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":
						result = append(result, suite)
					default:
					}
				}
				return result
			}(),
		},
		{
			name: "with all valid inputs, allows some legacy cipher names and returns the ciphers",
			allowedCipherNames: []string{
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
			},
			wantCipherSuites: func() []*tls.CipherSuite {
				suites := cipherSuitesForDefaultLDAP()

				var result []*tls.CipherSuite
				for _, suite := range suites {
					switch suite.Name {
					case "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
						"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":
						result = append(result, suite)
					default:
					}
				}
				return result
			}(),
		},
		{
			name:               "with invalid input, return an error with all known ciphers",
			allowedCipherNames: []string{"foo"},
			wantErr:            "unrecognized ciphers [foo], ciphers must be from list [TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA]",
		},
		{
			name: "with some valid and some invalid input, return an error with all known ciphers",
			allowedCipherNames: []string{
				"foo",
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"bar",
			},
			wantErr: "unrecognized ciphers [foo, bar], ciphers must be from list [TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA]",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			actual, err := validateAllowedCiphers(tt.allowedCipherNames)
			if len(tt.wantErr) > 0 {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantCipherSuites, actual)
			}
		})
	}

}

func TestCipherSuitesForDefault(t *testing.T) {
	expected := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	actual := cipherSuitesForDefault()

	require.Equal(t, len(expected), len(actual))
	for _, suite := range actual {
		require.True(t, slices.Contains(expected, suite.ID))
	}
}

func TestCipherSuitesForDefaultLDAP(t *testing.T) {
	expected := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

		// Add these for LDAP
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	}

	actual := cipherSuitesForDefaultLDAP()

	require.Equal(t, len(expected), len(actual))
	for _, suite := range actual {
		require.True(t, slices.Contains(expected, suite.ID))
	}
}
