// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build fips_strict

package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCipherSuitesForFIPS(t *testing.T) {
	t.Run("contains exactly and only the expected values", func(t *testing.T) {
		expected := []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		}

		actual := cipherSuitesForFIPS()

		require.Equal(t, len(expected), len(actual))
		for _, suite := range actual {
			require.True(t, slices.Contains(expected, suite.ID))
		}
	})
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
				"TLS_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_RSA_WITH_AES_256_GCM_SHA384",
			},
			wantCipherSuites: func() []*tls.CipherSuite {
				suites := cipherSuitesForFIPS()

				var result []*tls.CipherSuite
				for _, suite := range suites {
					switch suite.Name {
					case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
						"TLS_RSA_WITH_AES_128_GCM_SHA256",
						"TLS_RSA_WITH_AES_256_GCM_SHA384":
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
			wantErr:            "unrecognized ciphers [foo], ciphers must be from list [TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384]",
		},
		{
			name: "with some valid and some invalid input, return an error with all known ciphers",
			allowedCipherNames: []string{
				"foo",
				"TLS_RSA_WITH_AES_128_GCM_SHA256",
				"bar",
			},
			wantErr: "unrecognized ciphers [foo, bar], ciphers must be from list [TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384]",
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

func TestDefault(t *testing.T) {
	aCertPool := x509.NewCertPool()

	actual := Default(aCertPool)
	expected := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
		NextProtos: []string{"h2", "http/1.1"},
		RootCAs:    aCertPool,
	}

	require.Equal(t, expected, actual)
}
