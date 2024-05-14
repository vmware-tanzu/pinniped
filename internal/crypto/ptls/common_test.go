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
	t.Run("with valid ciphers, mutates the global state", func(t *testing.T) {
		require.Empty(t, getUserConfiguredCiphersAllowList())
		// With no user-configured allowed ciphers, expect all the hardcoded ciphers
		require.Equal(t, []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		}, Default(nil).CipherSuites)
		require.Equal(t, []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		}, DefaultLDAP(nil).CipherSuites)
		require.Empty(t, Secure(nil).CipherSuites)

		t.Cleanup(func() {
			err := SetUserConfiguredCiphersForTLSOneDotTwo(nil)
			require.NoError(t, err)
			require.Nil(t, getUserConfiguredCiphersAllowList())

			require.Equal(t, []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			}, Default(nil).CipherSuites)
			require.Equal(t, []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			}, DefaultLDAP(nil).CipherSuites)
			require.Empty(t, Secure(nil).CipherSuites)
		})

		userConfiguredAllowedCipherSuites := []string{
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", // this is an LDAP-only cipher
		}
		err := SetUserConfiguredCiphersForTLSOneDotTwo(userConfiguredAllowedCipherSuites)
		require.NoError(t, err)
		stored := getUserConfiguredCiphersAllowList()
		var storedNames []string
		for _, suite := range stored {
			storedNames = append(storedNames, suite.Name)
		}
		require.Equal(t, userConfiguredAllowedCipherSuites, storedNames)

		require.Equal(t, []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		}, Default(nil).CipherSuites)
		require.Equal(t, []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		}, DefaultLDAP(nil).CipherSuites)
		require.Empty(t, Secure(nil).CipherSuites)
	})

	t.Run("SetUserConfiguredCiphersForTLSOneDotTwo calls validateAllowedCiphers and returns error", func(t *testing.T) {
		err := SetUserConfiguredCiphersForTLSOneDotTwo([]string{"foo"})
		require.Regexp(t, regexp.QuoteMeta("unrecognized ciphers [foo], ciphers must be from list [TLS")+".*"+regexp.QuoteMeta("]"), err.Error())
	})
}

func TestConstrainCipherSuites(t *testing.T) {
	tests := []struct {
		name                              string
		hardcodedCipherSuites             []*tls.CipherSuite
		userConfiguredAllowedCipherSuites []*tls.CipherSuite
		wantCipherSuites                  []uint16
	}{
		{
			name:             "with empty inputs, returns empty output",
			wantCipherSuites: make([]uint16, 0),
		},
		{
			name: "with empty userConfiguredAllowedCipherSuites, returns hardcodedCipherSuites",
			hardcodedCipherSuites: []*tls.CipherSuite{
				{ID: 0},
				{ID: 1},
				{ID: 2},
			},
			wantCipherSuites: []uint16{0, 1, 2},
		},
		{
			name: "with userConfiguredAllowedCipherSuites, returns only ciphers found in both inputs",
			hardcodedCipherSuites: []*tls.CipherSuite{
				{ID: 0},
				{ID: 1},
				{ID: 2},
				{ID: 3},
				{ID: 4},
			},
			userConfiguredAllowedCipherSuites: []*tls.CipherSuite{
				{ID: 1},
				{ID: 3},
				{ID: 999},
			},
			wantCipherSuites: []uint16{1, 3},
		},
		{
			name: "with all invalid userConfiguredAllowedCipherSuites, returns hardcodedCipherSuites",
			hardcodedCipherSuites: []*tls.CipherSuite{
				{ID: 0},
				{ID: 1},
				{ID: 2},
				{ID: 3},
				{ID: 4},
			},
			userConfiguredAllowedCipherSuites: []*tls.CipherSuite{
				{ID: 1000},
				{ID: 2000},
				{ID: 3000},
			},
			wantCipherSuites: []uint16{0, 1, 2, 3, 4},
		},
		{
			name: "preserves order from hardcodedCipherSuites",
			hardcodedCipherSuites: []*tls.CipherSuite{
				{ID: 0},
				{ID: 1},
				{ID: 2},
				{ID: 3},
				{ID: 4},
			},
			userConfiguredAllowedCipherSuites: []*tls.CipherSuite{
				{ID: 5},
				{ID: 4},
				{ID: 3},
				{ID: 2},
			},
			wantCipherSuites: []uint16{2, 3, 4},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			actual := constrainCipherSuites(test.hardcodedCipherSuites, test.userConfiguredAllowedCipherSuites)
			require.Equal(t, test.wantCipherSuites, actual)
		})
	}
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
	t.Parallel()

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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			allowedCipherSuites := make([]*tls.CipherSuite, 0)
			for _, allowedCipher := range test.allowedCipherIDs {
				for _, cipherSuite := range tls.CipherSuites() {
					if allowedCipher == cipherSuite.ID {
						allowedCipherSuites = append(allowedCipherSuites, cipherSuite)
					}
				}
			}

			actualConfig := buildTLSConfig(test.rootCAs, test.configuredCipherSuites, allowedCipherSuites)
			require.Equal(t, test.wantConfig, actualConfig)
		})
	}
}

func TestValidateAllowedCiphers(t *testing.T) {
	cipherSuites := tls.CipherSuites()

	tests := []struct {
		name                           string
		hardCodedCipherSuites          []*tls.CipherSuite
		userConfiguredCiphersAllowList []string
		wantCipherSuites               []*tls.CipherSuite
		wantErr                        string
	}{
		{
			name: "empty inputs result in empty outputs",
		},
		{
			name:                  "with all valid inputs, returns the ciphers",
			hardCodedCipherSuites: cipherSuites,
			userConfiguredCiphersAllowList: []string{
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			},
			wantCipherSuites: func() []*tls.CipherSuite {
				var result []*tls.CipherSuite
				for _, suite := range cipherSuites {
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
			name:                  "with all valid inputs, allows some legacy cipher names and returns the ciphers",
			hardCodedCipherSuites: cipherSuites,
			userConfiguredCiphersAllowList: []string{
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
			},
			wantCipherSuites: func() []*tls.CipherSuite {
				var result []*tls.CipherSuite
				for _, suite := range cipherSuites {
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
			name:                           "with invalid input, return an error with all known ciphers",
			hardCodedCipherSuites:          cipherSuites[:2],
			userConfiguredCiphersAllowList: []string{"foo"},
			wantErr:                        "unrecognized ciphers [foo], ciphers must be from list [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384]",
		},
		{
			name:                  "with some valid and some invalid input, return an error with all known ciphers",
			hardCodedCipherSuites: cipherSuites[6:9],
			userConfiguredCiphersAllowList: []string{
				"foo",
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
				"bar",
			},
			wantErr: "unrecognized ciphers [foo, bar], ciphers must be from list [TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384]",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			actual, err := validateAllowedCiphers(test.hardCodedCipherSuites, test.userConfiguredCiphersAllowList)
			if len(test.wantErr) > 0 {
				require.ErrorContains(t, err, test.wantErr)
			} else {
				require.NoError(t, err)
				require.ElementsMatch(t, test.wantCipherSuites, actual)
			}
		})
	}
}

func TestTranslateIDIntoSecureCipherSuites(t *testing.T) {
	tests := []struct {
		name        string
		inputs      []uint16
		wantOutputs []uint16
	}{
		{
			name: "returns ciphers found in tls.CipherSuites",
			inputs: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			},
			wantOutputs: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		},
		{
			name: "returns ciphers in the input order",
			inputs: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			},
			wantOutputs: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			},
		},
		{
			name: "ignores cipher suites not returned by tls.CipherSuites",
			inputs: []uint16{
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
		},
		{
			name: "ignores cipher suites that only support TLS1.3",
			inputs: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			actual := translateIDIntoSecureCipherSuites(test.inputs)

			require.Len(t, actual, len(test.wantOutputs))
			for i, suite := range actual {
				require.Equal(t, test.wantOutputs[i], suite.ID)
			}
		})
	}
}
