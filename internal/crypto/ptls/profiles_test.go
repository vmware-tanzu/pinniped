// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/server/options"
)

func TestDefault(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

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
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, //nolint:gosec // this is a test
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
		NextProtos: []string{"h2", "http/1.1"},
		RootCAs:    aCertPool,
	}

	require.Equal(t, expected, actual)
}

func TestSecure(t *testing.T) {
	t.Parallel()

	aCertPool := x509.NewCertPool()

	actual := Secure(aCertPool)
	expected := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		CipherSuites: nil, // TLS 1.3 ciphers are not configurable
		NextProtos:   []string{"h2", "http/1.1"},
		RootCAs:      aCertPool,
	}

	require.Equal(t, expected, actual)
}

func TestSecureServing(t *testing.T) {
	t.Parallel()

	opts := &options.SecureServingOptionsWithLoopback{SecureServingOptions: &options.SecureServingOptions{}}
	SecureServing(opts)
	require.Equal(t, options.SecureServingOptionsWithLoopback{
		SecureServingOptions: &options.SecureServingOptions{
			MinTLSVersion: "VersionTLS13",
		},
	}, *opts)
}

func TestCipherSuitesForDefault(t *testing.T) {
	t.Run("contains exactly and only the expected values", func(t *testing.T) {
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
	})

	t.Run("is a subset of TestCipherSuitesForDefaultLDAP", func(t *testing.T) {
		a1 := cipherSuitesForDefault()
		a2 := cipherSuitesForDefaultLDAP()

		require.Greater(t, len(a1), 0)
		require.GreaterOrEqual(t, len(a2), len(a1))

		a1ids := sets.New[uint16]()
		for _, suite := range a1 {
			a1ids.Insert(suite.ID)
		}
		a2ids := sets.New[uint16]()
		for _, suite := range a1 {
			a2ids.Insert(suite.ID)
		}

		require.Equal(t, 0, a1ids.Difference(a2ids).Len())
	})
}

func TestCipherSuitesForDefaultLDAP(t *testing.T) {
	t.Run("contains exactly and only the expected values", func(t *testing.T) {
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
	})

	t.Run("is a superset of TestCipherSuitesForDefault", func(t *testing.T) {
		a1 := cipherSuitesForDefault()
		a2 := cipherSuitesForDefaultLDAP()

		require.Greater(t, len(a1), 0)
		require.GreaterOrEqual(t, len(a2), len(a1))

		a1ids := sets.New[uint16]()
		for _, suite := range a1 {
			a1ids.Insert(suite.ID)
		}
		a2ids := sets.New[uint16]()
		for _, suite := range a1 {
			a2ids.Insert(suite.ID)
		}

		require.True(t, a2ids.IsSuperset(a1ids))
	})
}
