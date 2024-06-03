// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/server/options"
)

func TestDefault(t *testing.T) {
	t.Parallel()

	aCertPool := x509.NewCertPool()

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

	require.Equal(t, expected, Default(aCertPool))
}

func TestDefaultLDAP(t *testing.T) {
	t.Parallel()

	aCertPool := x509.NewCertPool()

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

	require.Equal(t, expected, DefaultLDAP(aCertPool))
}

func TestSecure(t *testing.T) {
	t.Parallel()

	aCertPool := x509.NewCertPool()

	expected := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		CipherSuites: nil, // TLS 1.3 ciphers are not configurable
		NextProtos:   []string{"h2", "http/1.1"},
		RootCAs:      aCertPool,
	}

	require.Equal(t, expected, Secure(aCertPool))
}

func TestSecureServing(t *testing.T) {
	t.Parallel()

	opts := &options.SecureServingOptionsWithLoopback{SecureServingOptions: &options.SecureServingOptions{}}

	expected := options.SecureServingOptionsWithLoopback{
		SecureServingOptions: &options.SecureServingOptions{
			MinTLSVersion: "VersionTLS13",
		},
	}

	SecureServing(opts)
	require.Equal(t, expected, *opts)
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

		require.Equal(t, expected, Default(nil).CipherSuites)
	})

	t.Run("is a subset of TestCipherSuitesForDefaultLDAP", func(t *testing.T) {
		defaultSuiteIDs := Default(nil).CipherSuites
		ldapSuiteIDs := DefaultLDAP(nil).CipherSuites

		require.Greater(t, len(defaultSuiteIDs), 0)
		require.GreaterOrEqual(t, len(ldapSuiteIDs), len(defaultSuiteIDs))

		require.Equal(t, 0, sets.New[uint16](defaultSuiteIDs...).Difference(sets.New[uint16](ldapSuiteIDs...)).Len())
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

		require.Equal(t, expected, DefaultLDAP(nil).CipherSuites)
	})

	t.Run("is a superset of TestCipherSuitesForDefault", func(t *testing.T) {
		defaultSuiteIDs := Default(nil).CipherSuites
		ldapSuiteIDs := DefaultLDAP(nil).CipherSuites

		require.Greater(t, len(defaultSuiteIDs), 0)
		require.GreaterOrEqual(t, len(ldapSuiteIDs), len(defaultSuiteIDs))

		require.True(t, sets.New[uint16](ldapSuiteIDs...).IsSuperset(sets.New[uint16](defaultSuiteIDs...)))
	})
}
