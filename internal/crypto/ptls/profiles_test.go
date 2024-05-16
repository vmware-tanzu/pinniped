// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
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
