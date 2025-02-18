// Copyright 2021-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build fips_strict

package integration

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/util/cert"

	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/testutil/tlsserver"
	"go.pinniped.dev/test/testlib"
)

// Note: Everything in this file is an integration test only because we do not support build tags on unit tests.
// These are effectively unit tests for the ptls package when compiled in FIPS mode.

// TestFIPSCipherSuites_Parallel ensures that if the list of default FIPS cipher suites changes, then we will know.
// If this test ever fails during a golang upgrade, then we may need to change which ciphers we are using in
// the ptls package in FIPS mode.
func TestFIPSCipherSuites_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t) // this function call is required for integration tests

	server, ca := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// use the default fips config which contains a hard coded list of cipher suites
		// that should be equal to the default list of fips cipher suites.
		// assert that the client hello response has the same tls config as this test server.
		tlsserver.AssertTLS(t, r, ptls.Default)
	}), tlsserver.RecordTLSHello)

	pool, err := cert.NewPoolFromBytes(ca)
	require.NoError(t, err)
	// create a tls config that does not explicitly set cipher suites,
	// and therefore uses goboring's default fips ciphers.
	defaultConfig := &tls.Config{
		RootCAs:    pool,
		NextProtos: ptls.Default(nil).NextProtos, // we do not care about field for this test, so just make it match
	}
	transport := http.Transport{
		TLSClientConfig:   defaultConfig,
		ForceAttemptHTTP2: true,
	}
	// make a request against the test server, which will validate that the
	// tls config of the client without explicitly set ciphers
	// is the same as the tls config of the test server with explicitly
	// set ciphers from ptls.
	request, _ := http.NewRequest("GET", server.URL, nil)
	response, err := transport.RoundTrip(request)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
}

// Every profile should use the same cipher suites in FIPS mode, because FIPS requires these ciphers.
// Please treat this as a read-only const.
var expectedFIPSCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
}

func TestDefault_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t) // this function call is required for integration tests

	aCertPool := x509.NewCertPool()

	actual := ptls.Default(aCertPool)
	expected := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: expectedFIPSCipherSuites,
		NextProtos:   []string{"h2", "http/1.1"},
		RootCAs:      aCertPool,
	}

	require.Equal(t, expected, actual)
}

func TestDefaultLDAP_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t) // this function call is required for integration tests

	aCertPool := x509.NewCertPool()

	actual := ptls.DefaultLDAP(aCertPool)
	expected := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: expectedFIPSCipherSuites,
		NextProtos:   []string{"h2", "http/1.1"},
		RootCAs:      aCertPool,
	}

	require.Equal(t, expected, actual)
}

func TestSecure_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t) // this function call is required for integration tests

	aCertPool := x509.NewCertPool()

	actual := ptls.Secure(aCertPool)
	expected := &tls.Config{
		MinVersion:   tls.VersionTLS12, // allow TLS 1.2 in FIPS mode
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: expectedFIPSCipherSuites,
		NextProtos:   []string{"h2", "http/1.1"},
		RootCAs:      aCertPool,
	}

	require.Equal(t, expected, actual)
}

func TestSecureServing_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t) // this function call is required for integration tests

	opts := &options.SecureServingOptionsWithLoopback{SecureServingOptions: &options.SecureServingOptions{}}
	ptls.SecureServing(opts)

	expectedFIPSCipherSuiteNames := make([]string, len(expectedFIPSCipherSuites))
	for i, suite := range expectedFIPSCipherSuites {
		expectedFIPSCipherSuiteNames[i] = tls.CipherSuiteName(suite)
	}

	require.Equal(t, options.SecureServingOptionsWithLoopback{
		SecureServingOptions: &options.SecureServingOptions{
			CipherSuites:  expectedFIPSCipherSuiteNames,
			MinTLSVersion: "VersionTLS12", // allow TLS 1.2 in FIPS mode
		},
	}, *opts)
}
