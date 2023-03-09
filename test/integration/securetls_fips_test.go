// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build boringcrypto

package integration

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/util/cert"

	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/testutil/tlsserver"
	"go.pinniped.dev/test/testlib"
)

// TestFIPSCipherSuites_Parallel ensures that if the list of default fips cipher suites changes,
// we will know.  This is an integration test because we do not support build tags on unit tests.
func TestFIPSCipherSuites_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t)

	server := tlsserver.TLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// use the default fips config which contains a hard coded list of cipher suites
		// that should be equal to the default list of fips cipher suites.
		// assert that the client hello response has the same tls config as this test server.
		tlsserver.AssertTLS(t, r, ptls.Default)
	}), tlsserver.RecordTLSHello)

	ca := tlsserver.TLSTestServerCA(server)
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
