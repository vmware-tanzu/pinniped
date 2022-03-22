// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/util/cert"

	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/testutil/tlsserver"
)

// TestUnwrap ensures that the http.Client structs returned by this package contain
// a transport that can be fully unwrapped to get access to the underlying TLS config.
func TestUnwrap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		f    func(*x509.CertPool) *http.Client
	}{
		{
			name: "default",
			f:    Default,
		},
		{
			name: "secure",
			f:    Secure,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p, err := x509.SystemCertPool()
			require.NoError(t, err)

			c := tt.f(p)

			tlsConfig, err := net.TLSClientConfig(c.Transport)
			require.NoError(t, err)
			require.NotNil(t, tlsConfig)

			require.NotEmpty(t, tlsConfig.NextProtos)
			require.GreaterOrEqual(t, tlsConfig.MinVersion, uint16(tls.VersionTLS12))
			require.Equal(t, p, tlsConfig.RootCAs)
		})
	}
}

func TestClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		clientFunc func(*x509.CertPool) *http.Client
		configFunc ptls.ConfigFunc
	}{
		{
			name:       "default",
			clientFunc: Default,
			configFunc: ptls.Default,
		},
		{
			name:       "secure",
			clientFunc: Secure,
			configFunc: ptls.Secure,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var sawRequest bool
			server := tlsserver.TLSTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				tlsserver.AssertTLS(t, r, tt.configFunc(nil))
				assertUserAgent(t, r)
				sawRequest = true
			}), tlsserver.RecordTLSHello)

			rootCAs, err := cert.NewPoolFromBytes(tlsserver.TLSTestServerCA(server))
			require.NoError(t, err)

			c := tt.clientFunc(rootCAs)

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
			require.NoError(t, err)

			resp, err := c.Do(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())

			require.True(t, sawRequest)
		})
	}
}

func assertUserAgent(t *testing.T, r *http.Request) {
	t.Helper()

	ua := r.Header.Get("user-agent")

	// use assert instead of require to not break the http.Handler with a panic
	assert.Contains(t, ua, ") kubernetes/")
}
