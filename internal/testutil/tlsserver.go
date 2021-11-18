// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/testutil/tlsserver"
)

// TLSTestServer starts a test server listening on a local port using a test CA. It returns the PEM CA bundle and the
// URL of the listening server. The lifetime of the server is bound to the provided *testing.T.
func TLSTestServer(t *testing.T, handler http.HandlerFunc) (caBundlePEM, url string) {
	t.Helper()

	server := tlsserver.TLSTestServer(t, handler, nil)

	return string(tlsserver.TLSTestServerCA(server)), server.URL
}

func TLSTestServerWithCert(t *testing.T, handler http.HandlerFunc, certificate *tls.Certificate) (url string) {
	t.Helper()

	c := ptls.Default(nil) // mimic API server config
	c.Certificates = []tls.Certificate{*certificate}

	server := http.Server{
		TLSConfig: c,
		Handler:   handler,
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	serverShutdownChan := make(chan error)
	go func() {
		// Empty certFile and keyFile will use certs from Server.TLSConfig.
		serverShutdownChan <- server.ServeTLS(l, "", "")
	}()

	t.Cleanup(func() {
		_ = server.Close()
		serveErr := <-serverShutdownChan
		if !errors.Is(serveErr, http.ErrServerClosed) {
			t.Log("Got an unexpected error while starting the fake http server!")
			require.NoError(t, serveErr)
		}
	})

	return l.Addr().String()
}
