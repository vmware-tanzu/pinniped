// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TLSTestServer starts a test server listening on a local port using a test CA. It returns the PEM CA bundle and the
// URL of the listening server. The lifetime of the server is bound to the provided *testing.T.
func TLSTestServer(t *testing.T, handler http.HandlerFunc) (caBundlePEM string, url string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	caBundle := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.TLS.Certificates[0].Certificate[0],
	}))
	return caBundle, server.URL
}

func TLSTestServerWithCert(t *testing.T, handler http.HandlerFunc, certificate *tls.Certificate) (url string) {
	t.Helper()

	server := http.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*certificate},
			MinVersion:   tls.VersionTLS12,
		},
		Handler: handler,
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
