/*
Copyright 2020 the Pinniped contributors. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
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
