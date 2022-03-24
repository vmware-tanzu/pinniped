// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tlsserver

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/httpstream"

	"go.pinniped.dev/internal/crypto/ptls"
)

type ctxKey int

const (
	mapKey ctxKey = iota + 1
	helloKey
)

func TLSTestServer(t *testing.T, handler http.Handler, f func(*httptest.Server)) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(handler)
	server.TLS = ptls.Default(nil) // mimic API server config
	if f != nil {
		f(server)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TLSTestServerCA(server *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
}

func RecordTLSHello(server *httptest.Server) {
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, mapKey, &sync.Map{})
	}

	server.TLS.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		m, ok := getCtxMap(info.Context())
		if !ok {
			return nil, fmt.Errorf("could not find ctx map")
		}
		if actual, loaded := m.LoadOrStore(helloKey, info); loaded && !reflect.DeepEqual(info, actual) {
			return nil, fmt.Errorf("different client hello seen")
		}
		return nil, nil
	}
}

func AssertTLS(t *testing.T, r *http.Request, tlsConfigFunc ptls.ConfigFunc) {
	t.Helper()

	tlsConfig := tlsConfigFunc(nil)

	AssertTLSConfig(t, r, tlsConfig)
}

func AssertTLSConfig(t *testing.T, r *http.Request, tlsConfig *tls.Config) {
	t.Helper()

	m, ok := getCtxMap(r.Context())
	require.True(t, ok)

	h, ok := m.Load(helloKey)
	require.True(t, ok)

	info, ok := h.(*tls.ClientHelloInfo)
	require.True(t, ok)

	supportedVersions := []uint16{tlsConfig.MinVersion}
	ciphers := tlsConfig.CipherSuites

	if secureTLSConfig := ptls.Secure(nil); tlsConfig.MinVersion != secureTLSConfig.MinVersion {
		supportedVersions = append([]uint16{secureTLSConfig.MinVersion}, supportedVersions...)
		ciphers = append(ciphers, secureTLSConfig.CipherSuites...)
	}

	protos := tlsConfig.NextProtos
	if httpstream.IsUpgradeRequest(r) {
		protos = tlsConfig.NextProtos[1:]
	}

	helloInfoCiphers := info.CipherSuites
	sort.Slice(helloInfoCiphers, func(i, j int) bool { return helloInfoCiphers[i] < helloInfoCiphers[j] })
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	// use assert instead of require to not break the http.Handler with a panic
	ok1 := assert.Equal(t, supportedVersions, info.SupportedVersions)
	ok2 := assert.Equal(t, ciphers, helloInfoCiphers)
	ok3 := assert.Equal(t, protos, info.SupportedProtos)

	if all := ok1 && ok2 && ok3; !all {
		t.Errorf("insecure TLS detected for %q %q %q upgrade=%v supportedVersions=%v ciphers=%v protos=%v",
			r.Proto, r.Method, r.URL.String(), httpstream.IsUpgradeRequest(r), ok1, ok2, ok3)
	}
}

func getCtxMap(ctx context.Context) (*sync.Map, bool) {
	m, ok := ctx.Value(mapKey).(*sync.Map)
	return m, ok
}
