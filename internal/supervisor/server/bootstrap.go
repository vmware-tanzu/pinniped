// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"go.uber.org/atomic"
	"k8s.io/apimachinery/pkg/util/sets"

	"go.pinniped.dev/internal/certauthority"
)

// contextKey type is unexported to prevent collisions.
type contextKey int

const bootstrapKey contextKey = iota

func withBootstrapConnCtx(ctx context.Context, _ net.Conn) context.Context {
	isBootstrap := atomic.NewBool(false) // safe for concurrent access
	return context.WithValue(ctx, bootstrapKey, isBootstrap)
}

func setIsBootstrapConn(ctx context.Context) {
	isBootstrap, _ := ctx.Value(bootstrapKey).(*atomic.Bool)
	if isBootstrap == nil {
		return
	}
	isBootstrap.Store(true)
}

func withBootstrapPaths(handler http.Handler, paths ...string) http.Handler {
	bootstrapPaths := sets.NewString(paths...)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		isBootstrap, _ := req.Context().Value(bootstrapKey).(*atomic.Bool)

		if isBootstrap != nil && isBootstrap.Load() && !bootstrapPaths.Has(req.URL.Path) {
			http.Error(w, "pinniped supervisor has invalid TLS serving certificate configuration", http.StatusInternalServerError)
			return
		}

		handler.ServeHTTP(w, req)
	})
}

func getBootstrapCert() (*tls.Certificate, error) {
	const forever = 10 * 365 * 24 * time.Hour

	bootstrapCA, err := certauthority.New("pinniped-supervisor-bootstrap-ca", forever)
	if err != nil {
		return nil, fmt.Errorf("failed to create bootstrap CA: %w", err)
	}

	bootstrapCert, err := bootstrapCA.IssueServerCert([]string{"pinniped-supervisor-bootstrap-cert"}, nil, forever)
	if err != nil {
		return nil, fmt.Errorf("failed to create bootstrap cert: %w", err)
	}

	return bootstrapCert, nil // this is just enough to complete a TLS handshake, trust distribution does not matter
}
