// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"net/http"
	"strings"
	"sync"

	"k8s.io/klog/v2"

	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/discovery"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/provider"
)

// Manager can manage multiple active OIDC providers. It acts as a request router for them.
//
// It is thread-safe.
type Manager struct {
	mu                  sync.RWMutex
	providers           []*provider.OIDCProvider
	providerHandlers    map[string]http.Handler  // map of all routes for all providers
	nextHandler         http.Handler             // the next handler in a chain, called when this manager didn't know how to handle a request
	dynamicJWKSProvider jwks.DynamicJWKSProvider // in-memory cache of per-issuer JWKS data
}

// NewManager returns an empty Manager.
// nextHandler will be invoked for any requests that could not be handled by this manager's providers.
// dynamicJWKSProvider will be used as an in-memory cache for per-issuer JWKS data.
func NewManager(nextHandler http.Handler, dynamicJWKSProvider jwks.DynamicJWKSProvider) *Manager {
	return &Manager{
		providerHandlers:    make(map[string]http.Handler),
		nextHandler:         nextHandler,
		dynamicJWKSProvider: dynamicJWKSProvider,
	}
}

// SetProviders adds or updates all the given providerHandlers using each provider's issuer string
// as the name of the provider to decide if it is an add or update operation.
//
// It also removes any providerHandlers that were previously added but were not passed in to
// the current invocation.
//
// This method assumes that all of the OIDCProvider arguments have already been validated
// by someone else before they are passed to this method.
func (m *Manager) SetProviders(oidcProviders ...*provider.OIDCProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.providers = oidcProviders
	m.providerHandlers = make(map[string]http.Handler)

	for _, incomingProvider := range oidcProviders {
		wellKnownURL := strings.ToLower(incomingProvider.IssuerHost()) + "/" + incomingProvider.IssuerPath() + oidc.WellKnownEndpointPath
		m.providerHandlers[wellKnownURL] = discovery.NewHandler(incomingProvider.Issuer())

		jwksURL := strings.ToLower(incomingProvider.IssuerHost()) + "/" + incomingProvider.IssuerPath() + oidc.JWKSEndpointPath
		m.providerHandlers[jwksURL] = jwks.NewHandler(incomingProvider.Issuer(), m.dynamicJWKSProvider)

		klog.InfoS("oidc provider manager added or updated issuer", "issuer", incomingProvider.Issuer())
	}
}

// ServeHTTP implements the http.Handler interface.
func (m *Manager) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	requestHandler := m.findHandler(req)

	klog.InfoS(
		"oidc provider manager examining request",
		"method", req.Method,
		"host", req.Host,
		"path", req.URL.Path,
		"foundMatchingIssuer", requestHandler != nil,
	)

	if requestHandler == nil {
		requestHandler = m.nextHandler // couldn't find an issuer to handle the request
	}
	requestHandler.ServeHTTP(resp, req)
}

func (m *Manager) findHandler(req *http.Request) http.Handler {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.providerHandlers[strings.ToLower(req.Host)+"/"+req.URL.Path]
}
