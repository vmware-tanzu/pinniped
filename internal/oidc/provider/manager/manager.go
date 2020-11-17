// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/securecookie"

	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/auth"
	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/discovery"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
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
	idpListGetter       auth.IDPListGetter       // in-memory cache of upstream IDPs
}

// NewManager returns an empty Manager.
// nextHandler will be invoked for any requests that could not be handled by this manager's providers.
// dynamicJWKSProvider will be used as an in-memory cache for per-issuer JWKS data.
// idpListGetter will be used as an in-memory cache of currently configured upstream IDPs.
func NewManager(nextHandler http.Handler, dynamicJWKSProvider jwks.DynamicJWKSProvider, idpListGetter auth.IDPListGetter) *Manager {
	return &Manager{
		providerHandlers:    make(map[string]http.Handler),
		nextHandler:         nextHandler,
		dynamicJWKSProvider: dynamicJWKSProvider,
		idpListGetter:       idpListGetter,
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

		// Use NullStorage for the authorize endpoint because we do not actually want to store anything until
		// the upstream callback endpoint is called later.
		oauthHelper := oidc.FositeOauth2Helper(oidc.NullStorage{}, []byte("some secret - must have at least 32 bytes")) // TODO replace this secret

		// TODO use different codecs for the state and the cookie, because:
		//  1. we would like to state to have an embedded expiration date while the cookie does not need that
		//  2. we would like each downstream provider to use different secrets for signing/encrypting the upstream state, not share secrets
		//  3. we would like *all* downstream providers to use the *same* signing key for the CSRF cookie (which doesn't need to be encrypted) because cookies are sent per-domain and our issuers can share a domain name (but have different paths)
		var encoderHashKey = []byte("fake-hash-secret")  // TODO replace this secret
		var encoderBlockKey = []byte("16-bytes-aaaaaaa") // TODO replace this secret
		var encoder = securecookie.New(encoderHashKey, encoderBlockKey)
		encoder.SetSerializer(securecookie.JSONEncoder{})

		authURL := strings.ToLower(incomingProvider.IssuerHost()) + "/" + incomingProvider.IssuerPath() + oidc.AuthorizationEndpointPath
		m.providerHandlers[authURL] = auth.NewHandler(incomingProvider.Issuer(), m.idpListGetter, oauthHelper, csrftoken.Generate, pkce.Generate, nonce.Generate, encoder, encoder)

		plog.Debug("oidc provider manager added or updated issuer", "issuer", incomingProvider.Issuer())
	}
}

// ServeHTTP implements the http.Handler interface.
func (m *Manager) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	requestHandler := m.findHandler(req)

	plog.Debug(
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
