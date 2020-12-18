// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"net/http"
	"strings"
	"sync"

	"go.pinniped.dev/internal/secret"

	"go.pinniped.dev/internal/oidc/dynamiccodec"

	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/auth"
	"go.pinniped.dev/internal/oidc/callback"
	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/discovery"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidc/token"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

// Manager can manage multiple active OIDC providers. It acts as a request router for them.
//
// It is thread-safe.
type Manager struct {
	mu                  sync.RWMutex
	providers           []*provider.FederationDomainIssuer
	providerHandlers    map[string]http.Handler  // map of all routes for all providers
	nextHandler         http.Handler             // the next handler in a chain, called when this manager didn't know how to handle a request
	dynamicJWKSProvider jwks.DynamicJWKSProvider // in-memory cache of per-issuer JWKS data
	idpListGetter       oidc.IDPListGetter       // in-memory cache of upstream IDPs
	secretCache         *secret.Cache            // in-memory cache of cryptographic material
	secretsClient       corev1client.SecretInterface
}

// NewManager returns an empty Manager.
// nextHandler will be invoked for any requests that could not be handled by this manager's providers.
// dynamicJWKSProvider will be used as an in-memory cache for per-issuer JWKS data.
// idpListGetter will be used as an in-memory cache of currently configured upstream IDPs.
func NewManager(
	nextHandler http.Handler,
	dynamicJWKSProvider jwks.DynamicJWKSProvider,
	idpListGetter oidc.IDPListGetter,
	secretCache *secret.Cache,
	secretsClient corev1client.SecretInterface,
) *Manager {
	return &Manager{
		providerHandlers:    make(map[string]http.Handler),
		nextHandler:         nextHandler,
		dynamicJWKSProvider: dynamicJWKSProvider,
		idpListGetter:       idpListGetter,
		secretCache:         secretCache,
		secretsClient:       secretsClient,
	}
}

// SetProviders adds or updates all the given providerHandlers using each provider's issuer string
// as the name of the provider to decide if it is an add or update operation.
//
// It also removes any providerHandlers that were previously added but were not passed in to
// the current invocation.
//
// This method assumes that all of the FederationDomainIssuer arguments have already been validated
// by someone else before they are passed to this method.
func (m *Manager) SetProviders(federationDomains ...*provider.FederationDomainIssuer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.providers = federationDomains
	m.providerHandlers = make(map[string]http.Handler)

	var csrfCookieEncoder = dynamiccodec.New(
		oidc.CSRFCookieLifespan,
		m.secretCache.GetCSRFCookieEncoderHashKey,
		func() []byte { return nil },
	)

	for _, incomingProvider := range federationDomains {
		issuer := incomingProvider.Issuer()
		issuerHostWithPath := strings.ToLower(incomingProvider.IssuerHost()) + "/" + incomingProvider.IssuerPath()

		tokenHMACKeyGetter := wrapGetter(incomingProvider.Issuer(), m.secretCache.GetTokenHMACKey)

		timeoutsConfiguration := oidc.DefaultOIDCTimeoutsConfiguration()

		// Use NullStorage for the authorize endpoint because we do not actually want to store anything until
		// the upstream callback endpoint is called later.
		oauthHelperWithNullStorage := oidc.FositeOauth2Helper(oidc.NullStorage{}, issuer, tokenHMACKeyGetter, nil, timeoutsConfiguration)

		// For all the other endpoints, make another oauth helper with exactly the same settings except use real storage.
		oauthHelperWithKubeStorage := oidc.FositeOauth2Helper(oidc.NewKubeStorage(m.secretsClient, timeoutsConfiguration), issuer, tokenHMACKeyGetter, m.dynamicJWKSProvider, timeoutsConfiguration)

		var upstreamStateEncoder = dynamiccodec.New(
			timeoutsConfiguration.UpstreamStateParamLifespan,
			wrapGetter(incomingProvider.Issuer(), m.secretCache.GetStateEncoderHashKey),
			wrapGetter(incomingProvider.Issuer(), m.secretCache.GetStateEncoderBlockKey),
		)

		m.providerHandlers[(issuerHostWithPath + oidc.WellKnownEndpointPath)] = discovery.NewHandler(issuer)

		m.providerHandlers[(issuerHostWithPath + oidc.JWKSEndpointPath)] = jwks.NewHandler(issuer, m.dynamicJWKSProvider)

		m.providerHandlers[(issuerHostWithPath + oidc.AuthorizationEndpointPath)] = auth.NewHandler(
			issuer,
			m.idpListGetter,
			oauthHelperWithNullStorage,
			csrftoken.Generate,
			pkce.Generate,
			nonce.Generate,
			upstreamStateEncoder,
			csrfCookieEncoder,
		)

		m.providerHandlers[(issuerHostWithPath + oidc.CallbackEndpointPath)] = callback.NewHandler(
			m.idpListGetter,
			oauthHelperWithKubeStorage,
			upstreamStateEncoder,
			csrfCookieEncoder,
			issuer+oidc.CallbackEndpointPath,
		)

		m.providerHandlers[(issuerHostWithPath + oidc.TokenEndpointPath)] = token.NewHandler(
			oauthHelperWithKubeStorage,
		)

		plog.Debug("oidc provider manager added or updated issuer", "issuer", issuer)
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

func wrapGetter(issuer string, getter func(string) []byte) func() []byte {
	return func() []byte {
		return getter(issuer)
	}
}
