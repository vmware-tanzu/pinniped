// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"net/http"
	"strings"
	"sync"

	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/typed/config/v1alpha1"
	"go.pinniped.dev/internal/httputil/requestutil"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/auth"
	"go.pinniped.dev/internal/oidc/callback"
	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/discovery"
	"go.pinniped.dev/internal/oidc/dynamiccodec"
	"go.pinniped.dev/internal/oidc/idpdiscovery"
	"go.pinniped.dev/internal/oidc/idplister"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/login"
	"go.pinniped.dev/internal/oidc/oidcclientvalidator"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidc/token"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/secret"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

// Manager can manage multiple active OIDC providers. It acts as a request router for them.
//
// It is thread-safe.
type Manager struct {
	mu                  sync.RWMutex
	providers           []*provider.FederationDomainIssuer
	providerHandlers    map[string]http.Handler                   // map of all routes for all providers
	nextHandler         http.Handler                              // the next handler in a chain, called when this manager didn't know how to handle a request
	dynamicJWKSProvider jwks.DynamicJWKSProvider                  // in-memory cache of per-issuer JWKS data
	upstreamIDPs        idplister.UpstreamIdentityProvidersLister // in-memory cache of upstream IDPs
	secretCache         *secret.Cache                             // in-memory cache of cryptographic material
	secretsClient       corev1client.SecretInterface
	oidcClientsClient   v1alpha1.OIDCClientInterface
}

// NewManager returns an empty Manager.
// nextHandler will be invoked for any requests that could not be handled by this manager's providers.
// dynamicJWKSProvider will be used as an in-memory cache for per-issuer JWKS data.
// upstreamIDPs will be used as an in-memory cache of currently configured upstream IDPs.
func NewManager(
	nextHandler http.Handler,
	dynamicJWKSProvider jwks.DynamicJWKSProvider,
	upstreamIDPs idplister.UpstreamIdentityProvidersLister,
	secretCache *secret.Cache,
	secretsClient corev1client.SecretInterface,
	oidcClientsClient v1alpha1.OIDCClientInterface,
) *Manager {
	return &Manager{
		providerHandlers:    make(map[string]http.Handler),
		nextHandler:         nextHandler,
		dynamicJWKSProvider: dynamicJWKSProvider,
		upstreamIDPs:        upstreamIDPs,
		secretCache:         secretCache,
		secretsClient:       secretsClient,
		oidcClientsClient:   oidcClientsClient,
	}
}

// SetFederationDomains adds or updates all the given providerHandlers using each provider's issuer string
// as the name of the provider to decide if it is an add or update operation.
//
// It also removes any providerHandlers that were previously added but were not passed in to
// the current invocation.
//
// This method assumes that all of the FederationDomainIssuer arguments have already been validated
// by someone else before they are passed to this method.
func (m *Manager) SetFederationDomains(federationDomains ...*provider.FederationDomainIssuer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.providers = federationDomains
	m.providerHandlers = make(map[string]http.Handler)

	csrfCookieEncoder := dynamiccodec.New(
		oidc.CSRFCookieLifespan,
		m.secretCache.GetCSRFCookieEncoderHashKey,
		func() []byte { return nil },
	)

	for _, incomingFederationDomain := range federationDomains {
		issuerURL := incomingFederationDomain.Issuer()
		issuerHostWithPath := strings.ToLower(incomingFederationDomain.IssuerHost()) + "/" + incomingFederationDomain.IssuerPath()

		tokenHMACKeyGetter := wrapGetter(incomingFederationDomain.Issuer(), m.secretCache.GetTokenHMACKey)

		timeoutsConfiguration := oidc.DefaultOIDCTimeoutsConfiguration()

		// Use NullStorage for the authorize endpoint because we do not actually want to store anything until
		// the upstream callback endpoint is called later.
		oauthHelperWithNullStorage := oidc.FositeOauth2Helper(
			oidc.NewNullStorage(m.secretsClient, m.oidcClientsClient, oidcclientvalidator.DefaultMinBcryptCost),
			issuerURL,
			tokenHMACKeyGetter,
			nil,
			timeoutsConfiguration,
		)

		// For all the other endpoints, make another oauth helper with exactly the same settings except use real storage.
		oauthHelperWithKubeStorage := oidc.FositeOauth2Helper(
			oidc.NewKubeStorage(m.secretsClient, m.oidcClientsClient, timeoutsConfiguration, oidcclientvalidator.DefaultMinBcryptCost),
			issuerURL,
			tokenHMACKeyGetter,
			m.dynamicJWKSProvider,
			timeoutsConfiguration,
		)

		upstreamStateEncoder := dynamiccodec.New(
			timeoutsConfiguration.UpstreamStateParamLifespan,
			wrapGetter(incomingFederationDomain.Issuer(), m.secretCache.GetStateEncoderHashKey),
			wrapGetter(incomingFederationDomain.Issuer(), m.secretCache.GetStateEncoderBlockKey),
		)

		idpLister := provider.NewFederationDomainUpstreamIdentityProvidersLister(incomingFederationDomain, m.upstreamIDPs)

		m.providerHandlers[(issuerHostWithPath + oidc.WellKnownEndpointPath)] = discovery.NewHandler(issuerURL)

		m.providerHandlers[(issuerHostWithPath + oidc.JWKSEndpointPath)] = jwks.NewHandler(issuerURL, m.dynamicJWKSProvider)

		m.providerHandlers[(issuerHostWithPath + oidc.PinnipedIDPsPathV1Alpha1)] = idpdiscovery.NewHandler(idpLister)

		m.providerHandlers[(issuerHostWithPath + oidc.AuthorizationEndpointPath)] = auth.NewHandler(
			issuerURL,
			idpLister,
			oauthHelperWithNullStorage,
			oauthHelperWithKubeStorage,
			csrftoken.Generate,
			pkce.Generate,
			nonce.Generate,
			upstreamStateEncoder,
			csrfCookieEncoder,
		)

		m.providerHandlers[(issuerHostWithPath + oidc.CallbackEndpointPath)] = callback.NewHandler(
			idpLister,
			oauthHelperWithKubeStorage,
			upstreamStateEncoder,
			csrfCookieEncoder,
			issuerURL+oidc.CallbackEndpointPath,
		)

		m.providerHandlers[(issuerHostWithPath + oidc.TokenEndpointPath)] = token.NewHandler(
			idpLister,
			oauthHelperWithKubeStorage,
		)

		m.providerHandlers[(issuerHostWithPath + oidc.PinnipedLoginPath)] = login.NewHandler(
			upstreamStateEncoder,
			csrfCookieEncoder,
			login.NewGetHandler(incomingFederationDomain.IssuerPath()+oidc.PinnipedLoginPath),
			login.NewPostHandler(issuerURL, idpLister, oauthHelperWithKubeStorage),
		)

		plog.Debug("oidc provider manager added or updated issuer", "issuer", issuerURL)
	}
}

// ServeHTTP implements the http.Handler interface.
func (m *Manager) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	requestHandler := m.findHandler(req)

	// Using Info level so the user can safely configure a production Supervisor to show this message if they choose.
	plog.Info("received incoming request",
		"proto", req.Proto,
		"method", req.Method,
		"host", req.Host,
		"requestSNIServerName", requestutil.SNIServerName(req),
		"path", req.URL.Path,
		"remoteAddr", req.RemoteAddr,
		"foundFederationDomainRequestHandler", requestHandler != nil,
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
