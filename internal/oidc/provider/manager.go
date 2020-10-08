// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"net/http"
	"net/url"
	"strings"
	"sync"

	"k8s.io/klog/v2"

	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/discovery"
)

// Manager can manage multiple active OIDC providers. It acts as a request router for them.
//
// It is thread-safe.
type Manager struct {
	mu               sync.RWMutex
	providerHandlers map[string]*providerHandler // map of issuer name to providerHandler
	nextHandler      http.Handler                // the next handler in a chain, called when this manager didn't know how to handle a request
}

// New returns an empty Manager.
// nextHandler will be invoked for any requests that could not be handled by this manager's providers.
func NewManager(nextHandler http.Handler) *Manager {
	return &Manager{providerHandlers: make(map[string]*providerHandler), nextHandler: nextHandler}
}

type providerHandler struct {
	provider         *OIDCProvider
	discoveryHandler http.Handler
}

func (h *providerHandler) Issuer() *url.URL {
	return h.provider.Issuer
}

// SetProviders adds or updates all the given providerHandlers using each provider's issuer string
// as the name of the provider to decide if it is an add or update operation.
//
// It also removes any providerHandlers that were previously added but were not passed in to
// the current invocation.
//
// This method assumes that all of the OIDCProvider arguments have already been validated
// by someone else before they are passed to this method.
func (c *Manager) SetProviders(oidcProviders ...*OIDCProvider) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Add all of the incoming providers.
	for _, incomingProvider := range oidcProviders {
		issuerString := incomingProvider.Issuer.String()
		c.providerHandlers[issuerString] = &providerHandler{
			provider:         incomingProvider,
			discoveryHandler: discovery.New(issuerString),
		}
		klog.InfoS("oidc provider manager added or updated issuer", "issuer", issuerString)
	}
	// Remove any providers that we previously handled but no longer exist.
	for issuerKey := range c.providerHandlers {
		if !findIssuerInListOfProviders(issuerKey, oidcProviders) {
			delete(c.providerHandlers, issuerKey)
			klog.InfoS("oidc provider manager removed issuer", "issuer", issuerKey)
		}
	}
}

// ServeHTTP implements the http.Handler interface.
func (c *Manager) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	providerHandler := c.findProviderHandlerByIssuerURL(req.Host, req.URL.Path)
	if providerHandler != nil {
		if req.URL.Path == providerHandler.Issuer().Path+oidc.WellKnownURLPath {
			providerHandler.discoveryHandler.ServeHTTP(resp, req)
			return // handled!
		}
		klog.InfoS(
			"oidc provider manager found issuer but could not handle request",
			"method", req.Method,
			"host", req.Host,
			"path", req.URL.Path,
		)
	} else {
		klog.InfoS(
			"oidc provider manager could not find issuer to handle request",
			"method", req.Method,
			"host", req.Host,
			"path", req.URL.Path,
		)
	}
	// Didn't know how to handle this request, so send it along the chain for further processing.
	c.nextHandler.ServeHTTP(resp, req)
}

func (c *Manager) findProviderHandlerByIssuerURL(host, path string) *providerHandler {
	for _, providerHandler := range c.providerHandlers {
		pi := providerHandler.Issuer()
		// TODO do we need to compare scheme? not sure how to get it from the http.Request object
		if host == pi.Host && strings.HasPrefix(path, pi.Path) { // TODO probably need better logic here? also maybe needs some of the logic from inside ServeMux
			return providerHandler
		}
	}
	return nil
}

func findIssuerInListOfProviders(issuer string, oidcProviders []*OIDCProvider) bool {
	for _, provider := range oidcProviders {
		if provider.Issuer.String() == issuer {
			return true
		}
	}
	return false
}
