// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"net/url"
	"sync"

	"golang.org/x/oauth2"

	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

type UpstreamOIDCIdentityProviderI interface {
	// A name for this upstream provider, which will be used as a component of the path for the callback endpoint
	// hosted by the Supervisor.
	GetName() string

	// The Oauth client ID registered with the upstream provider to be used in the authorization code flow.
	GetClientID() string

	// The Authorization Endpoint fetched from discovery.
	GetAuthorizationURL() *url.URL

	// Scopes to request in authorization flow.
	GetScopes() []string

	// ID Token username claim name. May return empty string, in which case we will use some reasonable defaults.
	GetUsernameClaim() string

	// ID Token groups claim name. May return empty string, in which case we won't try to read groups from the upstream provider.
	GetGroupsClaim() string

	// Performs upstream OIDC authorization code exchange and token validation.
	// Returns the validated raw tokens as well as the parsed claims of the ID token.
	ExchangeAuthcodeAndValidateTokens(
		ctx context.Context,
		authcode string,
		pkceCodeVerifier pkce.Code,
		expectedIDTokenNonce nonce.Nonce,
		redirectURI string,
	) (*oidctypes.Token, error)

	ValidateToken(ctx context.Context, tok *oauth2.Token, expectedIDTokenNonce nonce.Nonce) (*oidctypes.Token, error)
}

type DynamicUpstreamIDPProvider interface {
	SetIDPList(oidcIDPs []UpstreamOIDCIdentityProviderI)
	GetIDPList() []UpstreamOIDCIdentityProviderI
}

type dynamicUpstreamIDPProvider struct {
	federationDomains []UpstreamOIDCIdentityProviderI
	mutex             sync.RWMutex
}

func NewDynamicUpstreamIDPProvider() DynamicUpstreamIDPProvider {
	return &dynamicUpstreamIDPProvider{
		federationDomains: []UpstreamOIDCIdentityProviderI{},
	}
}

func (p *dynamicUpstreamIDPProvider) SetIDPList(oidcIDPs []UpstreamOIDCIdentityProviderI) {
	p.mutex.Lock() // acquire a write lock
	defer p.mutex.Unlock()
	p.federationDomains = oidcIDPs
}

func (p *dynamicUpstreamIDPProvider) GetIDPList() []UpstreamOIDCIdentityProviderI {
	p.mutex.RLock() // acquire a read lock
	defer p.mutex.RUnlock()
	return p.federationDomains
}
