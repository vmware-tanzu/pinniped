// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"net/url"
	"sync"

	"golang.org/x/oauth2"

	"go.pinniped.dev/internal/authenticators"
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

type UpstreamLDAPIdentityProviderI interface {
	// A name for this upstream provider.
	GetName() string

	// Return a URL which uniquely identifies this LDAP provider, e.g. "ldaps://host.example.com:1234".
	// This URL is not used for connecting to the provider, but rather is used for creating a globally unique user
	// identifier by being combined with the user's UID, since user UIDs are only unique within one provider.
	GetURL() *url.URL

	// A method for performing user authentication against the upstream LDAP provider.
	authenticators.UserAuthenticator
}

type DynamicUpstreamIDPProvider interface {
	SetOIDCIdentityProviders(oidcIDPs []UpstreamOIDCIdentityProviderI)
	GetOIDCIdentityProviders() []UpstreamOIDCIdentityProviderI
	SetLDAPIdentityProviders(ldapIDPs []UpstreamLDAPIdentityProviderI)
	GetLDAPIdentityProviders() []UpstreamLDAPIdentityProviderI
	SetActiveDirectoryIdentityProviders(adIDPs []UpstreamLDAPIdentityProviderI)
	GetActiveDirectoryIdentityProviders() []UpstreamLDAPIdentityProviderI
}

type dynamicUpstreamIDPProvider struct {
	oidcUpstreams            []UpstreamOIDCIdentityProviderI
	ldapUpstreams            []UpstreamLDAPIdentityProviderI
	activeDirectoryUpstreams []UpstreamLDAPIdentityProviderI
	mutex                    sync.RWMutex
}

func NewDynamicUpstreamIDPProvider() DynamicUpstreamIDPProvider {
	return &dynamicUpstreamIDPProvider{
		oidcUpstreams:            []UpstreamOIDCIdentityProviderI{},
		ldapUpstreams:            []UpstreamLDAPIdentityProviderI{},
		activeDirectoryUpstreams: []UpstreamLDAPIdentityProviderI{},
	}
}

func (p *dynamicUpstreamIDPProvider) SetOIDCIdentityProviders(oidcIDPs []UpstreamOIDCIdentityProviderI) {
	p.mutex.Lock() // acquire a write lock
	defer p.mutex.Unlock()
	p.oidcUpstreams = oidcIDPs
}

func (p *dynamicUpstreamIDPProvider) GetOIDCIdentityProviders() []UpstreamOIDCIdentityProviderI {
	p.mutex.RLock() // acquire a read lock
	defer p.mutex.RUnlock()
	return p.oidcUpstreams
}

func (p *dynamicUpstreamIDPProvider) SetLDAPIdentityProviders(ldapIDPs []UpstreamLDAPIdentityProviderI) {
	p.mutex.Lock() // acquire a write lock
	defer p.mutex.Unlock()
	p.ldapUpstreams = ldapIDPs
}

func (p *dynamicUpstreamIDPProvider) GetLDAPIdentityProviders() []UpstreamLDAPIdentityProviderI {
	p.mutex.RLock() // acquire a read lock
	defer p.mutex.RUnlock()
	return p.ldapUpstreams
}

func (p *dynamicUpstreamIDPProvider) SetActiveDirectoryIdentityProviders(adIDPs []UpstreamLDAPIdentityProviderI) {
	p.mutex.Lock() // acquire a write lock
	defer p.mutex.Unlock()
	p.activeDirectoryUpstreams = adIDPs
}

func (p *dynamicUpstreamIDPProvider) GetActiveDirectoryIdentityProviders() []UpstreamLDAPIdentityProviderI {
	p.mutex.RLock() // acquire a read lock
	defer p.mutex.RUnlock()
	return p.activeDirectoryUpstreams
}
