// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"net/url"
	"sync"

	"go.pinniped.dev/internal/oidcclient"
	"go.pinniped.dev/internal/oidcclient/nonce"
	"go.pinniped.dev/internal/oidcclient/pkce"
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

	AuthcodeExchanger
}

// Performs upstream OIDC authorization code exchange and token validation.
// Returns the validated raw tokens as well as the parsed claims of the ID token.
type AuthcodeExchanger interface {
	ExchangeAuthcodeAndValidateTokens(
		ctx context.Context,
		authcode string,
		pkceCodeVerifier pkce.Code,
		expectedIDTokenNonce nonce.Nonce,
	) (tokens oidcclient.Token, parsedIDTokenClaims map[string]interface{}, err error)
}

type UpstreamOIDCIdentityProvider struct {
	Name             string
	ClientID         string
	AuthorizationURL url.URL
	UsernameClaim    string
	GroupsClaim      string
	Scopes           []string
}

func (u *UpstreamOIDCIdentityProvider) GetName() string {
	return u.Name
}

func (u *UpstreamOIDCIdentityProvider) GetClientID() string {
	return u.ClientID
}

func (u *UpstreamOIDCIdentityProvider) GetAuthorizationURL() *url.URL {
	return &u.AuthorizationURL
}

func (u *UpstreamOIDCIdentityProvider) GetScopes() []string {
	return u.Scopes
}

func (u *UpstreamOIDCIdentityProvider) GetUsernameClaim() string {
	return u.UsernameClaim
}

func (u *UpstreamOIDCIdentityProvider) GetGroupsClaim() string {
	return u.GroupsClaim
}

func (u *UpstreamOIDCIdentityProvider) ExchangeAuthcodeAndValidateTokens(
	ctx context.Context,
	authcode string,
	pkceCodeVerifier pkce.Code,
	expectedIDTokenNonce nonce.Nonce,
) (oidcclient.Token, map[string]interface{}, error) {
	panic("TODO implement me") // TODO
}

type DynamicUpstreamIDPProvider interface {
	SetIDPList(oidcIDPs []UpstreamOIDCIdentityProviderI)
	GetIDPList() []UpstreamOIDCIdentityProviderI
}

type dynamicUpstreamIDPProvider struct {
	oidcProviders []UpstreamOIDCIdentityProviderI
	mutex         sync.RWMutex
}

func NewDynamicUpstreamIDPProvider() DynamicUpstreamIDPProvider {
	return &dynamicUpstreamIDPProvider{
		oidcProviders: []UpstreamOIDCIdentityProviderI{},
	}
}

func (p *dynamicUpstreamIDPProvider) SetIDPList(oidcIDPs []UpstreamOIDCIdentityProviderI) {
	p.mutex.Lock() // acquire a write lock
	defer p.mutex.Unlock()
	p.oidcProviders = oidcIDPs
}

func (p *dynamicUpstreamIDPProvider) GetIDPList() []UpstreamOIDCIdentityProviderI {
	p.mutex.RLock() // acquire a read lock
	defer p.mutex.RUnlock()
	return p.oidcProviders
}
