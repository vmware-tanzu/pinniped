// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"context"
	"net/url"

	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidcclient"
	"go.pinniped.dev/internal/oidcclient/nonce"
	"go.pinniped.dev/internal/oidcclient/pkce"
)

// Test helpers for the OIDC package.

type TestUpstreamOIDCIdentityProvider struct {
	Name                                  string
	ClientID                              string
	AuthorizationURL                      url.URL
	UsernameClaim                         string
	GroupsClaim                           string
	Scopes                                []string
	ExchangeAuthcodeAndValidateTokensFunc func(
		ctx context.Context,
		authcode string,
		pkceCodeVerifier pkce.Code,
		expectedIDTokenNonce nonce.Nonce,
	) (oidcclient.Token, map[string]interface{}, error)
}

func (u *TestUpstreamOIDCIdentityProvider) GetName() string {
	return u.Name
}

func (u *TestUpstreamOIDCIdentityProvider) GetClientID() string {
	return u.ClientID
}

func (u *TestUpstreamOIDCIdentityProvider) GetAuthorizationURL() *url.URL {
	return &u.AuthorizationURL
}

func (u *TestUpstreamOIDCIdentityProvider) GetScopes() []string {
	return u.Scopes
}

func (u *TestUpstreamOIDCIdentityProvider) GetUsernameClaim() string {
	return u.UsernameClaim
}

func (u *TestUpstreamOIDCIdentityProvider) GetGroupsClaim() string {
	return u.GroupsClaim
}

func (u *TestUpstreamOIDCIdentityProvider) ExchangeAuthcodeAndValidateTokens(
	ctx context.Context,
	authcode string,
	pkceCodeVerifier pkce.Code,
	expectedIDTokenNonce nonce.Nonce,
) (oidcclient.Token, map[string]interface{}, error) {
	return u.ExchangeAuthcodeAndValidateTokensFunc(ctx, authcode, pkceCodeVerifier, expectedIDTokenNonce)
}

func NewIDPListGetter(upstreamOIDCIdentityProviders ...TestUpstreamOIDCIdentityProvider) provider.DynamicUpstreamIDPProvider {
	idpProvider := provider.NewDynamicUpstreamIDPProvider()
	upstreams := make([]provider.UpstreamOIDCIdentityProviderI, len(upstreamOIDCIdentityProviders))
	for i := range upstreamOIDCIdentityProviders {
		upstreams[i] = provider.UpstreamOIDCIdentityProviderI(&upstreamOIDCIdentityProviders[i])
	}
	idpProvider.SetIDPList(upstreams)
	return idpProvider
}

// Declare a separate type from the production code to ensure that the state param's contents was serialized
// in the format that we expect, with the json keys that we expect, etc. This also ensure that the order of
// the serialized fields is the same, which doesn't really matter expect that we can make simpler equality
// assertions about the redirect URL in this test.
type ExpectedUpstreamStateParamFormat struct {
	P string `json:"p"`
	N string `json:"n"`
	C string `json:"c"`
	K string `json:"k"`
	V string `json:"v"`
}
