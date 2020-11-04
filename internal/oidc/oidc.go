// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package oidc contains common OIDC functionality needed by Pinniped.
package oidc

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
)

const (
	WellKnownEndpointPath     = "/.well-known/openid-configuration"
	AuthorizationEndpointPath = "/oauth2/authorize"
	TokenEndpointPath         = "/oauth2/token" //nolint:gosec // ignore lint warning that this is a credential
	JWKSEndpointPath          = "/jwks.json"
)

func PinnipedCLIOIDCClient() *fosite.DefaultOpenIDConnectClient {
	return &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            "pinniped-cli",
			Public:        true,
			RedirectURIs:  []string{"http://127.0.0.1/callback"},
			ResponseTypes: []string{"code"},
			GrantTypes:    []string{"authorization_code"},
			Scopes:        []string{"openid", "profile", "email"},
		},
	}
}

// Note that Fosite requires the HMAC secret to be 32 bytes.
func FositeOauth2Helper(oauthStore interface{}, hmacSecretOfLength32 []byte) fosite.OAuth2Provider {
	oauthConfig := &compose.Config{
		EnforcePKCEForPublicClients: true,
	}

	return compose.Compose(
		oauthConfig,
		oauthStore,
		&compose.CommonStrategy{
			CoreStrategy: compose.NewOAuth2HMACStrategy(oauthConfig, hmacSecretOfLength32, nil),
		},
		nil, // hasher, defaults to using BCrypt when nil. Used for hashing client secrets.
		compose.OAuth2AuthorizeExplicitFactory,
		// compose.OAuth2RefreshTokenGrantFactory,
		// compose.OpenIDConnectExplicitFactory,
		// compose.OpenIDConnectRefreshFactory,
		compose.OAuth2PKCEFactory,
	)
}
