// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package oidc contains common OIDC functionality needed by Pinniped.
package oidc

import (
	"crypto/ecdsa"
	"time"

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
		TokenEndpointAuthMethod: "none",
	}
}

func FositeOauth2Helper(
	issuerURL string,
	oauthStore fosite.Storage,
	hmacSecretOfLengthAtLeast32 []byte,
	jwtSigningKey *ecdsa.PrivateKey,
) fosite.OAuth2Provider {
	oauthConfig := &compose.Config{
		AuthorizeCodeLifespan: 3 * time.Minute, // seems more than long enough to exchange a code

		IDTokenLifespan:     5 * time.Minute, // match clientCertificateTTL since it has similar properties to this token
		AccessTokenLifespan: 5 * time.Minute, // match clientCertificateTTL since it has similar properties to this token

		RefreshTokenLifespan: 16 * time.Hour, // long enough for a single workday

		IDTokenIssuer: issuerURL,
		TokenURL:      "", // TODO set once we have this endpoint written

		ScopeStrategy:            fosite.ExactScopeStrategy, // be careful and only support exact string matching for scopes
		AudienceMatchingStrategy: nil,                       // I believe the default is fine
		EnforcePKCE:              true,                      // follow current set of best practices and always require PKCE
		AllowedPromptValues:      []string{"none"},          // TODO unclear what we should set here

		RefreshTokenScopes:  nil, // TODO decide what makes sense when we add refresh token support
		MinParameterEntropy: 32,  // 256 bits seems about right
	}

	return compose.Compose(
		oauthConfig,
		oauthStore,
		&compose.CommonStrategy{
			// Note that Fosite requires the HMAC secret to be at least 32 bytes.
			CoreStrategy:               compose.NewOAuth2HMACStrategy(oauthConfig, hmacSecretOfLengthAtLeast32, nil),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectECDSAStrategy(oauthConfig, jwtSigningKey),
		},
		nil, // hasher, defaults to using BCrypt when nil. Used for hashing client secrets.
		compose.OAuth2AuthorizeExplicitFactory,
		// compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		// compose.OpenIDConnectRefreshFactory,
		compose.OAuth2PKCEFactory,
	)
}
