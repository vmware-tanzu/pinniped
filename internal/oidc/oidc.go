// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package oidc contains common OIDC functionality needed by Pinniped.
package oidc

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"

	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidcclient/nonce"
	"go.pinniped.dev/internal/oidcclient/pkce"
)

const (
	WellKnownEndpointPath     = "/.well-known/openid-configuration"
	AuthorizationEndpointPath = "/oauth2/authorize"
	TokenEndpointPath         = "/oauth2/token" //nolint:gosec // ignore lint warning that this is a credential
	JWKSEndpointPath          = "/jwks.json"
)

const (
	// Just in case we need to make a breaking change to the format of the upstream state param,
	// we are including a format version number. This gives the opportunity for a future version of Pinniped
	// to have the consumer of this format decide to reject versions that it doesn't understand.
	UpstreamStateParamFormatVersion = "1"

	// The `name` passed to the encoder for encoding the upstream state param value. This name is short
	// because it will be encoded into the upstream state param value and we're trying to keep that small.
	UpstreamStateParamEncodingName = "s"

	// CSRFCookieName is the name of the browser cookie which shall hold our CSRF value.
	// The `__Host` prefix has a special meaning. See
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Cookie_prefixes.
	CSRFCookieName = "__Host-pinniped-csrf"

	// CSRFCookieEncodingName is the `name` passed to the encoder for encoding and decoding the CSRF
	// cookie contents.
	CSRFCookieEncodingName = "csrf"
)

// Encoder is the encoding side of the securecookie.Codec interface.
type Encoder interface {
	Encode(name string, value interface{}) (string, error)
}

// Decoder is the decoding side of the securecookie.Codec interface.
type Decoder interface {
	Decode(name, value string, into interface{}) error
}

// Codec is both the encoding and decoding sides of the securecookie.Codec interface. It is
// interface'd here so that we properly wrap the securecookie dependency.
type Codec interface {
	Encoder
	Decoder
}

// UpstreamStateParamData is the format of the state parameter that we use when we communicate to an
// upstream OIDC provider.
//
// Keep the JSON to a minimal size because the upstream provider could impose size limitations on
// the state param.
type UpstreamStateParamData struct {
	AuthParams    string              `json:"p"`
	Nonce         nonce.Nonce         `json:"n"`
	CSRFToken     csrftoken.CSRFToken `json:"c"`
	PKCECode      pkce.Code           `json:"k"`
	FormatVersion string              `json:"v"`
}

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

func FositeOauth2Helper(oauthStore interface{}, hmacSecretOfLengthAtLeast32 []byte) fosite.OAuth2Provider {
	oauthConfig := &compose.Config{
		EnforcePKCEForPublicClients: true,
	}

	return compose.Compose(
		oauthConfig,
		oauthStore,
		&compose.CommonStrategy{
			// Note that Fosite requires the HMAC secret to be at least 32 bytes.
			CoreStrategy: compose.NewOAuth2HMACStrategy(oauthConfig, hmacSecretOfLengthAtLeast32, nil),
		},
		nil, // hasher, defaults to using BCrypt when nil. Used for hashing client secrets.
		compose.OAuth2AuthorizeExplicitFactory,
		// compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		// compose.OpenIDConnectRefreshFactory,
		compose.OAuth2PKCEFactory,
	)
}

type IDPListGetter interface {
	GetIDPList() []provider.UpstreamOIDCIdentityProviderI
}
