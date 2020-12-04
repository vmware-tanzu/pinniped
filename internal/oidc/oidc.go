// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package oidc contains common OIDC functionality needed by Pinniped.
package oidc

import (
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"

	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

const (
	WellKnownEndpointPath     = "/.well-known/openid-configuration"
	AuthorizationEndpointPath = "/oauth2/authorize"
	TokenEndpointPath         = "/oauth2/token" //nolint:gosec // ignore lint warning that this is a credential
	CallbackEndpointPath      = "/callback"
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
	// The `__Host` prefix has a special meaning. See:
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
	UpstreamName  string              `json:"u"`
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
		TokenEndpointAuthMethod: "none",
	}
}

func FositeOauth2Helper(
	oauthStore interface{},
	issuer string,
	hmacSecretOfLengthAtLeast32 []byte,
	jwksProvider jwks.DynamicJWKSProvider,
) fosite.OAuth2Provider {
	oauthConfig := &compose.Config{
		AuthorizeCodeLifespan: 3 * time.Minute, // seems more than long enough to exchange a code

		IDTokenLifespan:     5 * time.Minute, // match clientCertificateTTL since it has similar properties to this token
		AccessTokenLifespan: 5 * time.Minute, // match clientCertificateTTL since it has similar properties to this token

		RefreshTokenLifespan: 16 * time.Hour, // long enough for a single workday

		IDTokenIssuer: issuer,

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
			OpenIDConnectTokenStrategy: newDynamicOpenIDConnectECDSAStrategy(oauthConfig, jwksProvider),
		},
		nil, // hasher, defaults to using BCrypt when nil. Used for hashing client secrets.
		compose.OAuth2AuthorizeExplicitFactory,
		// compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		// compose.OpenIDConnectRefreshFactory,
		compose.OAuth2PKCEFactory,
	)
}

// FositeErrorForLog generates a list of information about the provided Fosite error that can be
// passed to a plog function (e.g., plog.Info()).
//
// Sample usage:
//   err := someFositeLibraryFunction()
//   if err != nil {
//     	plog.Info("some error", FositeErrorForLog(err)...)
//      ...
//    }
func FositeErrorForLog(err error) []interface{} {
	rfc6749Error := fosite.ErrorToRFC6749Error(err)
	keysAndValues := make([]interface{}, 0)
	keysAndValues = append(keysAndValues, "name")
	keysAndValues = append(keysAndValues, rfc6749Error.Name)
	keysAndValues = append(keysAndValues, "status")
	keysAndValues = append(keysAndValues, rfc6749Error.Status())
	keysAndValues = append(keysAndValues, "description")
	keysAndValues = append(keysAndValues, rfc6749Error.Description)
	return keysAndValues
}

type IDPListGetter interface {
	GetIDPList() []provider.UpstreamOIDCIdentityProviderI
}
