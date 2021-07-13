// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package clientregistry

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
)

func TestStaticRegistry(t *testing.T) {
	ctx := context.Background()

	t.Run("unimplemented methods", func(t *testing.T) {
		registry := StaticClientManager{}
		require.EqualError(t, registry.ClientAssertionJWTValid(ctx, "some-token-id"), "not implemented")
		require.EqualError(t, registry.SetClientAssertionJWT(ctx, "some-token-id", time.Now()), "not implemented")
	})

	t.Run("not found", func(t *testing.T) {
		registry := StaticClientManager{}
		got, err := registry.GetClient(ctx, "does-not-exist")
		require.Error(t, err)
		require.Nil(t, got)
		rfcErr := fosite.ErrorToRFC6749Error(err)
		require.NotNil(t, rfcErr)
		require.Equal(t, rfcErr.CodeField, 404)
		require.Equal(t, rfcErr.GetDescription(), "no such client")
	})

	t.Run("pinniped CLI", func(t *testing.T) {
		registry := StaticClientManager{}
		got, err := registry.GetClient(ctx, "pinniped-cli")
		require.NoError(t, err)
		require.NotNil(t, got)
		require.IsType(t, &Client{}, got)
	})
}

func TestPinnipedCLI(t *testing.T) {
	c := PinnipedCLI()
	require.Equal(t, "pinniped-cli", c.GetID())
	require.Nil(t, c.GetHashedSecret())
	require.Equal(t, []string{"http://127.0.0.1/callback"}, c.GetRedirectURIs())
	require.Equal(t, fosite.Arguments{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"}, c.GetGrantTypes())
	require.Equal(t, fosite.Arguments{"code"}, c.GetResponseTypes())
	require.Equal(t, fosite.Arguments{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "profile", "email", "pinniped:request-audience"}, c.GetScopes())
	require.True(t, c.IsPublic())
	require.Nil(t, c.GetAudience())
	require.Nil(t, c.GetRequestURIs())
	require.Nil(t, c.GetJSONWebKeys())
	require.Equal(t, "", c.GetJSONWebKeysURI())
	require.Equal(t, "", c.GetRequestObjectSigningAlgorithm())
	require.Equal(t, "none", c.GetTokenEndpointAuthMethod())
	require.Equal(t, "RS256", c.GetTokenEndpointAuthSigningAlgorithm())
	require.Equal(t, []fosite.ResponseModeType{"", "query", "form_post"}, c.GetResponseModes())

	marshaled, err := json.Marshal(c)
	require.NoError(t, err)
	require.JSONEq(t, `
		{
		  "id": "pinniped-cli",
		  "redirect_uris": [
			"http://127.0.0.1/callback"
		  ],
		  "grant_types": [
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:token-exchange"
		  ],
		  "response_types": [
			"code"
		  ],
		  "scopes": [
			"openid",
			"offline_access",
			"profile",
			"email",
			"pinniped:request-audience"
		  ],
		  "audience": null,
		  "public": true,
		  "jwks_uri": "",
		  "jwks": null,
		  "token_endpoint_auth_method": "none",
		  "request_uris": null,
		  "request_object_signing_alg": "",
		  "token_endpoint_auth_signing_alg": "RS256"
		}`, string(marshaled))
}
