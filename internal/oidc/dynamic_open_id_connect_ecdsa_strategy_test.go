// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/url"
	"testing"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"

	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/oidc/oidctestutil"
)

func TestDynamicOpenIDConnectECDSAStrategy(t *testing.T) {
	const (
		goodIssuer   = "https://some-good-issuer.com"
		clientID     = "some-client-id"
		goodSubject  = "some-subject"
		goodUsername = "some-username"
		goodNonce    = "some-nonce-that-is-at-least-32-characters-to-meet-entropy-requirements"
	)

	ecPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name           string
		issuer         string
		jwksProvider   func(jwks.DynamicJWKSProvider)
		wantErrorType  *fosite.RFC6749Error
		wantErrorCause string
		wantSigningJWK *jose.JSONWebKey
	}{
		{
			name:   "jwks provider does contain signing key for issuer",
			issuer: goodIssuer,
			jwksProvider: func(provider jwks.DynamicJWKSProvider) {
				provider.SetIssuerToJWKSMap(
					nil,
					map[string]*jose.JSONWebKey{
						goodIssuer: {
							Key: ecPrivateKey,
						},
					},
				)
			},
			wantSigningJWK: &jose.JSONWebKey{
				Key: ecPrivateKey,
			},
		},
		{
			name:           "jwks provider does not contain signing key for issuer",
			issuer:         goodIssuer,
			wantErrorType:  fosite.ErrTemporarilyUnavailable,
			wantErrorCause: "no JWK found for issuer",
		},
		{
			name:   "jwks provider contains signing key of wrong type for issuer",
			issuer: goodIssuer,
			jwksProvider: func(provider jwks.DynamicJWKSProvider) {
				provider.SetIssuerToJWKSMap(
					nil,
					map[string]*jose.JSONWebKey{
						goodIssuer: {
							Key: rsaPrivateKey,
						},
					},
				)
			},
			wantErrorType:  fosite.ErrServerError,
			wantErrorCause: "JWK must be of type ecdsa",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			jwksProvider := jwks.NewDynamicJWKSProvider()
			if test.jwksProvider != nil {
				test.jwksProvider(jwksProvider)
			}
			s := newDynamicOpenIDConnectECDSAStrategy(
				&compose.Config{IDTokenIssuer: test.issuer},
				jwksProvider,
			)

			requester := &fosite.Request{
				Client: &fosite.DefaultClient{
					ID: clientID,
				},
				Session: &openid.DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: goodSubject,
					},
					Subject:  goodSubject,
					Username: goodUsername,
				},
				Form: url.Values{
					"nonce": {goodNonce},
				},
			}
			idToken, err := s.GenerateIDToken(context.Background(), requester)
			if test.wantErrorType != nil {
				require.True(t, errors.Is(err, test.wantErrorType))
				require.EqualError(t, err.(*fosite.RFC6749Error).Cause(), test.wantErrorCause)
			} else {
				require.NoError(t, err)

				privateKey, ok := test.wantSigningJWK.Key.(*ecdsa.PrivateKey)
				require.True(t, ok, "wanted private key to be *ecdsa.PrivateKey, but was %T", test.wantSigningJWK)

				// Perform a light validation on the token to make sure 1) we passed through the correct
				// signing key and 2) we forwarded the fosite.Requester correctly. Token generation is
				// tested more expansively in the token endpoint.
				token := oidctestutil.VerifyECDSAIDToken(t, goodIssuer, clientID, privateKey, idToken)
				require.Equal(t, goodSubject, token.Subject)
				require.Equal(t, goodNonce, token.Nonce)
			}
		})
	}
}
