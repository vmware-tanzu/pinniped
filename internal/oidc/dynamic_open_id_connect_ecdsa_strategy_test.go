// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	coreosoidc "github.com/coreos/go-oidc"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"

	"go.pinniped.dev/internal/oidc/jwks"
)

func TestDynamicOpenIDConnectECDSAStrategy(t *testing.T) {
	const (
		goodIssuer   = "https://some-good-issuer.com"
		clientID     = "some-client-id"
		goodSubject  = "some-subject"
		goodUsername = "some-username"
	)

	ecPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name           string
		issuer         string
		jwksProvider   func(jwks.DynamicJWKSProvider)
		wantError      string
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
			name:      "jwks provider does not contain signing key for issuer",
			issuer:    goodIssuer,
			wantError: "No JWK found for issuer",
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
			wantError: "JWK must be of type ecdsa",
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
			}
			idToken, err := s.GenerateIDToken(context.Background(), requester)
			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
			} else {
				require.NoError(t, err)

				// TODO: common-ize this code with token endpoint test.
				// TODO: make more assertions about ID token

				privateKey, ok := test.wantSigningJWK.Key.(*ecdsa.PrivateKey)
				require.True(t, ok, "wanted private key to be *ecdsa.PrivateKey, but was %T", test.wantSigningJWK)

				keySet := newStaticKeySet(privateKey.Public())
				verifyConfig := coreosoidc.Config{
					ClientID:             clientID,
					SupportedSigningAlgs: []string{coreosoidc.ES256},
				}
				verifier := coreosoidc.NewVerifier(test.issuer, keySet, &verifyConfig)
				_, err := verifier.Verify(context.Background(), idToken)
				require.NoError(t, err)
			}
		})
	}
}

// TODO: de-dep me.
func newStaticKeySet(publicKey crypto.PublicKey) coreosoidc.KeySet {
	return &staticKeySet{publicKey}
}

type staticKeySet struct {
	publicKey crypto.PublicKey
}

func (s *staticKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
	}
	return jws.Verify(s.publicKey)
}
