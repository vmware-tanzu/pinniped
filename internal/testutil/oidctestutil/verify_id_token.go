// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidctestutil

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"testing"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

type staticKeySet struct {
	publicKey crypto.PublicKey
}

func newStaticKeySet(publicKey crypto.PublicKey) coreosoidc.KeySet {
	return &staticKeySet{publicKey}
}

func (s *staticKeySet) VerifySignature(_ context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %w", err)
	}
	return jws.Verify(s.publicKey)
}

// VerifyECDSAIDToken verifies that the provided idToken was issued via the provided jwtSigningKey.
// It also performs some light validation on the claims, i.e., it makes sure the provided idToken
// has the provided  issuer and clientID.
//
// Further validation can be done via callers via the returned coreosoidc.IDToken.
func VerifyECDSAIDToken(
	t *testing.T,
	issuer, clientID string,
	jwtSigningKey *ecdsa.PrivateKey,
	idToken string,
) *coreosoidc.IDToken {
	t.Helper()

	keySet := newStaticKeySet(jwtSigningKey.Public())
	verifyConfig := coreosoidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{coreosoidc.ES256}}
	verifier := coreosoidc.NewVerifier(issuer, keySet, &verifyConfig)
	token, err := verifier.Verify(context.Background(), idToken)
	require.NoError(t, err)

	return token
}
