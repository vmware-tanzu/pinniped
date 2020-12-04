// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"crypto/ecdsa"

	"go.pinniped.dev/internal/constable"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"

	"go.pinniped.dev/internal/oidc/jwks"
)

// TODO: doc me.
type dynamicOpenIDConnectECDSAStrategy struct {
	fositeConfig *compose.Config
	jwksProvider jwks.DynamicJWKSProvider
}

var _ openid.OpenIDConnectTokenStrategy = &dynamicOpenIDConnectECDSAStrategy{}

func newDynamicOpenIDConnectECDSAStrategy(
	fositeConfig *compose.Config,
	jwksProvider jwks.DynamicJWKSProvider,
) *dynamicOpenIDConnectECDSAStrategy {
	return &dynamicOpenIDConnectECDSAStrategy{
		fositeConfig: fositeConfig,
		jwksProvider: jwksProvider,
	}
}

func (s *dynamicOpenIDConnectECDSAStrategy) GenerateIDToken(
	ctx context.Context,
	requester fosite.Requester,
) (string, error) {
	_, activeJwk := s.jwksProvider.GetJWKS(s.fositeConfig.IDTokenIssuer)
	if activeJwk == nil {
		return "", constable.Error("No JWK found for issuer")
	}
	key, ok := activeJwk.Key.(*ecdsa.PrivateKey)
	if !ok {
		return "", constable.Error("JWK must be of type ecdsa")
	}

	// todo write story/issue about caching this strategy
	return compose.NewOpenIDConnectECDSAStrategy(s.fositeConfig, key).GenerateIDToken(ctx, requester)
}
