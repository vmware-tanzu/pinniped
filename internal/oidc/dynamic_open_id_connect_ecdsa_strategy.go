// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"crypto/ecdsa"
	"reflect"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/plog"

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
		plog.Debug("no JWK found for issuer", "issuer", s.fositeConfig.IDTokenIssuer)
		return "", constable.Error("no JWK found for issuer")
	}
	key, ok := activeJwk.Key.(*ecdsa.PrivateKey)
	if !ok {
		actualType := "nil"
		if t := reflect.TypeOf(activeJwk.Key); t != nil {
			actualType = t.String()
		}
		plog.Debug(
			"JWK must be of type ecdsa",
			"issuer",
			s.fositeConfig.IDTokenIssuer,
			"actualType",
			actualType,
		)
		return "", constable.Error("JWK must be of type ecdsa")
	}

	// todo write story/issue about caching this strategy
	return compose.NewOpenIDConnectECDSAStrategy(s.fositeConfig, key).GenerateIDToken(ctx, requester)
}
