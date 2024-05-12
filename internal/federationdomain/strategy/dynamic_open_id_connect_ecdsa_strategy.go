// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package strategy

import (
	"context"
	"crypto/ecdsa"
	"reflect"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/federationdomain/endpoints/jwks"
	"go.pinniped.dev/internal/plog"
)

// DynamicOpenIDConnectECDSAStrategy is an openid.OpenIDConnectTokenStrategy that can dynamically
// load a signing key to issue ID tokens. We want this dynamic capability since our controllers for
// loading FederationDomain's and signing keys run in parallel, and thus the signing key might not be
// ready when an FederationDomain is otherwise ready.
//
// If we ever update FederationDomain's to hold their signing key, we might not need this type, since we
// could have an invariant that routes to an FederationDomain's endpoints are only wired up if an
// FederationDomain has a valid signing key.
type DynamicOpenIDConnectECDSAStrategy struct {
	fositeConfig *fosite.Config
	jwksProvider jwks.DynamicJWKSProvider
}

var _ openid.OpenIDConnectTokenStrategy = &DynamicOpenIDConnectECDSAStrategy{}

func NewDynamicOpenIDConnectECDSAStrategy(
	fositeConfig *fosite.Config,
	jwksProvider jwks.DynamicJWKSProvider,
) *DynamicOpenIDConnectECDSAStrategy {
	return &DynamicOpenIDConnectECDSAStrategy{
		fositeConfig: fositeConfig,
		jwksProvider: jwksProvider,
	}
}

func (s *DynamicOpenIDConnectECDSAStrategy) GenerateIDToken(
	ctx context.Context,
	lifespan time.Duration,
	requester fosite.Requester,
) (string, error) {
	_, activeJwk := s.jwksProvider.GetJWKS(s.fositeConfig.IDTokenIssuer)
	if activeJwk == nil {
		plog.Debug("no JWK found for issuer", "issuer", s.fositeConfig.IDTokenIssuer)
		return "", fosite.ErrTemporarilyUnavailable.WithWrap(constable.Error("no JWK found for issuer"))
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
		return "", fosite.ErrServerError.WithWrap(constable.Error("JWK must be of type ecdsa"))
	}

	keyGetter := func(context.Context) (any, error) {
		return key, nil
	}
	strategy := compose.NewOpenIDConnectStrategy(keyGetter, s.fositeConfig)

	return strategy.GenerateIDToken(ctx, lifespan, requester)
}
