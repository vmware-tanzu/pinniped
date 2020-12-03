// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"

	"go.pinniped.dev/internal/oidc/jwks"
)

// TODO: doc me.
type dynamicOpenIDConnectECDSAStrategy struct {
	issuer       string
	fositeConfig *compose.Config
	jwksProvider jwks.DynamicJWKSProvider
}

var _ openid.OpenIDConnectTokenStrategy = &dynamicOpenIDConnectECDSAStrategy{}

func newDynamicOpenIDConnectECDSAStrategy(
	issuer string,
	fositeConfig *compose.Config,
	jwksProvider jwks.DynamicJWKSProvider,
) *dynamicOpenIDConnectECDSAStrategy {
	return &dynamicOpenIDConnectECDSAStrategy{
		issuer:       issuer,
		fositeConfig: fositeConfig,
		jwksProvider: jwksProvider,
	}
}

func (s *dynamicOpenIDConnectECDSAStrategy) GenerateIDToken(
	ctx context.Context,
	requester fosite.Requester,
) (string, error) {
	return "", nil
}
