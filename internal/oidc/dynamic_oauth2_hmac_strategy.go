// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
)

// dynamicOauth2HMACStrategy is an oauth2.CoreStrategy that can dynamically load an HMAC key to sign
// stuff (access tokens, refresh tokens, and auth codes). We want this dynamic capability since our
// controllers for loading FederationDomain's and signing keys run in parallel, and thus the signing key
// might not be ready when an FederationDomain is otherwise ready.
//
// If we ever update FederationDomain's to hold their signing key, we might not need this type, since we
// could have an invariant that routes to an FederationDomain's endpoints are only wired up if an
// FederationDomain has a valid signing key.
type dynamicOauth2HMACStrategy struct {
	fositeConfig *compose.Config
	keyFunc      func() []byte
}

var _ oauth2.CoreStrategy = &dynamicOauth2HMACStrategy{}

func newDynamicOauth2HMACStrategy(
	fositeConfig *compose.Config,
	keyFunc func() []byte,
) *dynamicOauth2HMACStrategy {
	return &dynamicOauth2HMACStrategy{
		fositeConfig: fositeConfig,
		keyFunc:      keyFunc,
	}
}

func (s *dynamicOauth2HMACStrategy) AccessTokenSignature(token string) string {
	return s.delegate().AccessTokenSignature(token)
}

func (s *dynamicOauth2HMACStrategy) GenerateAccessToken(
	ctx context.Context,
	requester fosite.Requester,
) (token string, signature string, err error) {
	return s.delegate().GenerateAccessToken(ctx, requester)
}

func (s *dynamicOauth2HMACStrategy) ValidateAccessToken(
	ctx context.Context,
	requester fosite.Requester,
	token string,
) (err error) {
	return s.delegate().ValidateAccessToken(ctx, requester, token)
}

func (s *dynamicOauth2HMACStrategy) RefreshTokenSignature(token string) string {
	return s.delegate().RefreshTokenSignature(token)
}

func (s *dynamicOauth2HMACStrategy) GenerateRefreshToken(
	ctx context.Context,
	requester fosite.Requester,
) (token string, signature string, err error) {
	return s.delegate().GenerateRefreshToken(ctx, requester)
}

func (s *dynamicOauth2HMACStrategy) ValidateRefreshToken(
	ctx context.Context,
	requester fosite.Requester,
	token string,
) (err error) {
	return s.delegate().ValidateRefreshToken(ctx, requester, token)
}

func (s *dynamicOauth2HMACStrategy) AuthorizeCodeSignature(token string) string {
	return s.delegate().AuthorizeCodeSignature(token)
}

func (s *dynamicOauth2HMACStrategy) GenerateAuthorizeCode(
	ctx context.Context,
	requester fosite.Requester,
) (token string, signature string, err error) {
	return s.delegate().GenerateAuthorizeCode(ctx, requester)
}

func (s *dynamicOauth2HMACStrategy) ValidateAuthorizeCode(
	ctx context.Context,
	requester fosite.Requester,
	token string,
) (err error) {
	return s.delegate().ValidateAuthorizeCode(ctx, requester, token)
}

func (s *dynamicOauth2HMACStrategy) delegate() *oauth2.HMACSHAStrategy {
	return compose.NewOAuth2HMACStrategy(s.fositeConfig, s.keyFunc(), nil)
}
