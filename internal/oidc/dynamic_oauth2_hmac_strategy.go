// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	errorsx "github.com/pkg/errors"
)

const (
	accessTokenPrefix  = "pin_at_" // "Pinniped access token" abbreviated.
	refreshTokenPrefix = "pin_rt_" // "Pinniped refresh token" abbreviated.
	authcodePrefix     = "pin_ac_" // "Pinniped authorization code" abbreviated.
)

// dynamicOauth2HMACStrategy is an oauth2.CoreStrategy that can dynamically load an HMAC key to sign
// stuff (access tokens, refresh tokens, and auth codes). We want this dynamic capability since our
// controllers for loading FederationDomain's and signing keys run in parallel, and thus the signing key
// might not be ready when an FederationDomain is otherwise ready.
//
// If we ever update FederationDomain's to hold their signing key, we might not need this type, since we
// could have an invariant that routes to an FederationDomain's endpoints are only wired up if an
// FederationDomain has a valid signing key.
//
// Tokens start with a custom prefix to make them identifiable as tokens when seen by a user
// out of context, such as when accidentally committed to a GitHub repo.
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
	token, sig, err := s.delegate().GenerateAccessToken(ctx, requester)
	if err == nil {
		token = accessTokenPrefix + token
	}
	return token, sig, err
}

func (s *dynamicOauth2HMACStrategy) ValidateAccessToken(
	ctx context.Context,
	requester fosite.Requester,
	token string,
) (err error) {
	if !strings.HasPrefix(token, accessTokenPrefix) {
		return errorsx.WithStack(fosite.ErrInvalidTokenFormat.
			WithDebugf("Access token did not have prefix %q", accessTokenPrefix))
	}
	return s.delegate().ValidateAccessToken(ctx, requester, token[len(accessTokenPrefix):])
}

func (s *dynamicOauth2HMACStrategy) RefreshTokenSignature(token string) string {
	return s.delegate().RefreshTokenSignature(token)
}

func (s *dynamicOauth2HMACStrategy) GenerateRefreshToken(
	ctx context.Context,
	requester fosite.Requester,
) (token string, signature string, err error) {
	token, sig, err := s.delegate().GenerateRefreshToken(ctx, requester)
	if err == nil {
		token = refreshTokenPrefix + token
	}
	return token, sig, err
}

func (s *dynamicOauth2HMACStrategy) ValidateRefreshToken(
	ctx context.Context,
	requester fosite.Requester,
	token string,
) (err error) {
	if !strings.HasPrefix(token, refreshTokenPrefix) {
		return errorsx.WithStack(fosite.ErrInvalidTokenFormat.
			WithDebugf("Refresh token did not have prefix %q", refreshTokenPrefix))
	}
	return s.delegate().ValidateRefreshToken(ctx, requester, token[len(refreshTokenPrefix):])
}

func (s *dynamicOauth2HMACStrategy) AuthorizeCodeSignature(token string) string {
	return s.delegate().AuthorizeCodeSignature(token)
}

func (s *dynamicOauth2HMACStrategy) GenerateAuthorizeCode(
	ctx context.Context,
	requester fosite.Requester,
) (token string, signature string, err error) {
	authcode, sig, err := s.delegate().GenerateAuthorizeCode(ctx, requester)
	if err == nil {
		authcode = authcodePrefix + authcode
	}
	return authcode, sig, err
}

func (s *dynamicOauth2HMACStrategy) ValidateAuthorizeCode(
	ctx context.Context,
	requester fosite.Requester,
	token string,
) (err error) {
	if !strings.HasPrefix(token, authcodePrefix) {
		return errorsx.WithStack(fosite.ErrInvalidTokenFormat.
			WithDebugf("Authorization code did not have prefix %q", authcodePrefix))
	}
	return s.delegate().ValidateAuthorizeCode(ctx, requester, token[len(authcodePrefix):])
}

func (s *dynamicOauth2HMACStrategy) delegate() *oauth2.HMACSHAStrategy {
	return compose.NewOAuth2HMACStrategy(s.fositeConfig, s.keyFunc(), nil)
}
