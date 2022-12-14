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
	pinAccessTokenPrefix = "pin_at_" // "Pinniped access token" abbreviated.
	oryAccessTokenPrefix = "ory_at_"

	pinRefreshTokenPrefix = "pin_rt_" // "Pinniped refresh token" abbreviated.
	oryRefreshTokenPrefix = "ory_rt_"

	pinAuthcodePrefix = "pin_ac_" // "Pinniped authorization code" abbreviated.
	oryAuthcodePrefix = "ory_ac_"
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
// out of context, such as when accidentally committed to a GitHub repo. After we implemented the
// custom prefix feature, fosite later added the same feature, but did not make the prefix customizable.
// Therefore, this code has been updated to replace the fosite prefix with our custom prefix.
type dynamicOauth2HMACStrategy struct {
	fositeConfig *fosite.Config
	keyFunc      func() []byte
}

var _ oauth2.CoreStrategy = &dynamicOauth2HMACStrategy{}

func newDynamicOauth2HMACStrategy(
	fositeConfig *fosite.Config,
	keyFunc func() []byte,
) *dynamicOauth2HMACStrategy {
	return &dynamicOauth2HMACStrategy{
		fositeConfig: fositeConfig,
		keyFunc:      keyFunc,
	}
}

func replacePrefix(s, prefixToReplace, newPrefix string) string {
	return newPrefix + strings.TrimPrefix(s, prefixToReplace)
}

func (s *dynamicOauth2HMACStrategy) AccessTokenSignature(ctx context.Context, token string) string {
	return s.delegate().AccessTokenSignature(ctx, token)
}

func (s *dynamicOauth2HMACStrategy) GenerateAccessToken(
	ctx context.Context,
	requester fosite.Requester,
) (string, string, error) {
	token, sig, err := s.delegate().GenerateAccessToken(ctx, requester)
	if err == nil {
		if !strings.HasPrefix(token, oryAccessTokenPrefix) {
			// This would only happen if fosite changed how it generates tokens. Defensive programming here.
			return "", "", errorsx.WithStack(fosite.ErrInvalidTokenFormat.
				WithDebugf("Generated token does not have expected prefix"))
		}
		token = replacePrefix(token, oryAccessTokenPrefix, pinAccessTokenPrefix)
	}
	return token, sig, err
}

func (s *dynamicOauth2HMACStrategy) ValidateAccessToken(
	ctx context.Context,
	requester fosite.Requester,
	token string,
) error {
	if !strings.HasPrefix(token, pinAccessTokenPrefix) {
		return errorsx.WithStack(fosite.ErrInvalidTokenFormat.
			WithDebugf("Access token did not have prefix %q", pinAccessTokenPrefix))
	}
	return s.delegate().ValidateAccessToken(ctx, requester, replacePrefix(token, pinAccessTokenPrefix, oryAccessTokenPrefix))
}

func (s *dynamicOauth2HMACStrategy) RefreshTokenSignature(ctx context.Context, token string) string {
	return s.delegate().RefreshTokenSignature(ctx, token)
}

func (s *dynamicOauth2HMACStrategy) GenerateRefreshToken(
	ctx context.Context,
	requester fosite.Requester,
) (string, string, error) {
	token, sig, err := s.delegate().GenerateRefreshToken(ctx, requester)
	if err == nil {
		if !strings.HasPrefix(token, oryRefreshTokenPrefix) {
			// This would only happen if fosite changed how it generates tokens. Defensive programming here.
			return "", "", errorsx.WithStack(fosite.ErrInvalidTokenFormat.
				WithDebugf("Generated token does not have expected prefix"))
		}
		token = replacePrefix(token, oryRefreshTokenPrefix, pinRefreshTokenPrefix)
	}
	return token, sig, err
}

func (s *dynamicOauth2HMACStrategy) ValidateRefreshToken(
	ctx context.Context,
	requester fosite.Requester,
	token string,
) error {
	if !strings.HasPrefix(token, pinRefreshTokenPrefix) {
		return errorsx.WithStack(fosite.ErrInvalidTokenFormat.
			WithDebugf("Refresh token did not have prefix %q", pinRefreshTokenPrefix))
	}
	return s.delegate().ValidateRefreshToken(ctx, requester, replacePrefix(token, pinRefreshTokenPrefix, oryRefreshTokenPrefix))
}

func (s *dynamicOauth2HMACStrategy) AuthorizeCodeSignature(ctx context.Context, token string) string {
	return s.delegate().AuthorizeCodeSignature(ctx, token)
}

func (s *dynamicOauth2HMACStrategy) GenerateAuthorizeCode(
	ctx context.Context,
	requester fosite.Requester,
) (string, string, error) {
	authcode, sig, err := s.delegate().GenerateAuthorizeCode(ctx, requester)
	if err == nil {
		if !strings.HasPrefix(authcode, oryAuthcodePrefix) {
			// This would only happen if fosite changed how it generates tokens. Defensive programming here.
			return "", "", errorsx.WithStack(fosite.ErrInvalidTokenFormat.
				WithDebugf("Generated token does not have expected prefix"))
		}
		authcode = replacePrefix(authcode, oryAuthcodePrefix, pinAuthcodePrefix)
	}
	return authcode, sig, err
}

func (s *dynamicOauth2HMACStrategy) ValidateAuthorizeCode(
	ctx context.Context,
	requester fosite.Requester,
	token string,
) error {
	if !strings.HasPrefix(token, pinAuthcodePrefix) {
		return errorsx.WithStack(fosite.ErrInvalidTokenFormat.
			WithDebugf("Authorization code did not have prefix %q", pinAuthcodePrefix))
	}
	return s.delegate().ValidateAuthorizeCode(ctx, requester, replacePrefix(token, pinAuthcodePrefix, oryAuthcodePrefix))
}

func (s *dynamicOauth2HMACStrategy) delegate() *oauth2.HMACSHAStrategy {
	return compose.NewOAuth2HMACStrategy(NewDynamicGlobalSecretConfig(s.fositeConfig, s.keyFunc))
}
