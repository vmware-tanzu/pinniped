// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
)

func TestDynamicOauth2HMACStrategy_Signatures(t *testing.T) {
	s := newDynamicOauth2HMACStrategy(
		&fosite.Config{}, // defaults are good enough for this unit test
		func() []byte { return []byte("12345678901234567890123456789012") }, // 32 character secret key
	)

	tests := []struct {
		name          string
		token         string
		signatureFunc func(ctx context.Context, token string) (signature string)
		wantSignature string
	}{
		{
			name:          "access token signature is the part after the dot in the default HMAC strategy",
			token:         "token.signature",
			signatureFunc: s.AccessTokenSignature,
			wantSignature: "signature",
		},
		{
			name:          "refresh token signature is the part after the dot in the default HMAC strategy",
			token:         "token.signature",
			signatureFunc: s.RefreshTokenSignature,
			wantSignature: "signature",
		},
		{
			name:          "authcode signature is the part after the dot in the default HMAC strategy",
			token:         "token.signature",
			signatureFunc: s.AuthorizeCodeSignature,
			wantSignature: "signature",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.wantSignature, tt.signatureFunc(context.Background(), tt.token))
		})
	}
}

func TestDynamicOauth2HMACStrategy_Generate(t *testing.T) {
	s := newDynamicOauth2HMACStrategy(
		&fosite.Config{}, // defaults are good enough for this unit test
		func() []byte { return []byte("12345678901234567890123456789012") }, // 32 character secret key
	)

	generateTokenErrorCausingStrategy := newDynamicOauth2HMACStrategy(
		&fosite.Config{},
		func() []byte { return []byte("too_short_causes_error") }, // secret key is below required 32 characters
	)

	tests := []struct {
		name            string
		generateFunc    func(ctx context.Context, requester fosite.Requester) (token string, signature string, err error)
		errGenerateFunc func(ctx context.Context, requester fosite.Requester) (token string, signature string, err error)
		wantPrefix      string
	}{
		{
			name:            "access tokens are base64 random bytes followed by dot followed by base64 signature of the random bytes in the default HMAC strategy",
			generateFunc:    s.GenerateAccessToken,
			errGenerateFunc: generateTokenErrorCausingStrategy.GenerateAccessToken,
			wantPrefix:      "pin_at_",
		},
		{
			name:            "refresh tokens are base64 random bytes followed by dot followed by base64 signature of the random bytes in the default HMAC strategy",
			generateFunc:    s.GenerateRefreshToken,
			errGenerateFunc: generateTokenErrorCausingStrategy.GenerateRefreshToken,
			wantPrefix:      "pin_rt_",
		},
		{
			name:            "authcodes are base64 random bytes followed by dot followed by base64 signature of the random bytes in the default HMAC strategy",
			generateFunc:    s.GenerateAuthorizeCode,
			errGenerateFunc: generateTokenErrorCausingStrategy.GenerateAuthorizeCode,
			wantPrefix:      "pin_ac_",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			requireRandomTokenInExpectedFormat := func(token, signature string) {
				// Tokens should start with a custom prefix to make them identifiable as tokens when seen by a user
				// out of context, such as when accidentally committed to a GitHub repo.
				require.True(t, strings.HasPrefix(token, tt.wantPrefix), "token %q did not have expected prefix %q", token, tt.wantPrefix)
				require.Equal(t, 1, strings.Count(token, "."))
				require.Len(t, signature, 43)
				require.True(t, strings.HasSuffix(token, "."+signature), "token %q did not end with dot followed by signature", token)
				// The part before the dot is the prefix plus 43 characters of base64 encoded random bytes.
				require.Len(t, strings.Split(token, ".")[0], len(tt.wantPrefix)+43)
			}

			var ctxIsIgnored context.Context
			var requesterIsIgnored fosite.Requester

			generatedToken1, signature1, err := tt.generateFunc(ctxIsIgnored, requesterIsIgnored)
			require.NoError(t, err)
			requireRandomTokenInExpectedFormat(generatedToken1, signature1)

			generatedToken2, signature2, err := tt.generateFunc(ctxIsIgnored, requesterIsIgnored)
			require.NoError(t, err)
			requireRandomTokenInExpectedFormat(generatedToken2, signature2)

			// Each generated token is random/different.
			require.NotEqual(t, generatedToken1, generatedToken2)
			require.NotEqual(t, signature1, signature2)

			// Test the return values when an error is encountered during generation.
			generatedToken3, signature3, err := tt.errGenerateFunc(ctxIsIgnored, requesterIsIgnored)
			require.EqualError(t, err, "secret for signing HMAC-SHA512/256 is expected to be 32 byte long, got 22 byte")
			require.Empty(t, generatedToken3)
			require.Empty(t, signature3)
		})
	}
}

func TestDynamicOauth2HMACStrategy_Validate(t *testing.T) {
	s := newDynamicOauth2HMACStrategy(
		&fosite.Config{}, // defaults are good enough for this unit test
		func() []byte { return []byte("12345678901234567890123456789012") }, // 32 character secret key
	)

	tests := []struct {
		name         string
		generateFunc func(ctx context.Context, requester fosite.Requester) (token string, signature string, err error)
		validateFunc func(ctx context.Context, requester fosite.Requester, token string) error
		wantPrefix   string
	}{
		{
			name:         "access tokens",
			generateFunc: s.GenerateAccessToken,
			validateFunc: s.ValidateAccessToken,
			wantPrefix:   "pin_at_",
		},
		{
			name:         "refresh tokens",
			generateFunc: s.GenerateRefreshToken,
			validateFunc: s.ValidateRefreshToken,
			wantPrefix:   "pin_rt_",
		},
		{
			name:         "authcodes",
			generateFunc: s.GenerateAuthorizeCode,
			validateFunc: s.ValidateAuthorizeCode,
			wantPrefix:   "pin_ac_",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var ctxIsIgnored context.Context
			var requesterIsIgnored fosite.Requester

			unexpiredSession := &fosite.DefaultSession{}
			unexpiredSession.SetExpiresAt(fosite.RefreshToken, time.Now().Add(time.Hour))
			unexpiredSession.SetExpiresAt(fosite.AccessToken, time.Now().Add(time.Hour))
			unexpiredSession.SetExpiresAt(fosite.AuthorizeCode, time.Now().Add(time.Hour))
			requesterWithUnexpiredTokens := &fosite.Request{Session: unexpiredSession}

			expiredSession := &fosite.DefaultSession{}
			expiredSession.SetExpiresAt(fosite.RefreshToken, time.Now().Add(-time.Hour))
			expiredSession.SetExpiresAt(fosite.AccessToken, time.Now().Add(-time.Hour))
			expiredSession.SetExpiresAt(fosite.AuthorizeCode, time.Now().Add(-time.Hour))
			requesterWithExpiredTokens := &fosite.Request{Session: expiredSession}

			generatedToken, _, err := tt.generateFunc(ctxIsIgnored, requesterIsIgnored)
			require.NoError(t, err)
			require.NoError(t, tt.validateFunc(ctxIsIgnored, requesterWithUnexpiredTokens, generatedToken))

			generatedToken, _, err = tt.generateFunc(ctxIsIgnored, requesterIsIgnored)
			require.NoError(t, err)
			require.NoError(t, tt.validateFunc(ctxIsIgnored, requesterWithUnexpiredTokens, generatedToken))

			// Generated token has prefix.
			require.True(t, strings.HasPrefix(generatedToken, tt.wantPrefix), "token %q did not have expected prefix %q", generatedToken, tt.wantPrefix)

			// Validate when expired according to session.
			require.EqualError(t, tt.validateFunc(ctxIsIgnored, requesterWithExpiredTokens, generatedToken), "invalid_token")

			// Validate when missing prefix.
			require.EqualError(t, tt.validateFunc(ctxIsIgnored, requesterWithUnexpiredTokens, strings.TrimPrefix(generatedToken, tt.wantPrefix)), "invalid_token")

			// Validate when wrong prefix.
			require.EqualError(t, tt.validateFunc(ctxIsIgnored, requesterWithUnexpiredTokens, "pin_wrong_"+strings.TrimPrefix(generatedToken, tt.wantPrefix)), "invalid_token")

			// Validate when correct prefix but otherwise invalid format.
			require.EqualError(t, tt.validateFunc(ctxIsIgnored, requesterWithUnexpiredTokens, tt.wantPrefix+"illegal token"), "invalid_token")

			// Validate when correct prefix but bad signature.
			var b64 = base64.URLEncoding.WithPadding(base64.NoPadding)
			tokenWithBadSig := tt.wantPrefix + b64.EncodeToString([]byte("some-token")) + "." + b64.EncodeToString([]byte("bad-signature"))
			require.EqualError(t, tt.validateFunc(ctxIsIgnored, requesterWithUnexpiredTokens, tokenWithBadSig), "token_signature_mismatch")
		})
	}
}
