// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidctestutil

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	oidcpkce "go.pinniped.dev/pkg/oidcclient/pkce"
)

// ExchangeAuthcodeAndValidateTokenArgs is used to spy on calls to
// TestUpstreamOIDCIdentityProvider.ExchangeAuthcodeAndValidateTokensFunc().
type ExchangeAuthcodeAndValidateTokenArgs struct {
	Ctx                  context.Context
	Authcode             string
	PKCECodeVerifier     oidcpkce.Code
	ExpectedIDTokenNonce nonce.Nonce
	RedirectURI          string
}

// PasswordCredentialsGrantAndValidateTokensArgs is used to spy on calls to
// TestUpstreamOIDCIdentityProvider.PasswordCredentialsGrantAndValidateTokensFunc().
type PasswordCredentialsGrantAndValidateTokensArgs struct {
	Ctx      context.Context
	Username string
	Password string
}

// PerformOIDCRefreshArgs is used to spy on calls to
// TestUpstreamOIDCIdentityProvider.PerformRefreshFunc().
type PerformOIDCRefreshArgs struct {
	Ctx          context.Context
	RefreshToken string
}

// RevokeTokenArgs is used to spy on calls to
// TestUpstreamOIDCIdentityProvider.RevokeTokenArgsFunc().
type RevokeTokenArgs struct {
	Ctx       context.Context
	Token     string
	TokenType upstreamprovider.RevocableTokenType
}

// ValidateTokenAndMergeWithUserInfoArgs is used to spy on calls to
// TestUpstreamOIDCIdentityProvider.ValidateTokenAndMergeWithUserInfoFunc().
type ValidateTokenAndMergeWithUserInfoArgs struct {
	Ctx                  context.Context
	Tok                  *oauth2.Token
	ExpectedIDTokenNonce nonce.Nonce
	RequireIDToken       bool
	RequireUserInfo      bool
}

type TestUpstreamOIDCIdentityProvider struct {
	Name                           string
	ClientID                       string
	ResourceUID                    types.UID
	AuthorizationURL               url.URL
	UserInfoURL                    bool
	RevocationURL                  *url.URL
	UsernameClaim                  string
	GroupsClaim                    string
	Scopes                         []string
	AdditionalAuthcodeParams       map[string]string
	AdditionalClaimMappings        map[string]string
	AllowPasswordGrant             bool
	DisplayNameForFederationDomain string
	TransformsForFederationDomain  *idtransform.TransformationPipeline

	ExchangeAuthcodeAndValidateTokensFunc func(
		ctx context.Context,
		authcode string,
		pkceCodeVerifier oidcpkce.Code,
		expectedIDTokenNonce nonce.Nonce,
	) (*oidctypes.Token, error)

	PasswordCredentialsGrantAndValidateTokensFunc func(
		ctx context.Context,
		username string,
		password string,
	) (*oidctypes.Token, error)

	PerformRefreshFunc func(ctx context.Context, refreshToken string) (*oauth2.Token, error)

	RevokeTokenFunc func(ctx context.Context, refreshToken string, tokenType upstreamprovider.RevocableTokenType) error

	ValidateTokenAndMergeWithUserInfoFunc func(ctx context.Context, tok *oauth2.Token, expectedIDTokenNonce nonce.Nonce) (*oidctypes.Token, error)

	// Fields for tracking actual calls make to mock functions.
	exchangeAuthcodeAndValidateTokensCallCount         int
	exchangeAuthcodeAndValidateTokensArgs              []*ExchangeAuthcodeAndValidateTokenArgs
	passwordCredentialsGrantAndValidateTokensCallCount int
	passwordCredentialsGrantAndValidateTokensArgs      []*PasswordCredentialsGrantAndValidateTokensArgs
	performRefreshCallCount                            int
	performRefreshArgs                                 []*PerformOIDCRefreshArgs
	revokeTokenCallCount                               int
	revokeTokenArgs                                    []*RevokeTokenArgs
	validateTokenAndMergeWithUserInfoCallCount         int
	validateTokenAndMergeWithUserInfoArgs              []*ValidateTokenAndMergeWithUserInfoArgs
}

var _ upstreamprovider.UpstreamOIDCIdentityProviderI = &TestUpstreamOIDCIdentityProvider{}

func (u *TestUpstreamOIDCIdentityProvider) GetResourceUID() types.UID {
	return u.ResourceUID
}

func (u *TestUpstreamOIDCIdentityProvider) GetAdditionalAuthcodeParams() map[string]string {
	return u.AdditionalAuthcodeParams
}

func (u *TestUpstreamOIDCIdentityProvider) GetAdditionalClaimMappings() map[string]string {
	return u.AdditionalClaimMappings
}

func (u *TestUpstreamOIDCIdentityProvider) GetName() string {
	return u.Name
}

func (u *TestUpstreamOIDCIdentityProvider) GetClientID() string {
	return u.ClientID
}

func (u *TestUpstreamOIDCIdentityProvider) GetAuthorizationURL() *url.URL {
	return &u.AuthorizationURL
}

func (u *TestUpstreamOIDCIdentityProvider) HasUserInfoURL() bool {
	return u.UserInfoURL
}

func (u *TestUpstreamOIDCIdentityProvider) GetRevocationURL() *url.URL {
	return u.RevocationURL
}

func (u *TestUpstreamOIDCIdentityProvider) GetScopes() []string {
	return u.Scopes
}

func (u *TestUpstreamOIDCIdentityProvider) GetUsernameClaim() string {
	return u.UsernameClaim
}

func (u *TestUpstreamOIDCIdentityProvider) GetGroupsClaim() string {
	return u.GroupsClaim
}

func (u *TestUpstreamOIDCIdentityProvider) AllowsPasswordGrant() bool {
	return u.AllowPasswordGrant
}

func (u *TestUpstreamOIDCIdentityProvider) PasswordCredentialsGrantAndValidateTokens(ctx context.Context, username, password string) (*oidctypes.Token, error) {
	u.passwordCredentialsGrantAndValidateTokensCallCount++
	u.passwordCredentialsGrantAndValidateTokensArgs = append(u.passwordCredentialsGrantAndValidateTokensArgs, &PasswordCredentialsGrantAndValidateTokensArgs{
		Ctx:      ctx,
		Username: username,
		Password: password,
	})
	return u.PasswordCredentialsGrantAndValidateTokensFunc(ctx, username, password)
}

func (u *TestUpstreamOIDCIdentityProvider) ExchangeAuthcodeAndValidateTokens(
	ctx context.Context,
	authcode string,
	pkceCodeVerifier oidcpkce.Code,
	expectedIDTokenNonce nonce.Nonce,
	redirectURI string,
) (*oidctypes.Token, error) {
	if u.exchangeAuthcodeAndValidateTokensArgs == nil {
		u.exchangeAuthcodeAndValidateTokensArgs = make([]*ExchangeAuthcodeAndValidateTokenArgs, 0)
	}
	u.exchangeAuthcodeAndValidateTokensCallCount++
	u.exchangeAuthcodeAndValidateTokensArgs = append(u.exchangeAuthcodeAndValidateTokensArgs, &ExchangeAuthcodeAndValidateTokenArgs{
		Ctx:                  ctx,
		Authcode:             authcode,
		PKCECodeVerifier:     pkceCodeVerifier,
		ExpectedIDTokenNonce: expectedIDTokenNonce,
		RedirectURI:          redirectURI,
	})
	return u.ExchangeAuthcodeAndValidateTokensFunc(ctx, authcode, pkceCodeVerifier, expectedIDTokenNonce)
}

func (u *TestUpstreamOIDCIdentityProvider) ExchangeAuthcodeAndValidateTokensCallCount() int {
	return u.exchangeAuthcodeAndValidateTokensCallCount
}

func (u *TestUpstreamOIDCIdentityProvider) ExchangeAuthcodeAndValidateTokensArgs(call int) *ExchangeAuthcodeAndValidateTokenArgs {
	if u.exchangeAuthcodeAndValidateTokensArgs == nil {
		u.exchangeAuthcodeAndValidateTokensArgs = make([]*ExchangeAuthcodeAndValidateTokenArgs, 0)
	}
	return u.exchangeAuthcodeAndValidateTokensArgs[call]
}

func (u *TestUpstreamOIDCIdentityProvider) PasswordCredentialsGrantAndValidateTokensCallCount() int {
	return u.passwordCredentialsGrantAndValidateTokensCallCount
}

func (u *TestUpstreamOIDCIdentityProvider) PasswordCredentialsGrantAndValidateTokensArgs(call int) *PasswordCredentialsGrantAndValidateTokensArgs {
	if u.passwordCredentialsGrantAndValidateTokensArgs == nil {
		u.passwordCredentialsGrantAndValidateTokensArgs = make([]*PasswordCredentialsGrantAndValidateTokensArgs, 0)
	}
	return u.passwordCredentialsGrantAndValidateTokensArgs[call]
}

func (u *TestUpstreamOIDCIdentityProvider) PerformRefresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	if u.performRefreshArgs == nil {
		u.performRefreshArgs = make([]*PerformOIDCRefreshArgs, 0)
	}
	u.performRefreshCallCount++
	u.performRefreshArgs = append(u.performRefreshArgs, &PerformOIDCRefreshArgs{
		Ctx:          ctx,
		RefreshToken: refreshToken,
	})
	return u.PerformRefreshFunc(ctx, refreshToken)
}

func (u *TestUpstreamOIDCIdentityProvider) RevokeToken(ctx context.Context, token string, tokenType upstreamprovider.RevocableTokenType) error {
	if u.revokeTokenArgs == nil {
		u.revokeTokenArgs = make([]*RevokeTokenArgs, 0)
	}
	u.revokeTokenCallCount++
	u.revokeTokenArgs = append(u.revokeTokenArgs, &RevokeTokenArgs{
		Ctx:       ctx,
		Token:     token,
		TokenType: tokenType,
	})
	return u.RevokeTokenFunc(ctx, token, tokenType)
}

func (u *TestUpstreamOIDCIdentityProvider) PerformRefreshCallCount() int {
	return u.performRefreshCallCount
}

func (u *TestUpstreamOIDCIdentityProvider) PerformRefreshArgs(call int) *PerformOIDCRefreshArgs {
	if u.performRefreshArgs == nil {
		u.performRefreshArgs = make([]*PerformOIDCRefreshArgs, 0)
	}
	return u.performRefreshArgs[call]
}

func (u *TestUpstreamOIDCIdentityProvider) RevokeTokenCallCount() int {
	return u.revokeTokenCallCount
}

func (u *TestUpstreamOIDCIdentityProvider) RevokeTokenArgs(call int) *RevokeTokenArgs {
	if u.revokeTokenArgs == nil {
		u.revokeTokenArgs = make([]*RevokeTokenArgs, 0)
	}
	return u.revokeTokenArgs[call]
}

func (u *TestUpstreamOIDCIdentityProvider) ValidateTokenAndMergeWithUserInfo(ctx context.Context, tok *oauth2.Token, expectedIDTokenNonce nonce.Nonce, requireIDToken bool, requireUserInfo bool) (*oidctypes.Token, error) {
	if u.validateTokenAndMergeWithUserInfoArgs == nil {
		u.validateTokenAndMergeWithUserInfoArgs = make([]*ValidateTokenAndMergeWithUserInfoArgs, 0)
	}
	u.validateTokenAndMergeWithUserInfoCallCount++
	u.validateTokenAndMergeWithUserInfoArgs = append(u.validateTokenAndMergeWithUserInfoArgs, &ValidateTokenAndMergeWithUserInfoArgs{
		Ctx:                  ctx,
		Tok:                  tok,
		ExpectedIDTokenNonce: expectedIDTokenNonce,
		RequireIDToken:       requireIDToken,
		RequireUserInfo:      requireUserInfo,
	})
	return u.ValidateTokenAndMergeWithUserInfoFunc(ctx, tok, expectedIDTokenNonce)
}

func (u *TestUpstreamOIDCIdentityProvider) ValidateTokenAndMergeWithUserInfoCallCount() int {
	return u.validateTokenAndMergeWithUserInfoCallCount
}

func (u *TestUpstreamOIDCIdentityProvider) ValidateTokenAndMergeWithUserInfoArgs(call int) *ValidateTokenAndMergeWithUserInfoArgs {
	if u.validateTokenAndMergeWithUserInfoArgs == nil {
		u.validateTokenAndMergeWithUserInfoArgs = make([]*ValidateTokenAndMergeWithUserInfoArgs, 0)
	}
	return u.validateTokenAndMergeWithUserInfoArgs[call]
}

type TestUpstreamOIDCIdentityProviderBuilder struct {
	name                                 string
	resourceUID                          types.UID
	clientID                             string
	scopes                               []string
	idToken                              map[string]interface{}
	refreshToken                         *oidctypes.RefreshToken
	accessToken                          *oidctypes.AccessToken
	usernameClaim                        string
	groupsClaim                          string
	refreshedTokens                      *oauth2.Token
	validatedAndMergedWithUserInfoTokens *oidctypes.Token
	authorizationURL                     url.URL
	hasUserInfoURL                       bool
	additionalAuthcodeParams             map[string]string
	additionalClaimMappings              map[string]string
	allowPasswordGrant                   bool
	authcodeExchangeErr                  error
	passwordGrantErr                     error
	performRefreshErr                    error
	revokeTokenErr                       error
	validateTokenAndMergeWithUserInfoErr error
	displayNameForFederationDomain       string
	transformsForFederationDomain        *idtransform.TransformationPipeline
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithName(value string) *TestUpstreamOIDCIdentityProviderBuilder {
	u.name = value
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithResourceUID(value types.UID) *TestUpstreamOIDCIdentityProviderBuilder {
	u.resourceUID = value
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithClientID(value string) *TestUpstreamOIDCIdentityProviderBuilder {
	u.clientID = value
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithAuthorizationURL(value url.URL) *TestUpstreamOIDCIdentityProviderBuilder {
	u.authorizationURL = value
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithUserInfoURL() *TestUpstreamOIDCIdentityProviderBuilder {
	u.hasUserInfoURL = true
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithoutUserInfoURL() *TestUpstreamOIDCIdentityProviderBuilder {
	u.hasUserInfoURL = false
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithAllowPasswordGrant(value bool) *TestUpstreamOIDCIdentityProviderBuilder {
	u.allowPasswordGrant = value
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithScopes(values []string) *TestUpstreamOIDCIdentityProviderBuilder {
	u.scopes = values
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithUsernameClaim(value string) *TestUpstreamOIDCIdentityProviderBuilder {
	u.usernameClaim = value
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithoutUsernameClaim() *TestUpstreamOIDCIdentityProviderBuilder {
	u.usernameClaim = ""
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithGroupsClaim(value string) *TestUpstreamOIDCIdentityProviderBuilder {
	u.groupsClaim = value
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithoutGroupsClaim() *TestUpstreamOIDCIdentityProviderBuilder {
	u.groupsClaim = ""
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithIDTokenClaim(name string, value interface{}) *TestUpstreamOIDCIdentityProviderBuilder {
	if u.idToken == nil {
		u.idToken = map[string]interface{}{}
	}
	u.idToken[name] = value
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithoutIDTokenClaim(claim string) *TestUpstreamOIDCIdentityProviderBuilder {
	delete(u.idToken, claim)
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithAdditionalAuthcodeParams(params map[string]string) *TestUpstreamOIDCIdentityProviderBuilder {
	u.additionalAuthcodeParams = params
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithAdditionalClaimMappings(m map[string]string) *TestUpstreamOIDCIdentityProviderBuilder {
	u.additionalClaimMappings = m
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithRefreshToken(token string) *TestUpstreamOIDCIdentityProviderBuilder {
	u.refreshToken = &oidctypes.RefreshToken{Token: token}
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithEmptyRefreshToken() *TestUpstreamOIDCIdentityProviderBuilder {
	u.refreshToken = &oidctypes.RefreshToken{Token: ""}
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithoutRefreshToken() *TestUpstreamOIDCIdentityProviderBuilder {
	u.refreshToken = nil
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithAccessToken(token string, expiry metav1.Time) *TestUpstreamOIDCIdentityProviderBuilder {
	u.accessToken = &oidctypes.AccessToken{Token: token, Expiry: expiry}
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithEmptyAccessToken() *TestUpstreamOIDCIdentityProviderBuilder {
	u.accessToken = &oidctypes.AccessToken{Token: ""}
	return u
}
func (u *TestUpstreamOIDCIdentityProviderBuilder) WithoutAccessToken() *TestUpstreamOIDCIdentityProviderBuilder {
	u.accessToken = nil
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithUpstreamAuthcodeExchangeError(err error) *TestUpstreamOIDCIdentityProviderBuilder {
	u.authcodeExchangeErr = err
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithPasswordGrantError(err error) *TestUpstreamOIDCIdentityProviderBuilder {
	u.passwordGrantErr = err
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithRefreshedTokens(tokens *oauth2.Token) *TestUpstreamOIDCIdentityProviderBuilder {
	u.refreshedTokens = tokens
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithPerformRefreshError(err error) *TestUpstreamOIDCIdentityProviderBuilder {
	u.performRefreshErr = err
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithValidatedAndMergedWithUserInfoTokens(tokens *oidctypes.Token) *TestUpstreamOIDCIdentityProviderBuilder {
	u.validatedAndMergedWithUserInfoTokens = tokens
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithValidateTokenAndMergeWithUserInfoError(err error) *TestUpstreamOIDCIdentityProviderBuilder {
	u.validateTokenAndMergeWithUserInfoErr = err
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithRevokeTokenError(err error) *TestUpstreamOIDCIdentityProviderBuilder {
	u.revokeTokenErr = err
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithDisplayNameForFederationDomain(displayName string) *TestUpstreamOIDCIdentityProviderBuilder {
	u.displayNameForFederationDomain = displayName
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) WithTransformsForFederationDomain(transforms *idtransform.TransformationPipeline) *TestUpstreamOIDCIdentityProviderBuilder {
	u.transformsForFederationDomain = transforms
	return u
}

func (u *TestUpstreamOIDCIdentityProviderBuilder) Build() *TestUpstreamOIDCIdentityProvider {
	if u.displayNameForFederationDomain == "" {
		// default it to the CR name
		u.displayNameForFederationDomain = u.name
	}
	if u.transformsForFederationDomain == nil {
		// default to an empty pipeline
		u.transformsForFederationDomain = idtransform.NewTransformationPipeline()
	}

	return &TestUpstreamOIDCIdentityProvider{
		Name:                           u.name,
		ClientID:                       u.clientID,
		ResourceUID:                    u.resourceUID,
		UsernameClaim:                  u.usernameClaim,
		GroupsClaim:                    u.groupsClaim,
		Scopes:                         u.scopes,
		AllowPasswordGrant:             u.allowPasswordGrant,
		AuthorizationURL:               u.authorizationURL,
		UserInfoURL:                    u.hasUserInfoURL,
		AdditionalAuthcodeParams:       u.additionalAuthcodeParams,
		AdditionalClaimMappings:        u.additionalClaimMappings,
		DisplayNameForFederationDomain: u.displayNameForFederationDomain,
		TransformsForFederationDomain:  u.transformsForFederationDomain,
		ExchangeAuthcodeAndValidateTokensFunc: func(ctx context.Context, authcode string, pkceCodeVerifier oidcpkce.Code, expectedIDTokenNonce nonce.Nonce) (*oidctypes.Token, error) {
			if u.authcodeExchangeErr != nil {
				return nil, u.authcodeExchangeErr
			}
			return &oidctypes.Token{IDToken: &oidctypes.IDToken{Claims: u.idToken}, RefreshToken: u.refreshToken, AccessToken: u.accessToken}, nil
		},
		PasswordCredentialsGrantAndValidateTokensFunc: func(ctx context.Context, username, password string) (*oidctypes.Token, error) {
			if u.passwordGrantErr != nil {
				return nil, u.passwordGrantErr
			}
			return &oidctypes.Token{IDToken: &oidctypes.IDToken{Claims: u.idToken}, RefreshToken: u.refreshToken, AccessToken: u.accessToken}, nil
		},
		PerformRefreshFunc: func(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
			if u.performRefreshErr != nil {
				return nil, u.performRefreshErr
			}
			return u.refreshedTokens, nil
		},
		RevokeTokenFunc: func(ctx context.Context, refreshToken string, tokenType upstreamprovider.RevocableTokenType) error {
			return u.revokeTokenErr
		},
		ValidateTokenAndMergeWithUserInfoFunc: func(ctx context.Context, tok *oauth2.Token, expectedIDTokenNonce nonce.Nonce) (*oidctypes.Token, error) {
			if u.validateTokenAndMergeWithUserInfoErr != nil {
				return nil, u.validateTokenAndMergeWithUserInfoErr
			}
			return u.validatedAndMergedWithUserInfoTokens, nil
		},
	}
}

func NewTestUpstreamOIDCIdentityProviderBuilder() *TestUpstreamOIDCIdentityProviderBuilder {
	return &TestUpstreamOIDCIdentityProviderBuilder{}
}
