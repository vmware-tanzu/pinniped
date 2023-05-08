// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidctestutil

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	kubetesting "k8s.io/client-go/testing"
	"k8s.io/utils/strings/slices"

	"go.pinniped.dev/internal/authenticators"
	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/fositestorage/authorizationcode"
	"go.pinniped.dev/internal/fositestorage/openidconnect"
	pkce2 "go.pinniped.dev/internal/fositestorage/pkce"
	"go.pinniped.dev/internal/fositestoragei"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidc/provider/upstreamprovider"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

// Test helpers for the OIDC package.

// ExchangeAuthcodeAndValidateTokenArgs is used to spy on calls to
// TestUpstreamOIDCIdentityProvider.ExchangeAuthcodeAndValidateTokensFunc().
type ExchangeAuthcodeAndValidateTokenArgs struct {
	Ctx                  context.Context
	Authcode             string
	PKCECodeVerifier     pkce.Code
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

// PerformRefreshArgs is used to spy on calls to
// TestUpstreamOIDCIdentityProvider.PerformRefreshFunc().
type PerformRefreshArgs struct {
	Ctx              context.Context
	RefreshToken     string
	DN               string
	ExpectedUsername string
	ExpectedSubject  string
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

type ValidateRefreshArgs struct {
	Ctx              context.Context
	Tok              *oauth2.Token
	StoredAttributes upstreamprovider.RefreshAttributes
}

type TestUpstreamLDAPIdentityProvider struct {
	Name                    string
	ResourceUID             types.UID
	URL                     *url.URL
	AuthenticateFunc        func(ctx context.Context, username, password string) (*authenticators.Response, bool, error)
	performRefreshCallCount int
	performRefreshArgs      []*PerformRefreshArgs
	PerformRefreshErr       error
	PerformRefreshGroups    []string
}

var _ upstreamprovider.UpstreamLDAPIdentityProviderI = &TestUpstreamLDAPIdentityProvider{}

func (u *TestUpstreamLDAPIdentityProvider) GetResourceUID() types.UID {
	return u.ResourceUID
}

func (u *TestUpstreamLDAPIdentityProvider) GetName() string {
	return u.Name
}

func (u *TestUpstreamLDAPIdentityProvider) AuthenticateUser(ctx context.Context, username, password string, grantedScopes []string) (*authenticators.Response, bool, error) {
	return u.AuthenticateFunc(ctx, username, password)
}

func (u *TestUpstreamLDAPIdentityProvider) GetURL() *url.URL {
	return u.URL
}

func (u *TestUpstreamLDAPIdentityProvider) PerformRefresh(ctx context.Context, storedRefreshAttributes upstreamprovider.RefreshAttributes) ([]string, error) {
	if u.performRefreshArgs == nil {
		u.performRefreshArgs = make([]*PerformRefreshArgs, 0)
	}
	u.performRefreshCallCount++
	u.performRefreshArgs = append(u.performRefreshArgs, &PerformRefreshArgs{
		Ctx:              ctx,
		DN:               storedRefreshAttributes.DN,
		ExpectedUsername: storedRefreshAttributes.Username,
		ExpectedSubject:  storedRefreshAttributes.Subject,
	})
	if u.PerformRefreshErr != nil {
		return nil, u.PerformRefreshErr
	}
	return u.PerformRefreshGroups, nil
}

func (u *TestUpstreamLDAPIdentityProvider) PerformRefreshCallCount() int {
	return u.performRefreshCallCount
}

func (u *TestUpstreamLDAPIdentityProvider) PerformRefreshArgs(call int) *PerformRefreshArgs {
	if u.performRefreshArgs == nil {
		u.performRefreshArgs = make([]*PerformRefreshArgs, 0)
	}
	return u.performRefreshArgs[call]
}

type TestUpstreamOIDCIdentityProvider struct {
	Name                     string
	ClientID                 string
	ResourceUID              types.UID
	AuthorizationURL         url.URL
	UserInfoURL              bool
	RevocationURL            *url.URL
	UsernameClaim            string
	GroupsClaim              string
	Scopes                   []string
	AdditionalAuthcodeParams map[string]string
	AdditionalClaimMappings  map[string]string
	AllowPasswordGrant       bool

	ExchangeAuthcodeAndValidateTokensFunc func(
		ctx context.Context,
		authcode string,
		pkceCodeVerifier pkce.Code,
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

	exchangeAuthcodeAndValidateTokensCallCount         int
	exchangeAuthcodeAndValidateTokensArgs              []*ExchangeAuthcodeAndValidateTokenArgs
	passwordCredentialsGrantAndValidateTokensCallCount int
	passwordCredentialsGrantAndValidateTokensArgs      []*PasswordCredentialsGrantAndValidateTokensArgs
	performRefreshCallCount                            int
	performRefreshArgs                                 []*PerformRefreshArgs
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
	pkceCodeVerifier pkce.Code,
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

func (u *TestUpstreamOIDCIdentityProvider) PerformRefresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	if u.performRefreshArgs == nil {
		u.performRefreshArgs = make([]*PerformRefreshArgs, 0)
	}
	u.performRefreshCallCount++
	u.performRefreshArgs = append(u.performRefreshArgs, &PerformRefreshArgs{
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

func (u *TestUpstreamOIDCIdentityProvider) PerformRefreshArgs(call int) *PerformRefreshArgs {
	if u.performRefreshArgs == nil {
		u.performRefreshArgs = make([]*PerformRefreshArgs, 0)
	}
	return u.performRefreshArgs[call]
}

func (u *TestUpstreamOIDCIdentityProvider) RevokeTokenCallCount() int {
	return u.performRefreshCallCount
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

type UpstreamIDPListerBuilder struct {
	upstreamOIDCIdentityProviders            []*TestUpstreamOIDCIdentityProvider
	upstreamLDAPIdentityProviders            []*TestUpstreamLDAPIdentityProvider
	upstreamActiveDirectoryIdentityProviders []*TestUpstreamLDAPIdentityProvider
}

func (b *UpstreamIDPListerBuilder) WithOIDC(upstreamOIDCIdentityProviders ...*TestUpstreamOIDCIdentityProvider) *UpstreamIDPListerBuilder {
	b.upstreamOIDCIdentityProviders = append(b.upstreamOIDCIdentityProviders, upstreamOIDCIdentityProviders...)
	return b
}

func (b *UpstreamIDPListerBuilder) WithLDAP(upstreamLDAPIdentityProviders ...*TestUpstreamLDAPIdentityProvider) *UpstreamIDPListerBuilder {
	b.upstreamLDAPIdentityProviders = append(b.upstreamLDAPIdentityProviders, upstreamLDAPIdentityProviders...)
	return b
}

func (b *UpstreamIDPListerBuilder) WithActiveDirectory(upstreamActiveDirectoryIdentityProviders ...*TestUpstreamLDAPIdentityProvider) *UpstreamIDPListerBuilder {
	b.upstreamActiveDirectoryIdentityProviders = append(b.upstreamActiveDirectoryIdentityProviders, upstreamActiveDirectoryIdentityProviders...)
	return b
}

func (b *UpstreamIDPListerBuilder) Build() provider.DynamicUpstreamIDPProvider {
	idpProvider := provider.NewDynamicUpstreamIDPProvider()

	oidcUpstreams := make([]upstreamprovider.UpstreamOIDCIdentityProviderI, len(b.upstreamOIDCIdentityProviders))
	for i := range b.upstreamOIDCIdentityProviders {
		oidcUpstreams[i] = upstreamprovider.UpstreamOIDCIdentityProviderI(b.upstreamOIDCIdentityProviders[i])
	}
	idpProvider.SetOIDCIdentityProviders(oidcUpstreams)

	ldapUpstreams := make([]upstreamprovider.UpstreamLDAPIdentityProviderI, len(b.upstreamLDAPIdentityProviders))
	for i := range b.upstreamLDAPIdentityProviders {
		ldapUpstreams[i] = upstreamprovider.UpstreamLDAPIdentityProviderI(b.upstreamLDAPIdentityProviders[i])
	}
	idpProvider.SetLDAPIdentityProviders(ldapUpstreams)

	adUpstreams := make([]upstreamprovider.UpstreamLDAPIdentityProviderI, len(b.upstreamActiveDirectoryIdentityProviders))
	for i := range b.upstreamActiveDirectoryIdentityProviders {
		adUpstreams[i] = upstreamprovider.UpstreamLDAPIdentityProviderI(b.upstreamActiveDirectoryIdentityProviders[i])
	}
	idpProvider.SetActiveDirectoryIdentityProviders(adUpstreams)

	return idpProvider
}

func (b *UpstreamIDPListerBuilder) RequireExactlyOneCallToPasswordCredentialsGrantAndValidateTokens(
	t *testing.T,
	expectedPerformedByUpstreamName string,
	expectedArgs *PasswordCredentialsGrantAndValidateTokensArgs,
) {
	t.Helper()
	var actualArgs *PasswordCredentialsGrantAndValidateTokensArgs
	var actualNameOfUpstreamWhichMadeCall string
	actualCallCountAcrossAllOIDCUpstreams := 0
	for _, upstreamOIDC := range b.upstreamOIDCIdentityProviders {
		callCountOnThisUpstream := upstreamOIDC.passwordCredentialsGrantAndValidateTokensCallCount
		actualCallCountAcrossAllOIDCUpstreams += callCountOnThisUpstream
		if callCountOnThisUpstream == 1 {
			actualNameOfUpstreamWhichMadeCall = upstreamOIDC.Name
			actualArgs = upstreamOIDC.passwordCredentialsGrantAndValidateTokensArgs[0]
		}
	}
	require.Equal(t, 1, actualCallCountAcrossAllOIDCUpstreams,
		"should have been exactly one call to PasswordCredentialsGrantAndValidateTokens() by all OIDC upstreams",
	)
	require.Equal(t, expectedPerformedByUpstreamName, actualNameOfUpstreamWhichMadeCall,
		"PasswordCredentialsGrantAndValidateTokens() was called on the wrong OIDC upstream",
	)
	require.Equal(t, expectedArgs, actualArgs)
}

func (b *UpstreamIDPListerBuilder) RequireExactlyZeroCallsToPasswordCredentialsGrantAndValidateTokens(t *testing.T) {
	t.Helper()
	actualCallCountAcrossAllOIDCUpstreams := 0
	for _, upstreamOIDC := range b.upstreamOIDCIdentityProviders {
		actualCallCountAcrossAllOIDCUpstreams += upstreamOIDC.passwordCredentialsGrantAndValidateTokensCallCount
	}
	require.Equal(t, 0, actualCallCountAcrossAllOIDCUpstreams,
		"expected exactly zero calls to PasswordCredentialsGrantAndValidateTokens()",
	)
}

func (b *UpstreamIDPListerBuilder) RequireExactlyOneCallToExchangeAuthcodeAndValidateTokens(
	t *testing.T,
	expectedPerformedByUpstreamName string,
	expectedArgs *ExchangeAuthcodeAndValidateTokenArgs,
) {
	t.Helper()
	var actualArgs *ExchangeAuthcodeAndValidateTokenArgs
	var actualNameOfUpstreamWhichMadeCall string
	actualCallCountAcrossAllOIDCUpstreams := 0
	for _, upstreamOIDC := range b.upstreamOIDCIdentityProviders {
		callCountOnThisUpstream := upstreamOIDC.exchangeAuthcodeAndValidateTokensCallCount
		actualCallCountAcrossAllOIDCUpstreams += callCountOnThisUpstream
		if callCountOnThisUpstream == 1 {
			actualNameOfUpstreamWhichMadeCall = upstreamOIDC.Name
			actualArgs = upstreamOIDC.exchangeAuthcodeAndValidateTokensArgs[0]
		}
	}
	require.Equal(t, 1, actualCallCountAcrossAllOIDCUpstreams,
		"should have been exactly one call to ExchangeAuthcodeAndValidateTokens() by all OIDC upstreams",
	)
	require.Equal(t, expectedPerformedByUpstreamName, actualNameOfUpstreamWhichMadeCall,
		"ExchangeAuthcodeAndValidateTokens() was called on the wrong OIDC upstream",
	)
	require.Equal(t, expectedArgs, actualArgs)
}

func (b *UpstreamIDPListerBuilder) RequireExactlyZeroCallsToExchangeAuthcodeAndValidateTokens(t *testing.T) {
	t.Helper()
	actualCallCountAcrossAllOIDCUpstreams := 0
	for _, upstreamOIDC := range b.upstreamOIDCIdentityProviders {
		actualCallCountAcrossAllOIDCUpstreams += upstreamOIDC.exchangeAuthcodeAndValidateTokensCallCount
	}
	require.Equal(t, 0, actualCallCountAcrossAllOIDCUpstreams,
		"expected exactly zero calls to ExchangeAuthcodeAndValidateTokens()",
	)
}

func (b *UpstreamIDPListerBuilder) RequireExactlyOneCallToPerformRefresh(
	t *testing.T,
	expectedPerformedByUpstreamName string,
	expectedArgs *PerformRefreshArgs,
) {
	t.Helper()
	var actualArgs *PerformRefreshArgs
	var actualNameOfUpstreamWhichMadeCall string
	actualCallCountAcrossAllUpstreams := 0
	for _, upstreamOIDC := range b.upstreamOIDCIdentityProviders {
		callCountOnThisUpstream := upstreamOIDC.performRefreshCallCount
		actualCallCountAcrossAllUpstreams += callCountOnThisUpstream
		if callCountOnThisUpstream == 1 {
			actualNameOfUpstreamWhichMadeCall = upstreamOIDC.Name
			actualArgs = upstreamOIDC.performRefreshArgs[0]
		}
	}
	for _, upstreamLDAP := range b.upstreamLDAPIdentityProviders {
		callCountOnThisUpstream := upstreamLDAP.performRefreshCallCount
		actualCallCountAcrossAllUpstreams += callCountOnThisUpstream
		if callCountOnThisUpstream == 1 {
			actualNameOfUpstreamWhichMadeCall = upstreamLDAP.Name
			actualArgs = upstreamLDAP.performRefreshArgs[0]
		}
	}
	for _, upstreamAD := range b.upstreamActiveDirectoryIdentityProviders {
		callCountOnThisUpstream := upstreamAD.performRefreshCallCount
		actualCallCountAcrossAllUpstreams += callCountOnThisUpstream
		if callCountOnThisUpstream == 1 {
			actualNameOfUpstreamWhichMadeCall = upstreamAD.Name
			actualArgs = upstreamAD.performRefreshArgs[0]
		}
	}
	require.Equal(t, 1, actualCallCountAcrossAllUpstreams,
		"should have been exactly one call to PerformRefresh() by all upstreams",
	)
	require.Equal(t, expectedPerformedByUpstreamName, actualNameOfUpstreamWhichMadeCall,
		"PerformRefresh() was called on the wrong upstream",
	)
	require.Equal(t, expectedArgs, actualArgs)
}

func (b *UpstreamIDPListerBuilder) RequireExactlyZeroCallsToPerformRefresh(t *testing.T) {
	t.Helper()
	actualCallCountAcrossAllUpstreams := 0
	for _, upstreamOIDC := range b.upstreamOIDCIdentityProviders {
		actualCallCountAcrossAllUpstreams += upstreamOIDC.performRefreshCallCount
	}
	for _, upstreamLDAP := range b.upstreamLDAPIdentityProviders {
		actualCallCountAcrossAllUpstreams += upstreamLDAP.performRefreshCallCount
	}
	for _, upstreamActiveDirectory := range b.upstreamActiveDirectoryIdentityProviders {
		actualCallCountAcrossAllUpstreams += upstreamActiveDirectory.performRefreshCallCount
	}

	require.Equal(t, 0, actualCallCountAcrossAllUpstreams,
		"expected exactly zero calls to PerformRefresh()",
	)
}

func (b *UpstreamIDPListerBuilder) RequireExactlyOneCallToValidateToken(
	t *testing.T,
	expectedPerformedByUpstreamName string,
	expectedArgs *ValidateTokenAndMergeWithUserInfoArgs,
) {
	t.Helper()
	var actualArgs *ValidateTokenAndMergeWithUserInfoArgs
	var actualNameOfUpstreamWhichMadeCall string
	actualCallCountAcrossAllOIDCUpstreams := 0
	for _, upstreamOIDC := range b.upstreamOIDCIdentityProviders {
		callCountOnThisUpstream := upstreamOIDC.validateTokenAndMergeWithUserInfoCallCount
		actualCallCountAcrossAllOIDCUpstreams += callCountOnThisUpstream
		if callCountOnThisUpstream == 1 {
			actualNameOfUpstreamWhichMadeCall = upstreamOIDC.Name
			actualArgs = upstreamOIDC.validateTokenAndMergeWithUserInfoArgs[0]
		}
	}
	require.Equal(t, 1, actualCallCountAcrossAllOIDCUpstreams,
		"should have been exactly one call to ValidateTokenAndMergeWithUserInfo() by all OIDC upstreams",
	)
	require.Equal(t, expectedPerformedByUpstreamName, actualNameOfUpstreamWhichMadeCall,
		"ValidateTokenAndMergeWithUserInfo() was called on the wrong OIDC upstream",
	)
	require.Equal(t, expectedArgs, actualArgs)
}

func (b *UpstreamIDPListerBuilder) RequireExactlyZeroCallsToValidateToken(t *testing.T) {
	t.Helper()
	actualCallCountAcrossAllOIDCUpstreams := 0
	for _, upstreamOIDC := range b.upstreamOIDCIdentityProviders {
		actualCallCountAcrossAllOIDCUpstreams += upstreamOIDC.validateTokenAndMergeWithUserInfoCallCount
	}
	require.Equal(t, 0, actualCallCountAcrossAllOIDCUpstreams,
		"expected exactly zero calls to ValidateTokenAndMergeWithUserInfo()",
	)
}

func (b *UpstreamIDPListerBuilder) RequireExactlyOneCallToRevokeToken(
	t *testing.T,
	expectedPerformedByUpstreamName string,
	expectedArgs *RevokeTokenArgs,
) {
	t.Helper()
	var actualArgs *RevokeTokenArgs
	var actualNameOfUpstreamWhichMadeCall string
	actualCallCountAcrossAllOIDCUpstreams := 0
	for _, upstreamOIDC := range b.upstreamOIDCIdentityProviders {
		callCountOnThisUpstream := upstreamOIDC.revokeTokenCallCount
		actualCallCountAcrossAllOIDCUpstreams += callCountOnThisUpstream
		if callCountOnThisUpstream == 1 {
			actualNameOfUpstreamWhichMadeCall = upstreamOIDC.Name
			actualArgs = upstreamOIDC.revokeTokenArgs[0]
		}
	}
	require.Equal(t, 1, actualCallCountAcrossAllOIDCUpstreams,
		"should have been exactly one call to RevokeToken() by all OIDC upstreams",
	)
	require.Equal(t, expectedPerformedByUpstreamName, actualNameOfUpstreamWhichMadeCall,
		"RevokeToken() was called on the wrong OIDC upstream",
	)
	require.Equal(t, expectedArgs, actualArgs)
}

func (b *UpstreamIDPListerBuilder) RequireExactlyZeroCallsToRevokeToken(t *testing.T) {
	t.Helper()
	actualCallCountAcrossAllOIDCUpstreams := 0
	for _, upstreamOIDC := range b.upstreamOIDCIdentityProviders {
		actualCallCountAcrossAllOIDCUpstreams += upstreamOIDC.revokeTokenCallCount
	}
	require.Equal(t, 0, actualCallCountAcrossAllOIDCUpstreams,
		"expected exactly zero calls to RevokeToken()",
	)
}

func NewUpstreamIDPListerBuilder() *UpstreamIDPListerBuilder {
	return &UpstreamIDPListerBuilder{}
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

func (u *TestUpstreamOIDCIdentityProviderBuilder) Build() *TestUpstreamOIDCIdentityProvider {
	return &TestUpstreamOIDCIdentityProvider{
		Name:                     u.name,
		ClientID:                 u.clientID,
		ResourceUID:              u.resourceUID,
		UsernameClaim:            u.usernameClaim,
		GroupsClaim:              u.groupsClaim,
		Scopes:                   u.scopes,
		AllowPasswordGrant:       u.allowPasswordGrant,
		AuthorizationURL:         u.authorizationURL,
		UserInfoURL:              u.hasUserInfoURL,
		AdditionalAuthcodeParams: u.additionalAuthcodeParams,
		AdditionalClaimMappings:  u.additionalClaimMappings,
		ExchangeAuthcodeAndValidateTokensFunc: func(ctx context.Context, authcode string, pkceCodeVerifier pkce.Code, expectedIDTokenNonce nonce.Nonce) (*oidctypes.Token, error) {
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

// Declare a separate type from the production code to ensure that the state param's contents was serialized
// in the format that we expect, with the json keys that we expect, etc. This also ensure that the order of
// the serialized fields is the same, which doesn't really matter expect that we can make simpler equality
// assertions about the redirect URL in this test.
type ExpectedUpstreamStateParamFormat struct {
	P string `json:"p"`
	U string `json:"u"`
	T string `json:"t"`
	N string `json:"n"`
	C string `json:"c"`
	K string `json:"k"`
	V string `json:"v"`
}

type UpstreamStateParamBuilder ExpectedUpstreamStateParamFormat

func (b UpstreamStateParamBuilder) Build(t *testing.T, stateEncoder *securecookie.SecureCookie) string {
	state, err := stateEncoder.Encode("s", b)
	require.NoError(t, err)
	return state
}

func (b *UpstreamStateParamBuilder) WithAuthorizeRequestParams(params string) *UpstreamStateParamBuilder {
	b.P = params
	return b
}

func (b *UpstreamStateParamBuilder) WithNonce(nonce string) *UpstreamStateParamBuilder {
	b.N = nonce
	return b
}

func (b *UpstreamStateParamBuilder) WithCSRF(csrf string) *UpstreamStateParamBuilder {
	b.C = csrf
	return b
}

func (b *UpstreamStateParamBuilder) WithPKCE(pkce string) *UpstreamStateParamBuilder {
	b.K = pkce
	return b
}

func (b *UpstreamStateParamBuilder) WithUpstreamIDPType(upstreamIDPType string) *UpstreamStateParamBuilder {
	b.T = upstreamIDPType
	return b
}

func (b *UpstreamStateParamBuilder) WithStateVersion(version string) *UpstreamStateParamBuilder {
	b.V = version
	return b
}

type staticKeySet struct {
	publicKey crypto.PublicKey
}

func newStaticKeySet(publicKey crypto.PublicKey) coreosoidc.KeySet {
	return &staticKeySet{publicKey}
}

func (s *staticKeySet) VerifySignature(_ context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt)
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

func RequireAuthCodeRegexpMatch(
	t *testing.T,
	actualContent string,
	wantRegexp string,
	kubeClient *fake.Clientset,
	secretsClient v1.SecretInterface,
	oauthStore fositestoragei.AllFositeStorage,
	wantDownstreamGrantedScopes []string,
	wantDownstreamIDTokenSubject string,
	wantDownstreamIDTokenUsername string,
	wantDownstreamIDTokenGroups []string,
	wantDownstreamRequestedScopes []string,
	wantDownstreamPKCEChallenge string,
	wantDownstreamPKCEChallengeMethod string,
	wantDownstreamNonce string,
	wantDownstreamClientID string,
	wantDownstreamRedirectURI string,
	wantCustomSessionData *psession.CustomSessionData,
	wantDownstreamAdditionalClaims map[string]interface{},
) {
	t.Helper()

	// Assert that Location header matches regular expression.
	regex := regexp.MustCompile(wantRegexp)
	submatches := regex.FindStringSubmatch(actualContent)
	require.Lenf(t, submatches, 2, "no regexp match in actualContent: %", actualContent)
	capturedAuthCode := submatches[1]

	// Authcodes should start with the custom prefix "pin_ac_" to make them identifiable as authcodes when seen by a user out of context.
	require.True(t, strings.HasPrefix(capturedAuthCode, "pin_ac_"), "token %q did not have expected prefix 'pin_ac_'", capturedAuthCode)

	// fosite authcodes are in the format `data.signature`, so grab the signature part, which is the lookup key in the storage interface
	authcodeDataAndSignature := strings.Split(capturedAuthCode, ".")
	require.Len(t, authcodeDataAndSignature, 2)

	// Several Secrets should have been created
	expectedNumberOfCreatedSecrets := 2
	if includesOpenIDScope(wantDownstreamGrantedScopes) {
		expectedNumberOfCreatedSecrets++
	}
	require.Len(t, FilterClientSecretCreateActions(kubeClient.Actions()), expectedNumberOfCreatedSecrets)

	// One authcode should have been stored.
	testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secretsClient, labels.Set{crud.SecretLabelKey: authorizationcode.TypeLabelValue}, 1)

	storedRequestFromAuthcode, storedSessionFromAuthcode := validateAuthcodeStorage(
		t,
		oauthStore,
		authcodeDataAndSignature[1], // Authcode store key is authcode signature
		wantDownstreamGrantedScopes,
		wantDownstreamIDTokenSubject,
		wantDownstreamIDTokenUsername,
		wantDownstreamIDTokenGroups,
		wantDownstreamRequestedScopes,
		wantDownstreamClientID,
		wantDownstreamRedirectURI,
		wantCustomSessionData,
		wantDownstreamAdditionalClaims,
	)

	// One PKCE should have been stored.
	testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secretsClient, labels.Set{crud.SecretLabelKey: pkce2.TypeLabelValue}, 1)

	validatePKCEStorage(
		t,
		oauthStore,
		authcodeDataAndSignature[1], // PKCE store key is authcode signature
		storedRequestFromAuthcode,
		storedSessionFromAuthcode,
		wantDownstreamPKCEChallenge,
		wantDownstreamPKCEChallengeMethod,
	)

	// One IDSession should have been stored, if the downstream actually requested the "openid" scope
	if includesOpenIDScope(wantDownstreamGrantedScopes) {
		testutil.RequireNumberOfSecretsMatchingLabelSelector(t, secretsClient, labels.Set{crud.SecretLabelKey: openidconnect.TypeLabelValue}, 1)

		validateIDSessionStorage(
			t,
			oauthStore,
			capturedAuthCode, // IDSession store key is full authcode
			storedRequestFromAuthcode,
			storedSessionFromAuthcode,
			wantDownstreamNonce,
		)
	}
}

func includesOpenIDScope(scopes []string) bool {
	for _, scope := range scopes {
		if scope == "openid" {
			return true
		}
	}
	return false
}

//nolint:funlen
func validateAuthcodeStorage(
	t *testing.T,
	oauthStore fositestoragei.AllFositeStorage,
	storeKey string,
	wantDownstreamGrantedScopes []string,
	wantDownstreamIDTokenSubject string,
	wantDownstreamIDTokenUsername string,
	wantDownstreamIDTokenGroups []string,
	wantDownstreamRequestedScopes []string,
	wantDownstreamClientID string,
	wantDownstreamRedirectURI string,
	wantCustomSessionData *psession.CustomSessionData,
	wantDownstreamAdditionalClaims map[string]interface{},
) (*fosite.Request, *psession.PinnipedSession) {
	t.Helper()

	const (
		authCodeExpirationSeconds = 10 * 60 // Currently, we set our auth code expiration to 10 minutes
		timeComparisonFudgeFactor = time.Second * 15
	)

	// Get the authcode session back from storage so we can require that it was stored correctly.
	storedAuthorizeRequestFromAuthcode, err := oauthStore.GetAuthorizeCodeSession(context.Background(), storeKey, nil)
	require.NoError(t, err)

	// Check that storage returned the expected concrete data types.
	storedRequestFromAuthcode, storedSessionFromAuthcode := castStoredAuthorizeRequest(t, storedAuthorizeRequestFromAuthcode)

	// Check which scopes were granted.
	require.ElementsMatch(t, wantDownstreamGrantedScopes, storedRequestFromAuthcode.GetGrantedScopes())

	// Check all the other fields of the stored request.
	require.NotEmpty(t, storedRequestFromAuthcode.ID)
	require.Equal(t, wantDownstreamClientID, storedRequestFromAuthcode.Client.GetID())
	require.ElementsMatch(t, wantDownstreamRequestedScopes, storedRequestFromAuthcode.RequestedScope)
	require.Nil(t, storedRequestFromAuthcode.RequestedAudience)
	require.Empty(t, storedRequestFromAuthcode.GrantedAudience)
	require.Equal(t, url.Values{"redirect_uri": []string{wantDownstreamRedirectURI}}, storedRequestFromAuthcode.Form)
	testutil.RequireTimeInDelta(t, time.Now(), storedRequestFromAuthcode.RequestedAt, timeComparisonFudgeFactor)

	// We're not using these fields yet, so confirm that we did not set them (for now).
	require.Empty(t, storedSessionFromAuthcode.Fosite.Subject)
	require.Empty(t, storedSessionFromAuthcode.Fosite.Username)
	require.Empty(t, storedSessionFromAuthcode.Fosite.Headers)

	// The authcode that we are issuing should be good for the length of time that we declare in the fosite config.
	testutil.RequireTimeInDelta(t, time.Now().Add(authCodeExpirationSeconds*time.Second), storedSessionFromAuthcode.Fosite.ExpiresAt[fosite.AuthorizeCode], timeComparisonFudgeFactor)
	require.Len(t, storedSessionFromAuthcode.Fosite.ExpiresAt, 1)

	// Now confirm the ID token claims.
	actualClaims := storedSessionFromAuthcode.Fosite.Claims

	// Should always have an azp claim.
	require.Equal(t, wantDownstreamClientID, actualClaims.Extra["azp"])
	wantDownstreamIDTokenExtraClaimsCount := 1 // should always have azp claim

	if len(wantDownstreamAdditionalClaims) > 0 {
		wantDownstreamIDTokenExtraClaimsCount++
	}

	// Check the user's identity, which are put into the downstream ID token's subject, username and groups claims.
	require.Equal(t, wantDownstreamIDTokenSubject, actualClaims.Subject)
	if wantDownstreamIDTokenUsername == "" {
		require.NotContains(t, actualClaims.Extra, "username")
	} else {
		wantDownstreamIDTokenExtraClaimsCount++ // should also have username claim
		require.Equal(t, wantDownstreamIDTokenUsername, actualClaims.Extra["username"])
	}
	if slices.Contains(wantDownstreamGrantedScopes, "groups") {
		wantDownstreamIDTokenExtraClaimsCount++ // should also have groups claim
		actualDownstreamIDTokenGroups := actualClaims.Extra["groups"]
		require.NotNil(t, actualDownstreamIDTokenGroups)
		require.ElementsMatch(t, wantDownstreamIDTokenGroups, actualDownstreamIDTokenGroups)
	} else {
		require.Emptyf(t, wantDownstreamIDTokenGroups, "test case did not want the groups scope to be granted, "+
			"but wanted something in the groups claim, which doesn't make sense. please review the test case's expectations.")
		actualDownstreamIDTokenGroups := actualClaims.Extra["groups"]
		require.Nil(t, actualDownstreamIDTokenGroups)
	}
	if len(wantDownstreamAdditionalClaims) > 0 {
		actualAdditionalClaims, ok := actualClaims.Get("additionalClaims").(map[string]interface{})
		require.True(t, ok, "expected additionalClaims to be a map[string]interface{}")
		require.Equal(t, wantDownstreamAdditionalClaims, actualAdditionalClaims)
	} else {
		require.NotContains(t, actualClaims.Extra, "additionalClaims", "additionalClaims must not be present when there are no wanted additional claims")
	}

	// Make sure that we asserted on every extra claim.
	require.Len(t, actualClaims.Extra, wantDownstreamIDTokenExtraClaimsCount)

	// Check the rest of the downstream ID token's claims. Fosite wants us to set these (in UTC time).
	testutil.RequireTimeInDelta(t, time.Now().UTC(), actualClaims.RequestedAt, timeComparisonFudgeFactor)
	testutil.RequireTimeInDelta(t, time.Now().UTC(), actualClaims.AuthTime, timeComparisonFudgeFactor)
	requestedAtZone, _ := actualClaims.RequestedAt.Zone()
	require.Equal(t, "UTC", requestedAtZone)
	authTimeZone, _ := actualClaims.AuthTime.Zone()
	require.Equal(t, "UTC", authTimeZone)

	// Fosite will set these fields for us in the token endpoint based on the store session
	// information. Therefore, we assert that they are empty because we want the library to do the
	// lifting for us.
	require.Empty(t, actualClaims.Issuer)
	require.Nil(t, actualClaims.Audience)
	require.Empty(t, actualClaims.Nonce)
	require.Zero(t, actualClaims.ExpiresAt)
	require.Zero(t, actualClaims.IssuedAt)

	// These are not needed yet.
	require.Empty(t, actualClaims.JTI)
	require.Empty(t, actualClaims.CodeHash)
	require.Empty(t, actualClaims.AccessTokenHash)
	require.Empty(t, actualClaims.AuthenticationContextClassReference)
	require.Empty(t, actualClaims.AuthenticationMethodsReferences)

	// Check that the custom Pinniped session data matches.
	require.Equal(t, wantCustomSessionData, storedSessionFromAuthcode.Custom)

	return storedRequestFromAuthcode, storedSessionFromAuthcode
}

func validatePKCEStorage(
	t *testing.T,
	oauthStore fositestoragei.AllFositeStorage,
	storeKey string,
	storedRequestFromAuthcode *fosite.Request,
	storedSessionFromAuthcode *psession.PinnipedSession,
	wantDownstreamPKCEChallenge, wantDownstreamPKCEChallengeMethod string,
) {
	t.Helper()

	storedAuthorizeRequestFromPKCE, err := oauthStore.GetPKCERequestSession(context.Background(), storeKey, nil)
	require.NoError(t, err)

	// Check that storage returned the expected concrete data types.
	storedRequestFromPKCE, storedSessionFromPKCE := castStoredAuthorizeRequest(t, storedAuthorizeRequestFromPKCE)

	// The stored PKCE request should be the same as the stored authcode request.
	require.Equal(t, storedRequestFromAuthcode.ID, storedRequestFromPKCE.ID)
	require.Equal(t, storedSessionFromAuthcode, storedSessionFromPKCE)

	// The stored PKCE request should also contain the PKCE challenge that the downstream sent us.
	require.Equal(t, wantDownstreamPKCEChallenge, storedRequestFromPKCE.Form.Get("code_challenge"))
	require.Equal(t, wantDownstreamPKCEChallengeMethod, storedRequestFromPKCE.Form.Get("code_challenge_method"))
}

func validateIDSessionStorage(
	t *testing.T,
	oauthStore fositestoragei.AllFositeStorage,
	storeKey string,
	storedRequestFromAuthcode *fosite.Request,
	storedSessionFromAuthcode *psession.PinnipedSession,
	wantDownstreamNonce string,
) {
	t.Helper()

	storedAuthorizeRequestFromIDSession, err := oauthStore.GetOpenIDConnectSession(context.Background(), storeKey, nil)
	require.NoError(t, err)

	// Check that storage returned the expected concrete data types.
	storedRequestFromIDSession, storedSessionFromIDSession := castStoredAuthorizeRequest(t, storedAuthorizeRequestFromIDSession)

	// The stored IDSession request should be the same as the stored authcode request.
	require.Equal(t, storedRequestFromAuthcode.ID, storedRequestFromIDSession.ID)
	require.Equal(t, storedSessionFromAuthcode, storedSessionFromIDSession)

	// The stored IDSession request should also contain the nonce that the downstream sent us.
	require.Equal(t, wantDownstreamNonce, storedRequestFromIDSession.Form.Get("nonce"))
}

func castStoredAuthorizeRequest(t *testing.T, storedAuthorizeRequest fosite.Requester) (*fosite.Request, *psession.PinnipedSession) {
	t.Helper()

	storedRequest, ok := storedAuthorizeRequest.(*fosite.Request)
	require.Truef(t, ok, "could not cast %T to %T", storedAuthorizeRequest, &fosite.Request{})
	storedSession, ok := storedAuthorizeRequest.GetSession().(*psession.PinnipedSession)
	require.Truef(t, ok, "could not cast %T to %T", storedAuthorizeRequest.GetSession(), &psession.PinnipedSession{})

	return storedRequest, storedSession
}

// FilterClientSecretCreateActions ignores any reads made to get a storage secret corresponding to an OIDCClient, since these
// are normal actions when the request is using a dynamic client's client_id, and we don't need to make assertions
// about these Secrets since they are not related to session storage.
func FilterClientSecretCreateActions(actions []kubetesting.Action) []kubetesting.Action {
	filtered := make([]kubetesting.Action, 0, len(actions))
	for _, action := range actions {
		if action.Matches("get", "secrets") {
			getAction := action.(kubetesting.GetAction)
			if strings.HasPrefix(getAction.GetName(), "pinniped-storage-oidc-client-secret-") {
				continue // filter out OIDCClient's storage secret reads
			}
		}
		filtered = append(filtered, action) // otherwise include the action
	}
	return filtered
}
