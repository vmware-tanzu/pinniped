// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testidplister

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/federationdomain/dynamicupstreamprovider"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider/resolvedgithub"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider/resolvedldap"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider/resolvedoidc"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil/oidctestutil"
)

// TestFederationDomainIdentityProvidersListerFinder implements FederationDomainIdentityProvidersListerFinderI
// for testing purposes.
type TestFederationDomainIdentityProvidersListerFinder struct {
	upstreamOIDCIdentityProviders            []*oidctestutil.TestUpstreamOIDCIdentityProvider
	upstreamLDAPIdentityProviders            []*oidctestutil.TestUpstreamLDAPIdentityProvider
	upstreamActiveDirectoryIdentityProviders []*oidctestutil.TestUpstreamLDAPIdentityProvider
	upstreamGitHubIdentityProviders          []*oidctestutil.TestUpstreamGitHubIdentityProvider
	defaultIDPDisplayName                    string
}

func (t *TestFederationDomainIdentityProvidersListerFinder) HasDefaultIDP() bool {
	return t.defaultIDPDisplayName != ""
}

func (t *TestFederationDomainIdentityProvidersListerFinder) IDPCount() int {
	return len(t.upstreamOIDCIdentityProviders) + len(t.upstreamLDAPIdentityProviders) + len(t.upstreamActiveDirectoryIdentityProviders)
}

func (t *TestFederationDomainIdentityProvidersListerFinder) GetIdentityProviders() []resolvedprovider.FederationDomainResolvedIdentityProvider {
	fdIDPs := make([]resolvedprovider.FederationDomainResolvedIdentityProvider,
		len(t.upstreamOIDCIdentityProviders)+len(t.upstreamLDAPIdentityProviders)+len(t.upstreamActiveDirectoryIdentityProviders)+len(t.upstreamGitHubIdentityProviders))
	i := 0
	for _, testIDP := range t.upstreamOIDCIdentityProviders {
		fdIDP := &resolvedoidc.FederationDomainResolvedOIDCIdentityProvider{
			DisplayName:         testIDP.DisplayNameForFederationDomain,
			Provider:            testIDP,
			SessionProviderType: psession.ProviderTypeOIDC,
			Transforms:          testIDP.TransformsForFederationDomain,
		}
		fdIDPs[i] = fdIDP
		i++
	}
	for _, testIDP := range t.upstreamLDAPIdentityProviders {
		fdIDP := &resolvedldap.FederationDomainResolvedLDAPIdentityProvider{
			DisplayName:         testIDP.DisplayNameForFederationDomain,
			Provider:            testIDP,
			SessionProviderType: psession.ProviderTypeLDAP,
			Transforms:          testIDP.TransformsForFederationDomain,
		}
		fdIDPs[i] = fdIDP
		i++
	}
	for _, testIDP := range t.upstreamActiveDirectoryIdentityProviders {
		fdIDP := &resolvedldap.FederationDomainResolvedLDAPIdentityProvider{
			DisplayName:         testIDP.DisplayNameForFederationDomain,
			Provider:            testIDP,
			SessionProviderType: psession.ProviderTypeActiveDirectory,
			Transforms:          testIDP.TransformsForFederationDomain,
		}
		fdIDPs[i] = fdIDP
		i++
	}
	for _, testIDP := range t.upstreamGitHubIdentityProviders {
		fdIDP := &resolvedgithub.FederationDomainResolvedGitHubIdentityProvider{
			DisplayName:         testIDP.DisplayNameForFederationDomain,
			Provider:            testIDP,
			SessionProviderType: psession.ProviderTypeGitHub,
			Transforms:          testIDP.TransformsForFederationDomain,
		}
		fdIDPs[i] = fdIDP
		i++
	}
	return fdIDPs
}

func (t *TestFederationDomainIdentityProvidersListerFinder) FindDefaultIDP() (resolvedprovider.FederationDomainResolvedIdentityProvider, error) {
	if t.defaultIDPDisplayName == "" {
		return nil, fmt.Errorf("identity provider not found: this federation domain does not have a default identity provider")
	}
	return t.FindUpstreamIDPByDisplayName(t.defaultIDPDisplayName)
}

func (t *TestFederationDomainIdentityProvidersListerFinder) FindUpstreamIDPByDisplayName(upstreamIDPDisplayName string) (resolvedprovider.FederationDomainResolvedIdentityProvider, error) {
	for _, testIDP := range t.upstreamOIDCIdentityProviders {
		if upstreamIDPDisplayName == testIDP.DisplayNameForFederationDomain {
			return &resolvedoidc.FederationDomainResolvedOIDCIdentityProvider{
				DisplayName:         testIDP.DisplayNameForFederationDomain,
				Provider:            testIDP,
				SessionProviderType: psession.ProviderTypeOIDC,
				Transforms:          testIDP.TransformsForFederationDomain,
			}, nil
		}
	}
	for _, testIDP := range t.upstreamLDAPIdentityProviders {
		if upstreamIDPDisplayName == testIDP.DisplayNameForFederationDomain {
			return &resolvedldap.FederationDomainResolvedLDAPIdentityProvider{
				DisplayName:         testIDP.DisplayNameForFederationDomain,
				Provider:            testIDP,
				SessionProviderType: psession.ProviderTypeLDAP,
				Transforms:          testIDP.TransformsForFederationDomain,
			}, nil
		}
	}
	for _, testIDP := range t.upstreamActiveDirectoryIdentityProviders {
		if upstreamIDPDisplayName == testIDP.DisplayNameForFederationDomain {
			return &resolvedldap.FederationDomainResolvedLDAPIdentityProvider{
				DisplayName:         testIDP.DisplayNameForFederationDomain,
				Provider:            testIDP,
				SessionProviderType: psession.ProviderTypeActiveDirectory,
				Transforms:          testIDP.TransformsForFederationDomain,
			}, nil
		}
	}
	for _, testIDP := range t.upstreamGitHubIdentityProviders {
		if upstreamIDPDisplayName == testIDP.DisplayNameForFederationDomain {
			return &resolvedgithub.FederationDomainResolvedGitHubIdentityProvider{
				DisplayName:         testIDP.DisplayNameForFederationDomain,
				Provider:            testIDP,
				SessionProviderType: psession.ProviderTypeGitHub,
				Transforms:          testIDP.TransformsForFederationDomain,
			}, nil
		}
	}
	return nil, fmt.Errorf("did not find IDP with name %q", upstreamIDPDisplayName)
}

func (t *TestFederationDomainIdentityProvidersListerFinder) SetOIDCIdentityProviders(providers []*oidctestutil.TestUpstreamOIDCIdentityProvider) {
	t.upstreamOIDCIdentityProviders = providers
}

func (t *TestFederationDomainIdentityProvidersListerFinder) SetLDAPIdentityProviders(providers []*oidctestutil.TestUpstreamLDAPIdentityProvider) {
	t.upstreamLDAPIdentityProviders = providers
}

func (t *TestFederationDomainIdentityProvidersListerFinder) SetActiveDirectoryIdentityProviders(providers []*oidctestutil.TestUpstreamLDAPIdentityProvider) {
	t.upstreamActiveDirectoryIdentityProviders = providers
}

func (t *TestFederationDomainIdentityProvidersListerFinder) SetGitHubIdentityProviders(providers []*oidctestutil.TestUpstreamGitHubIdentityProvider) {
	t.upstreamGitHubIdentityProviders = providers
}

// UpstreamIDPListerBuilder can be used to build either a dynamicupstreamprovider.DynamicUpstreamIDPProvider
// or a FederationDomainIdentityProvidersListerFinderI for testing.
type UpstreamIDPListerBuilder struct {
	upstreamOIDCIdentityProviders            []*oidctestutil.TestUpstreamOIDCIdentityProvider
	upstreamLDAPIdentityProviders            []*oidctestutil.TestUpstreamLDAPIdentityProvider
	upstreamActiveDirectoryIdentityProviders []*oidctestutil.TestUpstreamLDAPIdentityProvider
	upstreamGitHubIdentityProviders          []*oidctestutil.TestUpstreamGitHubIdentityProvider
	defaultIDPDisplayName                    string
}

func (b *UpstreamIDPListerBuilder) WithOIDC(upstreamOIDCIdentityProviders ...*oidctestutil.TestUpstreamOIDCIdentityProvider) *UpstreamIDPListerBuilder {
	b.upstreamOIDCIdentityProviders = append(b.upstreamOIDCIdentityProviders, upstreamOIDCIdentityProviders...)
	return b
}

func (b *UpstreamIDPListerBuilder) WithLDAP(upstreamLDAPIdentityProviders ...*oidctestutil.TestUpstreamLDAPIdentityProvider) *UpstreamIDPListerBuilder {
	b.upstreamLDAPIdentityProviders = append(b.upstreamLDAPIdentityProviders, upstreamLDAPIdentityProviders...)
	return b
}

func (b *UpstreamIDPListerBuilder) WithActiveDirectory(upstreamActiveDirectoryIdentityProviders ...*oidctestutil.TestUpstreamLDAPIdentityProvider) *UpstreamIDPListerBuilder {
	b.upstreamActiveDirectoryIdentityProviders = append(b.upstreamActiveDirectoryIdentityProviders, upstreamActiveDirectoryIdentityProviders...)
	return b
}

func (b *UpstreamIDPListerBuilder) WithGitHub(upstreamGithubIdentityProviders ...*oidctestutil.TestUpstreamGitHubIdentityProvider) *UpstreamIDPListerBuilder {
	b.upstreamGitHubIdentityProviders = append(b.upstreamGitHubIdentityProviders, upstreamGithubIdentityProviders...)
	return b
}

func (b *UpstreamIDPListerBuilder) WithDefaultIDPDisplayName(defaultIDPDisplayName string) *UpstreamIDPListerBuilder {
	b.defaultIDPDisplayName = defaultIDPDisplayName
	return b
}

func (b *UpstreamIDPListerBuilder) BuildFederationDomainIdentityProvidersListerFinder() *TestFederationDomainIdentityProvidersListerFinder {
	return &TestFederationDomainIdentityProvidersListerFinder{
		upstreamOIDCIdentityProviders:            b.upstreamOIDCIdentityProviders,
		upstreamLDAPIdentityProviders:            b.upstreamLDAPIdentityProviders,
		upstreamActiveDirectoryIdentityProviders: b.upstreamActiveDirectoryIdentityProviders,
		upstreamGitHubIdentityProviders:          b.upstreamGitHubIdentityProviders,
		defaultIDPDisplayName:                    b.defaultIDPDisplayName,
	}
}

func (b *UpstreamIDPListerBuilder) BuildDynamicUpstreamIDPProvider() dynamicupstreamprovider.DynamicUpstreamIDPProvider {
	idpProvider := dynamicupstreamprovider.NewDynamicUpstreamIDPProvider()

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

	githubUpstreams := make([]upstreamprovider.UpstreamGithubIdentityProviderI, len(b.upstreamGitHubIdentityProviders))
	for i := range b.upstreamGitHubIdentityProviders {
		githubUpstreams[i] = upstreamprovider.UpstreamGithubIdentityProviderI(b.upstreamGitHubIdentityProviders[i])
	}
	idpProvider.SetGitHubIdentityProviders(githubUpstreams)

	return idpProvider
}

func (b *UpstreamIDPListerBuilder) RequireExactlyOneCallToPasswordCredentialsGrantAndValidateTokens(
	t *testing.T,
	expectedPerformedByUpstreamName string,
	expectedArgs *oidctestutil.PasswordCredentialsGrantAndValidateTokensArgs,
) {
	t.Helper()
	var actualArgs *oidctestutil.PasswordCredentialsGrantAndValidateTokensArgs
	var actualNameOfUpstreamWhichMadeCall string
	actualCallCountAcrossAllOIDCUpstreams := 0
	for _, upstreamOIDC := range b.upstreamOIDCIdentityProviders {
		callCountOnThisUpstream := upstreamOIDC.PasswordCredentialsGrantAndValidateTokensCallCount()
		actualCallCountAcrossAllOIDCUpstreams += callCountOnThisUpstream
		if callCountOnThisUpstream == 1 {
			actualNameOfUpstreamWhichMadeCall = upstreamOIDC.Name
			actualArgs = upstreamOIDC.PasswordCredentialsGrantAndValidateTokensArgs(0)
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
		actualCallCountAcrossAllOIDCUpstreams += upstreamOIDC.PasswordCredentialsGrantAndValidateTokensCallCount()
	}
	require.Equal(t, 0, actualCallCountAcrossAllOIDCUpstreams,
		"expected exactly zero calls to PasswordCredentialsGrantAndValidateTokens()",
	)
}

func (b *UpstreamIDPListerBuilder) RequireExactlyOneOIDCAuthcodeExchange(
	t *testing.T,
	expectedPerformedByUpstreamName string,
	expectedArgs *oidctestutil.ExchangeAuthcodeAndValidateTokenArgs,
) {
	t.Helper()
	var actualArgs *oidctestutil.ExchangeAuthcodeAndValidateTokenArgs
	var actualNameOfUpstreamWhichMadeCall string
	actualCallCount := 0
	for _, upstream := range b.upstreamOIDCIdentityProviders {
		callCountOnThisUpstream := upstream.ExchangeAuthcodeAndValidateTokensCallCount()
		actualCallCount += callCountOnThisUpstream
		if callCountOnThisUpstream == 1 {
			actualNameOfUpstreamWhichMadeCall = upstream.Name
			actualArgs = upstream.ExchangeAuthcodeAndValidateTokensArgs(0)
		}
	}
	require.Equal(t, 1, actualCallCount,
		"expected exactly one call to OIDC ExchangeAuthcodeAndValidateTokens()",
	)
	require.Equal(t, expectedPerformedByUpstreamName, actualNameOfUpstreamWhichMadeCall,
		"OIDC ExchangeAuthcodeAndValidateTokens() was called on the wrong upstream name",
	)
	require.Equal(t, expectedArgs, actualArgs)
}

func (b *UpstreamIDPListerBuilder) RequireExactlyOneGitHubAuthcodeExchange(
	t *testing.T,
	expectedPerformedByUpstreamName string,
	expectedArgs *oidctestutil.ExchangeAuthcodeArgs,
) {
	t.Helper()
	var actualArgs *oidctestutil.ExchangeAuthcodeArgs
	var actualNameOfUpstreamWhichMadeCall string
	actualCallCount := 0
	for _, upstream := range b.upstreamGitHubIdentityProviders {
		callCountOnThisUpstream := upstream.ExchangeAuthcodeCallCount()
		actualCallCount += callCountOnThisUpstream
		if callCountOnThisUpstream == 1 {
			actualNameOfUpstreamWhichMadeCall = upstream.Name
			actualArgs = upstream.ExchangeAuthcodeArgs(0)
		}
	}
	require.Equal(t, 1, actualCallCount,
		"expected exactly one call to GitHub ExchangeAuthcode()",
	)
	require.Equal(t, expectedPerformedByUpstreamName, actualNameOfUpstreamWhichMadeCall,
		"GitHub ExchangeAuthcode() was called on the wrong upstream name",
	)
	require.Equal(t, expectedArgs, actualArgs)
}

func (b *UpstreamIDPListerBuilder) RequireExactlyZeroAuthcodeExchanges(t *testing.T) {
	t.Helper()
	actualCallCount := 0
	for _, upstreamOIDC := range b.upstreamOIDCIdentityProviders {
		actualCallCount += upstreamOIDC.ExchangeAuthcodeAndValidateTokensCallCount()
	}
	for _, upstreamGitHub := range b.upstreamGitHubIdentityProviders {
		actualCallCount += upstreamGitHub.ExchangeAuthcodeCallCount()
	}

	require.Equal(t, 0, actualCallCount,
		"expected exactly zero calls to OIDC ExchangeAuthcodeAndValidateTokens() or GitHub ExchangeAuthcode()",
	)
}

func (b *UpstreamIDPListerBuilder) RequireExactlyOneCallToPerformRefresh(
	t *testing.T,
	expectedPerformedByUpstreamName string,
	expectedArgs *oidctestutil.PerformRefreshArgs,
) {
	t.Helper()
	var actualArgs *oidctestutil.PerformRefreshArgs
	var actualNameOfUpstreamWhichMadeCall string
	actualCallCountAcrossAllUpstreams := 0
	for _, upstreamOIDC := range b.upstreamOIDCIdentityProviders {
		callCountOnThisUpstream := upstreamOIDC.PerformRefreshCallCount()
		actualCallCountAcrossAllUpstreams += callCountOnThisUpstream
		if callCountOnThisUpstream == 1 {
			actualNameOfUpstreamWhichMadeCall = upstreamOIDC.Name
			actualArgs = upstreamOIDC.PerformRefreshArgs(0)
		}
	}
	for _, upstreamLDAP := range b.upstreamLDAPIdentityProviders {
		callCountOnThisUpstream := upstreamLDAP.PerformRefreshCallCount()
		actualCallCountAcrossAllUpstreams += callCountOnThisUpstream
		if callCountOnThisUpstream == 1 {
			actualNameOfUpstreamWhichMadeCall = upstreamLDAP.Name
			actualArgs = upstreamLDAP.PerformRefreshArgs(0)
		}
	}
	for _, upstreamAD := range b.upstreamActiveDirectoryIdentityProviders {
		callCountOnThisUpstream := upstreamAD.PerformRefreshCallCount()
		actualCallCountAcrossAllUpstreams += callCountOnThisUpstream
		if callCountOnThisUpstream == 1 {
			actualNameOfUpstreamWhichMadeCall = upstreamAD.Name
			actualArgs = upstreamAD.PerformRefreshArgs(0)
		}
	}
	// TODO: probably add GitHub loop once we flesh out the structs
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
		actualCallCountAcrossAllUpstreams += upstreamOIDC.PerformRefreshCallCount()
	}
	for _, upstreamLDAP := range b.upstreamLDAPIdentityProviders {
		actualCallCountAcrossAllUpstreams += upstreamLDAP.PerformRefreshCallCount()
	}
	for _, upstreamActiveDirectory := range b.upstreamActiveDirectoryIdentityProviders {
		actualCallCountAcrossAllUpstreams += upstreamActiveDirectory.PerformRefreshCallCount()
	}
	// TODO: probably add GitHub loop once we flesh out the structs

	require.Equal(t, 0, actualCallCountAcrossAllUpstreams,
		"expected exactly zero calls to PerformRefresh()",
	)
}

func (b *UpstreamIDPListerBuilder) RequireExactlyOneCallToValidateToken(
	t *testing.T,
	expectedPerformedByUpstreamName string,
	expectedArgs *oidctestutil.ValidateTokenAndMergeWithUserInfoArgs,
) {
	t.Helper()
	var actualArgs *oidctestutil.ValidateTokenAndMergeWithUserInfoArgs
	var actualNameOfUpstreamWhichMadeCall string
	actualCallCountAcrossAllOIDCUpstreams := 0
	for _, upstreamOIDC := range b.upstreamOIDCIdentityProviders {
		callCountOnThisUpstream := upstreamOIDC.ValidateTokenAndMergeWithUserInfoCallCount()
		actualCallCountAcrossAllOIDCUpstreams += callCountOnThisUpstream
		if callCountOnThisUpstream == 1 {
			actualNameOfUpstreamWhichMadeCall = upstreamOIDC.Name
			actualArgs = upstreamOIDC.ValidateTokenAndMergeWithUserInfoArgs(0)
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
		actualCallCountAcrossAllOIDCUpstreams += upstreamOIDC.ValidateTokenAndMergeWithUserInfoCallCount()
	}
	require.Equal(t, 0, actualCallCountAcrossAllOIDCUpstreams,
		"expected exactly zero calls to ValidateTokenAndMergeWithUserInfo()",
	)
}

func (b *UpstreamIDPListerBuilder) RequireExactlyOneCallToRevokeToken(
	t *testing.T,
	expectedPerformedByUpstreamName string,
	expectedArgs *oidctestutil.RevokeTokenArgs,
) {
	t.Helper()
	var actualArgs *oidctestutil.RevokeTokenArgs
	var actualNameOfUpstreamWhichMadeCall string
	actualCallCountAcrossAllOIDCUpstreams := 0
	for _, upstreamOIDC := range b.upstreamOIDCIdentityProviders {
		callCountOnThisUpstream := upstreamOIDC.RevokeTokenCallCount()
		actualCallCountAcrossAllOIDCUpstreams += callCountOnThisUpstream
		if callCountOnThisUpstream == 1 {
			actualNameOfUpstreamWhichMadeCall = upstreamOIDC.Name
			actualArgs = upstreamOIDC.RevokeTokenArgs(0)
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
		actualCallCountAcrossAllOIDCUpstreams += upstreamOIDC.RevokeTokenCallCount()
	}
	require.Equal(t, 0, actualCallCountAcrossAllOIDCUpstreams,
		"expected exactly zero calls to RevokeToken()",
	)
}

func NewUpstreamIDPListerBuilder() *UpstreamIDPListerBuilder {
	return &UpstreamIDPListerBuilder{}
}
