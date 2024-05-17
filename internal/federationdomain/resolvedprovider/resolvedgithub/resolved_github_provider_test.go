// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resolvedgithub

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	idpdiscoveryv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/internal/testutil/transformtestutil"
	"go.pinniped.dev/internal/upstreamgithub"
)

func TestFederationDomainResolvedGitHubIdentityProvider(t *testing.T) {
	transforms := transformtestutil.NewRejectAllAuthPipeline(t)

	provider := upstreamgithub.New(upstreamgithub.ProviderConfig{
		Name:                 "fake-provider-config",
		ResourceUID:          "fake-resource-uid",
		APIBaseURL:           "https://fake-api-host.com",
		UsernameAttribute:    idpv1alpha1.GitHubUsernameID,
		GroupNameAttribute:   idpv1alpha1.GitHubUseTeamSlugForGroupName,
		AllowedOrganizations: []string{"org1", "org2"},
		HttpClient:           nil, // not needed yet for this test
		OAuth2Config: &oauth2.Config{
			ClientID:     "fake-client-id",
			ClientSecret: "fake-client-secret",
			Scopes:       []string{"read:user", "read:org"},
			Endpoint: oauth2.Endpoint{
				AuthURL:       "https://fake-authorization-url",
				DeviceAuthURL: "",
				TokenURL:      "https://fake-token-url",
				AuthStyle:     oauth2.AuthStyleInParams,
			},
		},
	})

	subject := FederationDomainResolvedGitHubIdentityProvider{
		DisplayName:         "fake-display-name",
		Provider:            provider,
		SessionProviderType: psession.ProviderTypeGitHub,
		Transforms:          transforms,
	}

	require.Equal(t, "fake-display-name", subject.GetDisplayName())
	require.Equal(t, provider, subject.GetProvider())
	require.Equal(t, psession.ProviderTypeGitHub, subject.GetSessionProviderType())
	require.Equal(t, idpdiscoveryv1alpha1.IDPTypeGitHub, subject.GetIDPDiscoveryType())
	require.Equal(t, []idpdiscoveryv1alpha1.IDPFlow{idpdiscoveryv1alpha1.IDPFlowBrowserAuthcode}, subject.GetIDPDiscoveryFlows())
	require.Equal(t, transforms, subject.GetTransforms())

	originalCustomSession := &psession.CustomSessionData{
		Username:         "fake-username",
		UpstreamUsername: "fake-upstream-username",
		GitHub:           &psession.GitHubSessionData{UpstreamAccessToken: "fake-upstream-access-token"},
	}
	clonedCustomSession := subject.CloneIDPSpecificSessionDataFromSession(originalCustomSession)
	require.Equal(t,
		&psession.GitHubSessionData{UpstreamAccessToken: "fake-upstream-access-token"},
		clonedCustomSession,
	)
	require.NotSame(t, originalCustomSession, clonedCustomSession)

	customSessionToBeMutated := &psession.CustomSessionData{
		Username:         "fake-username2",
		UpstreamUsername: "fake-upstream-username2",
	}
	subject.ApplyIDPSpecificSessionDataToSession(customSessionToBeMutated, &psession.GitHubSessionData{UpstreamAccessToken: "OTHER-upstream-access-token"})
	require.Equal(t, &psession.CustomSessionData{
		Username:         "fake-username2",
		UpstreamUsername: "fake-upstream-username2",
		GitHub:           &psession.GitHubSessionData{UpstreamAccessToken: "OTHER-upstream-access-token"},
	}, customSessionToBeMutated)

	redirectURL, err := subject.UpstreamAuthorizeRedirectURL(
		&resolvedprovider.UpstreamAuthorizeRequestState{
			EncodedStateParam: "encodedStateParam12345",
			PKCE:              "pkce6789",
			Nonce:             "nonce1289",
		},
		"https://localhost/fake/path",
	)
	require.NoError(t, err)
	// Note that GitHub does not require (or document) the standard response_type=code param, but in manual testing
	// of GitHub authorize endpoint, it seems to ignore the param. The oauth2 package wants to add the param, so
	// we will let it.
	require.Equal(t,
		"https://fake-authorization-url?"+
			"client_id=fake-client-id&"+
			"redirect_uri=https%3A%2F%2Flocalhost%2Ffake%2Fpath%2Fcallback&"+
			"response_type=code&"+
			"scope=read%3Auser+read%3Aorg&"+
			"state=encodedStateParam12345",
		redirectURL,
	)
}

func TestLoginFromCallback(t *testing.T) {
	uniqueCtx := context.WithValue(context.Background(), "some-unique-key", "some-value") //nolint:staticcheck // okay to use string key for test

	tests := []struct {
		name        string
		provider    *oidctestutil.TestUpstreamGitHubIdentityProvider
		authcode    string
		redirectURI string

		wantExchangeAuthcodeCall bool
		wantExchangeAuthcodeArgs *oidctestutil.ExchangeAuthcodeArgs
		wantGetUserCall          bool
		wantGetUserArgs          *oidctestutil.GetUserArgs
		wantIdentity             *resolvedprovider.Identity
		wantExtras               *resolvedprovider.IdentityLoginExtras
		wantErr                  string
	}{
		{
			name: "happy path",
			provider: oidctestutil.NewTestUpstreamGitHubIdentityProviderBuilder().
				WithAccessToken("fake-access-token").
				WithUser(&upstreamprovider.GitHubUser{
					Username:          "fake-username",
					Groups:            []string{"fake-group1", "fake-group2"},
					DownstreamSubject: "https://fake-downstream-subject",
				}).
				Build(),
			authcode:                 "fake-authcode",
			redirectURI:              "https://fake-redirect-uri",
			wantExchangeAuthcodeCall: true,
			wantExchangeAuthcodeArgs: &oidctestutil.ExchangeAuthcodeArgs{
				Ctx:         uniqueCtx,
				Authcode:    "fake-authcode",
				RedirectURI: "https://fake-redirect-uri",
			},
			wantGetUserCall: true,
			wantGetUserArgs: &oidctestutil.GetUserArgs{
				Ctx:         uniqueCtx,
				AccessToken: "fake-access-token",
			},
			wantIdentity: &resolvedprovider.Identity{
				UpstreamUsername:  "fake-username",
				UpstreamGroups:    []string{"fake-group1", "fake-group2"},
				DownstreamSubject: "https://fake-downstream-subject",
				IDPSpecificSessionData: &psession.GitHubSessionData{
					UpstreamAccessToken: "fake-access-token",
				},
			},
			wantExtras: &resolvedprovider.IdentityLoginExtras{},
		},
		{
			name: "error while exchanging authcode",
			provider: oidctestutil.NewTestUpstreamGitHubIdentityProviderBuilder().
				WithAuthcodeExchangeError(errors.New("fake authcode exchange error")).
				Build(),
			authcode:                 "fake-authcode",
			redirectURI:              "https://fake-redirect-uri",
			wantExchangeAuthcodeCall: true,
			wantExchangeAuthcodeArgs: &oidctestutil.ExchangeAuthcodeArgs{
				Ctx:         uniqueCtx,
				Authcode:    "fake-authcode",
				RedirectURI: "https://fake-redirect-uri",
			},
			wantGetUserCall: false,
			wantIdentity:    nil,
			wantExtras:      nil,
			wantErr:         "failed to exchange auth code using GitHub API: fake authcode exchange error",
		},
		{
			name: "error while getting user info",
			provider: oidctestutil.NewTestUpstreamGitHubIdentityProviderBuilder().
				WithAccessToken("fake-access-token").
				WithGetUserError(errors.New("fake user info error")).
				Build(),
			authcode:                 "fake-authcode",
			redirectURI:              "https://fake-redirect-uri",
			wantExchangeAuthcodeCall: true,
			wantExchangeAuthcodeArgs: &oidctestutil.ExchangeAuthcodeArgs{
				Ctx:         uniqueCtx,
				Authcode:    "fake-authcode",
				RedirectURI: "https://fake-redirect-uri",
			},
			wantGetUserCall: true,
			wantGetUserArgs: &oidctestutil.GetUserArgs{
				Ctx:         uniqueCtx,
				AccessToken: "fake-access-token",
			},
			wantIdentity: nil,
			wantExtras:   nil,
			wantErr:      "failed to get user info from GitHub API: fake user info error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transforms := transformtestutil.NewRejectAllAuthPipeline(t)

			subject := FederationDomainResolvedGitHubIdentityProvider{
				DisplayName:         "fake-display-name",
				Provider:            test.provider,
				SessionProviderType: psession.ProviderTypeGitHub,
				Transforms:          transforms,
			}

			identity, loginExtras, err := subject.LoginFromCallback(uniqueCtx,
				test.authcode,
				"pkce-will-be-ignored",
				"nonce-will-be-ignored",
				test.redirectURI,
			)

			if test.wantExchangeAuthcodeCall {
				require.Equal(t, 1, test.provider.ExchangeAuthcodeCallCount())
				require.Equal(t, test.wantExchangeAuthcodeArgs, test.provider.ExchangeAuthcodeArgs(0))
			} else {
				require.Zero(t, test.provider.ExchangeAuthcodeCallCount())
			}

			if test.wantGetUserCall {
				require.Equal(t, 1, test.provider.GetUserCallCount())
				require.Equal(t, test.wantGetUserArgs, test.provider.GetUserArgs(0))
			} else {
				require.Zero(t, test.provider.GetUserCallCount())
			}

			if test.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, test.wantErr)
			}
			require.Equal(t, test.wantExtras, loginExtras)
			require.Equal(t, test.wantIdentity, identity)
		})
	}
}
