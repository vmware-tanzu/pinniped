// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resolvedgithub

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	idpdiscoveryv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/psession"
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
	subject.ApplyIDPSpecificSessionDataToSession(customSessionToBeMutated, &psession.GitHubSessionData{UpstreamAccessToken: "fake-upstream-access-token2"})
	require.Equal(t, &psession.CustomSessionData{
		Username:         "fake-username2",
		UpstreamUsername: "fake-upstream-username2",
		GitHub:           &psession.GitHubSessionData{UpstreamAccessToken: "fake-upstream-access-token2"},
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
