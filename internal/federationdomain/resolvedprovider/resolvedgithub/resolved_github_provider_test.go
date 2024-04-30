// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resolvedgithub

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/upstreamgithub"
)

type fakeTransformer struct{}

func (a fakeTransformer) Evaluate(_ context.Context, _ string, _ []string) (*idtransform.TransformationResult, error) {
	return &idtransform.TransformationResult{}, nil
}
func (a fakeTransformer) Source() interface{} { return nil }

func TestFederationDomainResolvedGitHubIdentityProvider(t *testing.T) {
	fake := fakeTransformer{}
	transforms := idtransform.NewTransformationPipeline()
	transforms.AppendTransformation(fake)
	subject := FederationDomainResolvedGitHubIdentityProvider{
		DisplayName: "fake-display-name",
		Provider: upstreamgithub.New(upstreamgithub.ProviderConfig{
			Name:        "fake-provider-config",
			ResourceUID: "fake-resource-uid",
			OAuth2Config: &oauth2.Config{
				ClientID:     "clientID12345",
				ClientSecret: "clientSecret6789",
				RedirectURL:  "some/redirect/url",
			},
		}),
		SessionProviderType: psession.ProviderTypeGitHub,
		Transforms:          transforms,
	}

	require.Equal(t, "fake-display-name", subject.GetDisplayName())
	require.Equal(t, upstreamgithub.New(upstreamgithub.ProviderConfig{
		Name:        "fake-provider-config",
		ResourceUID: "fake-resource-uid",
		OAuth2Config: &oauth2.Config{
			ClientID:     "clientID12345",
			ClientSecret: "clientSecret6789",
			RedirectURL:  "some/redirect/url",
		},
	}), subject.GetProvider())
	require.Equal(t, psession.ProviderTypeGitHub, subject.GetSessionProviderType())
	require.Equal(t, v1alpha1.IDPTypeGitHub, subject.GetIDPDiscoveryType())
	require.Equal(t, []v1alpha1.IDPFlow{v1alpha1.IDPFlowBrowserAuthcode}, subject.GetIDPDiscoveryFlows())
	require.Equal(t, transforms, subject.GetTransforms())
	require.Equal(t, &psession.GitHubSessionData{}, subject.CloneIDPSpecificSessionDataFromSession(&psession.CustomSessionData{
		Username:         "fake-username",
		UpstreamUsername: "fake-upstream-username",
		GitHub:           &psession.GitHubSessionData{},
	}))
	redirectURL, err := subject.UpstreamAuthorizeRedirectURL(
		&resolvedprovider.UpstreamAuthorizeRequestState{
			EncodedStateParam: "encodedStateParam12345",
			PKCE:              "pkce6789",
			Nonce:             "nonce1289",
		},
		"https://localhost/fake/path",
	)
	require.NoError(t, err)
	require.Equal(t,
		"?client_id=clientID12345&redirect_uri=https%3A%2F%2Flocalhost%2Ffake%2Fpath%2Fcallback&response_type=code&state=encodedStateParam12345",
		redirectURL,
	)
}
