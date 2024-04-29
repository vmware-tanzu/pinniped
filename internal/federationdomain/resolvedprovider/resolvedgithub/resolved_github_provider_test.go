// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resolvedgithub

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
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
		}),
		SessionProviderType: psession.ProviderTypeGitHub,
		Transforms:          transforms,
	}

	require.Equal(t, "fake-display-name", subject.GetDisplayName())
	require.Equal(t, upstreamgithub.New(upstreamgithub.ProviderConfig{
		Name:        "fake-provider-config",
		ResourceUID: "fake-resource-uid",
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
}
