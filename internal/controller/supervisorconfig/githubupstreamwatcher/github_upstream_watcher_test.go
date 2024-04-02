// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package githubupstreamwatcher

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/federationdomain/dynamicupstreamprovider"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil/githubtestutil"
	"go.pinniped.dev/internal/upstreamgithub"
)

func TestController(t *testing.T) {
	t.Parallel()

	testNamespace := "foo"
	testName := "bar"

	tests := []struct {
		name                    string
		githubIdentityProviders []runtime.Object
		inputSecrets            []runtime.Object
		configClient            func(*pinnipedfake.Clientset)
		wantErr                 string
		wantLogs                []string
		wantResultingCache      []*githubtestutil.TestUpstreamGithubIdentityProvider
		wantResultingUpstreams  []v1alpha1.GitHubIdentityProvider
	}{
		{
			name: "no upstreams",
		}, {
			name:         "found github idp is cached",
			inputSecrets: []runtime.Object{},
			githubIdentityProviders: []runtime.Object{&v1alpha1.GitHubIdentityProvider{
				ObjectMeta: v1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.GitHubIdentityProviderSpec{
					GitHubAPI: v1alpha1.GitHubAPIConfig{
						Host: ptr.To("127.0.0.1"),
						TLS: &v1alpha1.TLSSpec{
							CertificateAuthorityData: "irrelevant",
						},
					},
					Claims: v1alpha1.GitHubClaims{
						Username: ptr.To(v1alpha1.GitHubUsernameID),
						Groups:   ptr.To(v1alpha1.GitHubUseTeamNameForGroupName),
					},
					AllowAuthentication: v1alpha1.GitHubAllowAuthenticationSpec{
						Organizations: v1alpha1.GitHubOrganizationsSpec{
							Policy:  ptr.To(v1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
							Allowed: []string{"foo", "bar"},
						},
					},
					Client: v1alpha1.GitHubClientSpec{
						SecretName: "some-secret",
					},
				},
			}},
			wantResultingCache: []*githubtestutil.TestUpstreamGithubIdentityProvider{{
				Name: "test-github-idp-to-flesh-out",
			}},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pinnipedAPIClient := pinnipedfake.NewSimpleClientset(tt.githubIdentityProviders...)
			fakePinnipedClientForInformers := pinnipedfake.NewSimpleClientset(tt.githubIdentityProviders...)
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(fakePinnipedClientForInformers, 0)

			fakeKubeClient := kubernetesfake.NewSimpleClientset(tt.inputSecrets...)
			kubeInformers := k8sinformers.NewSharedInformerFactoryWithOptions(fakeKubeClient, 0)

			cache := dynamicupstreamprovider.NewDynamicUpstreamIDPProvider()
			cache.SetGitHubIdentityProviders([]upstreamprovider.UpstreamGithubIdentityProviderI{
				&upstreamgithub.ProviderConfig{Name: "initial-entry-to-remove"},
			})

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			controller := New(
				cache,
				pinnipedAPIClient,
				pinnipedInformers.IDP().V1alpha1().GitHubIdentityProviders(),
				kubeInformers.Core().V1().Secrets(),
				logger,
				controllerlib.WithInformer,
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			pinnipedInformers.Start(ctx.Done())
			kubeInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: controllerlib.Key{}}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			actualIDPList := cache.GetGitHubIdentityProviders()
			require.Equal(t, len(tt.wantResultingCache), len(actualIDPList))
		})
	}
}
