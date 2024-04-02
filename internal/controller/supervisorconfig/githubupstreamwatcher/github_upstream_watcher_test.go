// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package githubupstreamwatcher

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	k8sinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/federationdomain/dynamicupstreamprovider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil/oidctestutil"
)

func TestController(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                    string
		githubIdentityProviders []runtime.Object
		inputSecrets            []runtime.Object
		configClient            func(*pinnipedfake.Clientset)
		wantErr                 string
		wantLogs                []string
		wantResultingCache      []*oidctestutil.TestUpstreamOIDCIdentityProvider
		wantResultingUpstreams  []v1alpha1.GitHubIdentityProvider
	}{
		{
			name: "The controller runs.... and should be further tested.",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dynamicUpstreamProvider := dynamicupstreamprovider.NewDynamicUpstreamIDPProvider()
			pinnipedAPIClient := pinnipedfake.NewSimpleClientset(tt.githubIdentityProviders...)
			fakePinnipedClientForInformers := pinnipedfake.NewSimpleClientset(tt.githubIdentityProviders...)
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(fakePinnipedClientForInformers, 0)

			fakeKubeClient := kubernetesfake.NewSimpleClientset(tt.inputSecrets...)
			kubeInformers := k8sinformers.NewSharedInformerFactoryWithOptions(fakeKubeClient, 0)

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			controller := New(
				dynamicUpstreamProvider,
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
		})
	}
}
