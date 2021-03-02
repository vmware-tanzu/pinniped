// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	"go.pinniped.dev/test/library"
)

func TestCredentialIssuer(t *testing.T) {
	env := library.IntegrationEnv(t)
	config := library.NewClientConfig(t)
	client := library.NewConciergeClientset(t)
	aggregatedClientset := library.NewAggregatedClientset(t)

	library.AssertNoRestartsDuringTest(t, env.ConciergeNamespace, "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("test successful CredentialIssuer", func(t *testing.T) {
		actualConfigList, err := client.
			ConfigV1alpha1().
			CredentialIssuers().
			List(ctx, metav1.ListOptions{})
		require.NoError(t, err)

		require.Len(t, actualConfigList.Items, 1)

		actualConfig := actualConfigList.Items[0]
		actualStatusKubeConfigInfo := actualConfigList.Items[0].Status.KubeConfigInfo

		for k, v := range env.ConciergeCustomLabels {
			require.Equalf(t, v, actualConfig.Labels[k], "expected ci to have label `%s: %s`", k, v)
		}
		require.Equal(t, env.ConciergeAppName, actualConfig.Labels["app"])

		// verify owner ref is set
		require.Len(t, actualConfig.OwnerReferences, 1)

		apiService, err := aggregatedClientset.ApiregistrationV1().APIServices().Get(ctx, "v1alpha1.login.concierge."+env.APIGroupSuffix, metav1.GetOptions{})
		require.NoError(t, err)

		// work around stupid behavior of WithoutVersionDecoder.Decode
		apiService.APIVersion, apiService.Kind = apiregistrationv1.SchemeGroupVersion.WithKind("APIService").ToAPIVersionAndKind()

		ref := metav1.OwnerReference{
			APIVersion: apiService.APIVersion,
			Kind:       apiService.Kind,
			Name:       apiService.Name,
			UID:        apiService.UID,
		}
		require.Equal(t, ref, actualConfig.OwnerReferences[0])

		// Verify the cluster strategy status based on what's expected of the test cluster's ability to share signing keys.
		actualStatusStrategies := actualConfigList.Items[0].Status.Strategies
		require.Len(t, actualStatusStrategies, 1)
		actualStatusStrategy := actualStatusStrategies[0]
		require.Equal(t, configv1alpha1.KubeClusterSigningCertificateStrategyType, actualStatusStrategy.Type)

		if env.HasCapability(library.ClusterSigningKeyIsAvailable) {
			require.Equal(t, configv1alpha1.SuccessStrategyStatus, actualStatusStrategy.Status)
			require.Equal(t, configv1alpha1.FetchedKeyStrategyReason, actualStatusStrategy.Reason)
			require.Equal(t, "Key was fetched successfully", actualStatusStrategy.Message)
			require.NotNil(t, actualStatusStrategy.Frontend)
			require.Equal(t, configv1alpha1.TokenCredentialRequestAPIFrontendType, actualStatusStrategy.Frontend.Type)
			expectedTokenRequestAPIInfo := configv1alpha1.TokenCredentialRequestAPIInfo{
				Server:                   config.Host,
				CertificateAuthorityData: base64.StdEncoding.EncodeToString(config.TLSClientConfig.CAData),
			}
			require.Equal(t, &expectedTokenRequestAPIInfo, actualStatusStrategy.Frontend.TokenCredentialRequestAPIInfo)

			// Verify the published kube config info.
			require.Equal(
				t,
				&configv1alpha1.CredentialIssuerKubeConfigInfo{
					Server:                   expectedTokenRequestAPIInfo.Server,
					CertificateAuthorityData: expectedTokenRequestAPIInfo.CertificateAuthorityData,
				},
				actualStatusKubeConfigInfo,
			)

			// Only validate LastUpdateTime when cluster signing key is available. The last update time
			// will be set every time our controllers resync, but only when there exists controller
			// manager pods (all other pods will be filtered out), hence why this assertion is in this
			// if branch.
			//
			// This behavior is up for debate. We should eventually discuss the contract for this
			// LastUpdateTime field and ensure that the implementation is the same for when the cluster
			// signing key is available and not available.
			require.WithinDuration(t, time.Now(), actualStatusStrategy.LastUpdateTime.Local(), 10*time.Minute)
		} else {
			require.Equal(t, configv1alpha1.ErrorStrategyStatus, actualStatusStrategy.Status)
			require.Equal(t, configv1alpha1.CouldNotFetchKeyStrategyReason, actualStatusStrategy.Reason)
			require.Contains(t, actualStatusStrategy.Message, "did not find kube-controller-manager pod(s)")
			// For now, don't verify the kube config info because its not available on GKE. We'll need to address
			// this somehow once we starting supporting those cluster types.
			// Require `nil` to remind us to address this later for other types of clusters where it is available.
			require.Nil(t, actualStatusKubeConfigInfo)
		}
	})
}
