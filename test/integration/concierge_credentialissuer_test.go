// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
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

	conciergeconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	"go.pinniped.dev/test/testlib"
)

func TestCredentialIssuer(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	config := testlib.NewClientConfig(t)
	client := testlib.NewConciergeClientset(t)
	aggregatedClientset := testlib.NewAggregatedClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	t.Run("test successful CredentialIssuer", func(t *testing.T) {
		actualConfigList, err := client.
			ConfigV1alpha1().
			CredentialIssuers().
			List(ctx, metav1.ListOptions{})
		require.NoError(t, err)

		require.Len(t, actualConfigList.Items, 1)

		actualConfig := actualConfigList.Items[0]

		for k, v := range env.ConciergeCustomLabels {
			require.Equalf(t, v, actualConfig.Labels[k], "expected ci to have label `%s: %s`", k, v)
		}
		require.Equal(t, env.ConciergeAppName, actualConfig.Labels["app"])

		apiService, err := aggregatedClientset.ApiregistrationV1().APIServices().Get(ctx, "v1alpha1.login.concierge."+env.APIGroupSuffix, metav1.GetOptions{})
		require.NoError(t, err)

		// work around stupid behavior of WithoutVersionDecoder.Decode
		apiService.APIVersion, apiService.Kind = apiregistrationv1.SchemeGroupVersion.WithKind("APIService").ToAPIVersionAndKind()

		// Verify the cluster strategy status based on what's expected of the test cluster's ability to share signing keys.
		actualStatusStrategies := actualConfigList.Items[0].Status.Strategies

		// There should be two. One of type KubeClusterSigningCertificate and one of type ImpersonationProxy.
		require.Len(t, actualStatusStrategies, 2)

		// The details of the ImpersonationProxy type is tested by a different integration test for the impersonator.
		// Grab the KubeClusterSigningCertificate result so we can check it in detail below.
		var actualStatusStrategy conciergeconfigv1alpha1.CredentialIssuerStrategy
		for _, s := range actualStatusStrategies {
			if s.Type == conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType {
				actualStatusStrategy = s
				break
			}
		}
		require.NotNil(t, actualStatusStrategy)

		if env.HasCapability(testlib.ClusterSigningKeyIsAvailable) {
			require.Equal(t, conciergeconfigv1alpha1.SuccessStrategyStatus, actualStatusStrategy.Status)
			require.Equal(t, conciergeconfigv1alpha1.FetchedKeyStrategyReason, actualStatusStrategy.Reason)
			require.Equal(t, "key was fetched successfully", actualStatusStrategy.Message)
			require.NotNil(t, actualStatusStrategy.Frontend)
			require.Equal(t, conciergeconfigv1alpha1.TokenCredentialRequestAPIFrontendType, actualStatusStrategy.Frontend.Type)
			expectedTokenRequestAPIInfo := conciergeconfigv1alpha1.TokenCredentialRequestAPIInfo{
				Server:                   config.Host,
				CertificateAuthorityData: base64.StdEncoding.EncodeToString(config.CAData),
			}
			require.Equal(t, &expectedTokenRequestAPIInfo, actualStatusStrategy.Frontend.TokenCredentialRequestAPIInfo)
		} else {
			require.Equal(t, conciergeconfigv1alpha1.ErrorStrategyStatus, actualStatusStrategy.Status)
			require.Equal(t, conciergeconfigv1alpha1.CouldNotFetchKeyStrategyReason, actualStatusStrategy.Reason)
			require.Contains(t, actualStatusStrategy.Message, "could not find a healthy kube-controller-manager pod (0 candidates): "+
				"note that this error is the expected behavior for some cluster types, including most cloud provider clusters (e.g. GKE, AKS, EKS)")
		}
	})
}
