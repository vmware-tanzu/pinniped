// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	"go.pinniped.dev/test/library"
)

func TestCredentialIssuerConfig(t *testing.T) {
	library.SkipUnlessIntegration(t)
	namespaceName := library.GetEnv(t, "PINNIPED_NAMESPACE")

	config := library.NewClientConfig(t)
	client := library.NewPinnipedClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("test successful CredentialIssuerConfig", func(t *testing.T) {
		actualConfigList, err := client.
			ConfigV1alpha1().
			CredentialIssuerConfigs(namespaceName).
			List(ctx, metav1.ListOptions{})
		require.NoError(t, err)

		require.Len(t, actualConfigList.Items, 1)

		actualStatusKubeConfigInfo := actualConfigList.Items[0].Status.KubeConfigInfo

		// Verify the cluster strategy status based on what's expected of the test cluster's ability to share signing keys.
		actualStatusStrategies := actualConfigList.Items[0].Status.Strategies
		require.Len(t, actualStatusStrategies, 1)
		actualStatusStrategy := actualStatusStrategies[0]
		require.Equal(t, configv1alpha1.KubeClusterSigningCertificateStrategyType, actualStatusStrategy.Type)

		if library.ClusterHasCapability(t, library.ClusterSigningKeyIsAvailable) {
			require.Equal(t, configv1alpha1.SuccessStrategyStatus, actualStatusStrategy.Status)
			require.Equal(t, configv1alpha1.FetchedKeyStrategyReason, actualStatusStrategy.Reason)
			require.Equal(t, "Key was fetched successfully", actualStatusStrategy.Message)
			// Verify the published kube config info.
			require.Equal(
				t,
				&configv1alpha1.CredentialIssuerConfigKubeConfigInfo{
					Server:                   config.Host,
					CertificateAuthorityData: base64.StdEncoding.EncodeToString(config.TLSClientConfig.CAData),
				},
				actualStatusKubeConfigInfo,
			)
		} else {
			require.Equal(t, configv1alpha1.ErrorStrategyStatus, actualStatusStrategy.Status)
			require.Equal(t, configv1alpha1.CouldNotFetchKeyStrategyReason, actualStatusStrategy.Reason)
			require.Contains(t, actualStatusStrategy.Message, "did not find kube-controller-manager pod")
			// For now, don't verify the kube config info because its not available on GKE. We'll need to address
			// this somehow once we starting supporting those cluster types.
			// Require `nil` to remind us to address this later for other types of clusters where it is available.
			require.Nil(t, actualStatusKubeConfigInfo)
		}

		require.WithinDuration(t, time.Now(), actualStatusStrategy.LastUpdateTime.Local(), 10*time.Minute)
	})
}
