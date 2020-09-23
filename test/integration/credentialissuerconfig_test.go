// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

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
			require.Equal(t, expectedStatusKubeConfigInfo(config), actualStatusKubeConfigInfo)
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

	t.Run("reconciling CredentialIssuerConfig", func(t *testing.T) {
		library.SkipUnlessClusterHasCapability(t, library.ClusterSigningKeyIsAvailable)

		existingConfig, err := client.
			ConfigV1alpha1().
			CredentialIssuerConfigs(namespaceName).
			Get(ctx, "pinniped-config", metav1.GetOptions{})
		require.NoError(t, err)
		require.Len(t, existingConfig.Status.Strategies, 1)
		initialStrategy := existingConfig.Status.Strategies[0]

		// Mutate the existing object. Don't delete it because that would mess up its `Status.Strategies` array,
		// since the reconciling controller is not currently responsible for that field.
		updatedServerValue := "https://junk"
		// TODO maybe mutate the kube-info configmap's CA value instead, because that's the object that we care to check that the controller is watching
		existingConfig.Status.KubeConfigInfo.Server = updatedServerValue
		updatedConfig, err := client.
			ConfigV1alpha1().
			CredentialIssuerConfigs(namespaceName).
			Update(ctx, existingConfig, metav1.UpdateOptions{})
		require.NoError(t, err)
		require.Equal(t, updatedServerValue, updatedConfig.Status.KubeConfigInfo.Server)

		// Expect that the object's mutated field is set back to what matches its source of truth by the controller.
		var actualCredentialIssuerConfig *configv1alpha1.CredentialIssuerConfig
		var configChangesServerField = func() bool {
			actualCredentialIssuerConfig, err = client.
				ConfigV1alpha1().
				CredentialIssuerConfigs(namespaceName).
				Get(ctx, "pinniped-config", metav1.GetOptions{})
			return err == nil && actualCredentialIssuerConfig.Status.KubeConfigInfo.Server != updatedServerValue
		}
		assert.Eventually(t, configChangesServerField, 10*time.Second, 100*time.Millisecond)
		require.NoError(t, err) // prints out the error and stops the test in case of failure
		actualStatusKubeConfigInfo := actualCredentialIssuerConfig.Status.KubeConfigInfo
		require.Equal(t, expectedStatusKubeConfigInfo(config), actualStatusKubeConfigInfo)

		// The strategies should not have changed during reconciliation.
		require.Len(t, actualCredentialIssuerConfig.Status.Strategies, 1)
		require.Equal(t, initialStrategy, actualCredentialIssuerConfig.Status.Strategies[0])
	})
}

func expectedStatusKubeConfigInfo(config *rest.Config) *configv1alpha1.CredentialIssuerConfigKubeConfigInfo {
	return &configv1alpha1.CredentialIssuerConfigKubeConfigInfo{
		Server:                   config.Host,
		CertificateAuthorityData: base64.StdEncoding.EncodeToString(config.TLSClientConfig.CAData),
	}
}
