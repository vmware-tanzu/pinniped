// Copyright 2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"go.pinniped.dev/internal/config/concierge"
	"go.pinniped.dev/test/testlib"
)

// TestKubeCertAgentPriorityClassName tests the feature which allows the user to configure
// the priorityClassName for the kube cert agent Deployment's pods. This test is Disruptive because
// it restarts the Concierge to reconfigure this setting, and then restarts it
// again to put back the original configuration.
func TestKubeCertAgentPriorityClassName_Disruptive(t *testing.T) {
	env := testEnvForPodShutdownTests(t)

	// The name of the Concierge static configmap.
	staticConfigMapName := env.ConciergeAppName + "-config"

	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancelFunc)

	kubeClient := testlib.NewKubernetesClientset(t)

	// Get the Concierge's static configmap.
	staticConfigMap, err := kubeClient.CoreV1().ConfigMaps(env.ConciergeNamespace).
		Get(ctx, staticConfigMapName, metav1.GetOptions{})
	require.NoError(t, err)

	// Parse the content of the static configmap and check some preconditions.
	originalConfigYAML := staticConfigMap.Data["pinniped.yaml"]
	require.NotEmpty(t, originalConfigYAML)
	var originalConfig concierge.Config
	err = yaml.Unmarshal([]byte(originalConfigYAML), &originalConfig)
	require.NoError(t, err)

	// Should have a name for the kube cert agent configured.
	require.NotNil(t, originalConfig.KubeCertAgentConfig.NamePrefix)
	require.NotEmpty(t, *originalConfig.KubeCertAgentConfig.NamePrefix)
	// The default value should end with "-".
	require.True(t, strings.HasSuffix(*originalConfig.KubeCertAgentConfig.NamePrefix, "-"))
	kubeCertAgentDeploymentName := strings.TrimSuffix(*originalConfig.KubeCertAgentConfig.NamePrefix, "-")
	require.NotEmpty(t, kubeCertAgentDeploymentName)

	// PriorityClassName configuration should be empty by default.
	require.Empty(t, originalConfig.KubeCertAgentConfig.PriorityClassName)

	// Get the actual kube cert agent deployment.
	originalKubeCertAgentDeployment, err := kubeClient.AppsV1().Deployments(env.ConciergeNamespace).
		Get(ctx, kubeCertAgentDeploymentName, metav1.GetOptions{})
	require.NoError(t, err)
	// Should not have PriorityClassName by default.
	require.Empty(t, originalKubeCertAgentDeployment.Spec.Template.Spec.PriorityClassName)

	// PriorityClass "system-cluster-critical" exists on all Kubernetes clusters by default.
	// See https://kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/#how-to-use-priority-and-preemption.
	newlyConfiguredPriorityClassName := "system-cluster-critical"

	// Schedule this now so it runs after the cleanup scheduled by updateStaticConfigMapAndRestartApp() below.
	t.Cleanup(func() {
		// After some time, the kube cert agent deployment should revert back to its default value
		// of not having any PriorityClassName configured on it.
		t.Log("waiting for kube cert agent deployment to get original (empty) PriorityClassName")
		testlib.RequireEventually(t,
			func(requireEventually *require.Assertions) {
				// The deployment should be updated.
				updatedKubeCertAgentDeployment, err := kubeClient.AppsV1().Deployments(env.ConciergeNamespace).
					Get(ctx, kubeCertAgentDeploymentName, metav1.GetOptions{})
				requireEventually.NoError(err)
				requireEventually.Empty(updatedKubeCertAgentDeployment.Spec.Template.Spec.PriorityClassName)

				// The deployment should have rolled out a new pod which has the original (empty) PriorityClassName.
				newPods := getRunningPodsByNamePrefix(t, env.ConciergeNamespace, kubeCertAgentDeploymentName+"-", "")
				requireEventually.Equal(len(newPods), 1)
				requireEventually.True(allPodsReady(newPods), "wanted new pod to be ready")
				requireEventually.Empty(newPods[0].Spec.PriorityClassName)

				t.Log("observed that kube cert agent deployment and pod both got original (empty) PriorityClassName")
			},
			2*time.Minute,
			250*time.Millisecond,
		)
	})

	t.Log("updating Concierge's static ConfigMap and restarting the pods")
	updateStaticConfigMapAndRestartApp(t,
		ctx,
		env.ConciergeNamespace,
		staticConfigMapName,
		env.ConciergeAppName,
		true,
		func(t *testing.T, configMapData string) string {
			t.Helper()

			var config concierge.Config
			err := yaml.Unmarshal([]byte(configMapData), &config)
			require.NoError(t, err)

			config.KubeCertAgentConfig.PriorityClassName = newlyConfiguredPriorityClassName

			updatedConfig, err := yaml.Marshal(config)
			require.NoError(t, err)
			return string(updatedConfig)
		},
	)

	// After some time, the kube cert agent deployment should have the new PriorityClassName configured on it.
	t.Log("waiting for kube cert agent deployment to get new PriorityClassName")
	testlib.RequireEventually(t,
		func(requireEventually *require.Assertions) {
			// The deployment should be updated.
			updatedKubeCertAgentDeployment, err := kubeClient.AppsV1().Deployments(env.ConciergeNamespace).
				Get(ctx, kubeCertAgentDeploymentName, metav1.GetOptions{})
			requireEventually.NoError(err)
			requireEventually.Equal(newlyConfiguredPriorityClassName, updatedKubeCertAgentDeployment.Spec.Template.Spec.PriorityClassName)

			// The deployment should have rolled out a new pod which has the new PriorityClassName.
			newPods := getRunningPodsByNamePrefix(t, env.ConciergeNamespace, kubeCertAgentDeploymentName+"-", "")
			requireEventually.Equal(len(newPods), 1)
			requireEventually.True(allPodsReady(newPods), "wanted new pod to be ready")
			requireEventually.Equal(newlyConfiguredPriorityClassName, newPods[0].Spec.PriorityClassName)

			t.Log("observed that kube cert agent deployment and pod both got new PriorityClassName")
		},
		// Wait 5 minutes in case the Concierge was just redeployed, in which case it can take time for
		// the controllers to be ready again. This test could theoretically get run as the very first test in the whole suite.
		5*time.Minute,
		250*time.Millisecond,
	)
}
