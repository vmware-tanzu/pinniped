// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/tls"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"go.pinniped.dev/internal/config/concierge"
	"go.pinniped.dev/internal/config/supervisor"
	"go.pinniped.dev/test/testlib"
)

type stringEditorFunc func(t *testing.T, in string) string

func performLimitedCiphersTest(
	t *testing.T,
	allowedCiphersConfig []string,
	expectedConfigForSupervisorOIDCEndpoints *tls.Config,
	expectedConfigForAggregatedAPIEndpoints *tls.Config,
) {
	env := testEnvForPodShutdownTests(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	editSupervisorAllowedCiphersConfig := func(t *testing.T, configMapData string) string {
		t.Helper()

		var config supervisor.Config
		err := yaml.Unmarshal([]byte(configMapData), &config)
		require.NoError(t, err)

		require.Empty(t, config.TLS.OneDotTwo.AllowedCiphers) // precondition

		config.TLS.OneDotTwo.AllowedCiphers = allowedCiphersConfig

		updatedConfig, err := yaml.Marshal(config)
		require.NoError(t, err)
		return string(updatedConfig)
	}

	editConciergeAllowedCiphersConfig := func(t *testing.T, configMapData string) string {
		t.Helper()

		var config concierge.Config
		err := yaml.Unmarshal([]byte(configMapData), &config)
		require.NoError(t, err)

		require.Empty(t, config.TLS.OneDotTwo.AllowedCiphers) // precondition

		config.TLS.OneDotTwo.AllowedCiphers = allowedCiphersConfig

		updatedConfig, err := yaml.Marshal(config)
		require.NoError(t, err)
		return string(updatedConfig)
	}

	// Update Supervisor's allowed ciphers in its static configmap and restart pods.
	updateStaticConfigMapAndRestartApp(t,
		ctx,
		env.SupervisorNamespace,
		env.SupervisorAppName+"-static-config",
		env.SupervisorAppName,
		false,
		editSupervisorAllowedCiphersConfig,
	)

	// Update Concierge's allowed ciphers in its static configmap and restart pods.
	updateStaticConfigMapAndRestartApp(t,
		ctx,
		env.ConciergeNamespace,
		env.ConciergeAppName+"-config",
		env.ConciergeAppName,
		true,
		editConciergeAllowedCiphersConfig,
	)

	// Probe TLS config of Supervisor's OIDC endpoints.
	expectTLSConfigForServicePort(t, ctx,
		env.SupervisorAppName+"-nodeport", env.SupervisorNamespace, "10509",
		expectedConfigForSupervisorOIDCEndpoints,
	)

	// Probe TLS config of Supervisor's aggregated endpoints.
	expectTLSConfigForServicePort(t, ctx,
		env.SupervisorAppName+"-api", env.SupervisorNamespace, "10510",
		expectedConfigForAggregatedAPIEndpoints,
	)

	// Probe TLS config of Concierge's aggregated endpoints.
	expectTLSConfigForServicePort(t, ctx,
		env.ConciergeAppName+"-api", env.ConciergeNamespace, "10511",
		expectedConfigForAggregatedAPIEndpoints,
	)
}

func expectTLSConfigForServicePort(
	t *testing.T,
	ctx context.Context,
	serviceName string,
	serviceNamespace string,
	localPortAsStr string,
	expectedConfig *tls.Config,
) {
	portAsInt, err := strconv.Atoi(localPortAsStr)
	require.NoError(t, err)
	portAsUint := uint16(portAsInt) //nolint:gosec // okay to cast because it will only be legal port numbers

	startKubectlPortForward(ctx, t, localPortAsStr, "443", serviceName, serviceNamespace)

	stdout, stderr := testlib.RunNmapSSLEnum(t, "127.0.0.1", portAsUint)
	require.Empty(t, stderr)

	expectedNMapOutput := testlib.GetExpectedCiphers(expectedConfig, "server")
	assert.Contains(t,
		stdout,
		expectedNMapOutput,
		"actual nmap output:\n%s", stdout,
		"but was expected to contain:\n%s", expectedNMapOutput,
	)
}

func updateStaticConfigMapAndRestartApp(
	t *testing.T,
	ctx context.Context,
	namespace string,
	staticConfigMapName string,
	appName string,
	isConcierge bool,
	editConfigMapFunc stringEditorFunc,
) {
	configMapClient := testlib.NewKubernetesClientset(t).CoreV1().ConfigMaps(namespace)

	staticConfigMap, err := configMapClient.Get(ctx, staticConfigMapName, metav1.GetOptions{})
	require.NoError(t, err)

	originalConfig := staticConfigMap.Data["pinniped.yaml"]
	require.NotEmpty(t, originalConfig)

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		staticConfigMapForCleanup, err := configMapClient.Get(cleanupCtx, staticConfigMapName, metav1.GetOptions{})
		require.NoError(t, err)

		staticConfigMapForCleanup.Data = make(map[string]string)
		staticConfigMapForCleanup.Data["pinniped.yaml"] = originalConfig

		_, err = configMapClient.Update(cleanupCtx, staticConfigMapForCleanup, metav1.UpdateOptions{})
		require.NoError(t, err)

		restartAllPodsOfApp(t, namespace, appName, isConcierge)
	})

	staticConfigMap.Data = make(map[string]string)
	staticConfigMap.Data["pinniped.yaml"] = editConfigMapFunc(t, originalConfig)

	_, err = configMapClient.Update(ctx, staticConfigMap, metav1.UpdateOptions{})
	require.NoError(t, err)

	restartAllPodsOfApp(t, namespace, appName, isConcierge)
}

// restartAllPodsOfApp will immediately scale to 0 and then scale back.
func restartAllPodsOfApp(
	t *testing.T,
	namespace string,
	appName string,
	isConcierge bool,
) {
	t.Helper()

	ignorePodsWithNameSubstring := ""
	if isConcierge {
		ignorePodsWithNameSubstring = "-kube-cert-agent-"
	}

	// Precondition: the app should have some pods running initially.
	initialPods := getRunningPodsByNamePrefix(t, namespace, appName+"-", ignorePodsWithNameSubstring)
	require.Greater(t, len(initialPods), 0)

	// Scale down the deployment's number of replicas to 0, which will shut down all the pods.
	originalScale := updateDeploymentScale(t, namespace, appName, 0)
	require.Greater(t, int(originalScale), 0)

	scaleDeploymentBackToOriginalScale := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()
		client := testlib.NewKubernetesClientset(t)

		currentScale, err := client.AppsV1().Deployments(namespace).GetScale(ctx, appName, metav1.GetOptions{})
		require.NoError(t, err)
		if currentScale.Spec.Replicas == originalScale {
			// Already scaled appropriately. No need to change the scale.
			return
		}

		updateDeploymentScale(t, namespace, appName, originalScale)

		// Wait for all the new pods to be running and ready.
		var newPods []corev1.Pod
		testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
			newPods = getRunningPodsByNamePrefix(t, namespace, appName+"-", ignorePodsWithNameSubstring)
			requireEventually.Equal(len(newPods), int(originalScale), "wanted pods to return to original scale")
			requireEventually.True(allPodsReady(newPods), "wanted all new pods to be ready")
		}, 2*time.Minute, 200*time.Millisecond)
	}

	// Even if the test fails due to the below assertions, still try to scale back to original scale,
	// to avoid polluting other tests.
	t.Cleanup(scaleDeploymentBackToOriginalScale)

	// Now that we have adjusted the scale to 0, the pods should go away.
	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		newPods := getRunningPodsByNamePrefix(t, namespace, appName+"-", ignorePodsWithNameSubstring)
		requireEventually.Len(newPods, 0, "wanted zero pods")
	}, 2*time.Minute, 200*time.Millisecond)

	// Scale back to original scale immediately.
	scaleDeploymentBackToOriginalScale()
}
