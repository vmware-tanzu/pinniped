// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"go.pinniped.dev/internal/config/supervisor"
	"go.pinniped.dev/test/testlib"
)

func performLimitedCiphersTest(t *testing.T, allowedCiphers []string, expectedCiphers []uint16) {
	env := testOnKindWithPodShutdown(t)

	client := testlib.NewKubernetesClientset(t)
	configMapClient := client.CoreV1().ConfigMaps(env.SupervisorNamespace)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	staticConfigMapName := env.SupervisorAppName + "-static-config"
	supervisorStaticConfigMap, err := configMapClient.Get(ctx, staticConfigMapName, metav1.GetOptions{})
	require.NoError(t, err)

	originalSupervisorConfig := supervisorStaticConfigMap.Data["pinniped.yaml"]
	require.NotEmpty(t, originalSupervisorConfig)

	t.Cleanup(func() {
		supervisorStaticConfigMapCleanup, err := configMapClient.Get(ctx, staticConfigMapName, metav1.GetOptions{})
		require.NoError(t, err)

		supervisorStaticConfigMapCleanup.Data = make(map[string]string)
		supervisorStaticConfigMapCleanup.Data["pinniped.yaml"] = originalSupervisorConfig

		_, err = configMapClient.Update(ctx, supervisorStaticConfigMapCleanup, metav1.UpdateOptions{})
		require.NoError(t, err)

		// this will cycle all the pods
		restartAllPodsOfApp(t, env.SupervisorNamespace, env.SupervisorAppName, false)
	})

	var config supervisor.Config
	err = yaml.Unmarshal([]byte(originalSupervisorConfig), &config)
	require.NoError(t, err)

	// As a precondition of this test, ensure that the list of allowedCiphers is empty
	require.Empty(t, config.TLS.OneDotTwo.AllowedCiphers)

	config.TLS.OneDotTwo.AllowedCiphers = allowedCiphers

	updatedSupervisorConfig, err := yaml.Marshal(config)
	require.NoError(t, err)

	supervisorStaticConfigMap.Data = make(map[string]string)
	supervisorStaticConfigMap.Data["pinniped.yaml"] = string(updatedSupervisorConfig)

	_, err = configMapClient.Update(ctx, supervisorStaticConfigMap, metav1.UpdateOptions{})
	require.NoError(t, err)

	// this will cycle all the pods
	restartAllPodsOfApp(t, env.SupervisorNamespace, env.SupervisorAppName, false)

	startKubectlPortForward(ctx, t, "10509", "443", env.SupervisorAppName+"-nodeport", env.SupervisorNamespace)
	stdout, stderr := testlib.RunNmapSSLEnum(t, "127.0.0.1", 10509)
	require.Empty(t, stderr)

	expectedCiphersConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   testlib.MaxTLSVersion,
		CipherSuites: expectedCiphers,
	}

	require.Contains(t, stdout, testlib.GetExpectedCiphers(expectedCiphersConfig, "server"), "stdout:\n%s", stdout)

}

// restartAllPodsOfApp will immediately scale to 0 and then scale back.
// There are no uses of t.Cleanup since these actions need to happen immediately.
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

	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		newPods := getRunningPodsByNamePrefix(t, namespace, appName+"-", ignorePodsWithNameSubstring)
		requireEventually.Len(newPods, 0, "wanted zero pods")
	}, 2*time.Minute, 200*time.Millisecond)

	// Reset the application to its original scale.
	updateDeploymentScale(t, namespace, appName, originalScale)

	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		newPods := getRunningPodsByNamePrefix(t, namespace, appName+"-", ignorePodsWithNameSubstring)
		requireEventually.Len(newPods, originalScale, "wanted %d pods", originalScale)
	}, 2*time.Minute, 200*time.Millisecond)
}

// TestRemoveAllowedCiphersFromStaticConfig_Disruptive updates the Supervisor's static configuration to make sure that the allowed ciphers list is empty.
// It will restart the Supervisor pods. Skipped because it's only here for local testing purposes.
func TestRemoveAllowedCiphersFromStaticConfig_Disruptive(t *testing.T) {
	t.Skip()

	env := testOnKindWithPodShutdown(t)

	client := testlib.NewKubernetesClientset(t)
	configMapClient := client.CoreV1().ConfigMaps(env.SupervisorNamespace)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	staticConfigMapName := env.SupervisorAppName + "-static-config"
	supervisorStaticConfigMap, err := configMapClient.Get(ctx, staticConfigMapName, metav1.GetOptions{})
	require.NoError(t, err)

	originalSupervisorConfig := supervisorStaticConfigMap.Data["pinniped.yaml"]
	require.NotEmpty(t, originalSupervisorConfig)

	var config supervisor.Config
	err = yaml.Unmarshal([]byte(originalSupervisorConfig), &config)
	require.NoError(t, err)

	config.TLS.OneDotTwo.AllowedCiphers = nil

	updatedConfigBytes, err := yaml.Marshal(config)
	require.NoError(t, err)

	supervisorStaticConfigMap.Data = make(map[string]string)
	supervisorStaticConfigMap.Data["pinniped.yaml"] = string(updatedConfigBytes)

	_, err = configMapClient.Update(ctx, supervisorStaticConfigMap, metav1.UpdateOptions{})
	require.NoError(t, err)

	// this will cycle all the pods
	restartAllPodsOfApp(t, env.SupervisorNamespace, env.SupervisorAppName, false)
}
