// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"

	"go.pinniped.dev/internal/concierge/impersonator"
	"go.pinniped.dev/internal/testutil/impersonationtoken"
	"go.pinniped.dev/test/library"
)

// TODO don't hard code "pinniped-concierge-" in this string. It should be constructed from the env app name.
const impersonationProxyConfigMapName = "pinniped-concierge-impersonation-proxy-config"

func TestImpersonationProxy(t *testing.T) {
	env := library.IntegrationEnv(t)
	if env.Proxy == "" {
		t.Skip("this test can only run in environments with the in-cluster proxy right now")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Create a client using the admin kubeconfig.
	adminClient := library.NewKubernetesClientset(t)

	// Create a WebhookAuthenticator.
	authenticator := library.CreateTestWebhookAuthenticator(ctx, t)

	// The address of the ClusterIP service that points at the impersonation proxy's port
	proxyServiceURL := fmt.Sprintf("https://%s-proxy.%s.svc.cluster.local", env.ConciergeAppName, env.ConciergeNamespace)
	t.Logf("making kubeconfig that points to %q", proxyServiceURL)

	kubeconfig := &rest.Config{
		Host:            proxyServiceURL,
		TLSClientConfig: rest.TLSClientConfig{Insecure: true},
		BearerToken:     impersonationtoken.Make(t, env.TestUser.Token, &authenticator, env.APIGroupSuffix),
		Proxy: func(req *http.Request) (*url.URL, error) {
			proxyURL, err := url.Parse(env.Proxy)
			require.NoError(t, err)
			t.Logf("passing request for %s through proxy %s", req.URL, proxyURL.String())
			return proxyURL, nil
		},
	}

	impersonationProxyClient, err := kubernetes.NewForConfig(kubeconfig)
	require.NoError(t, err, "unexpected failure from kubernetes.NewForConfig()")

	oldConfigMap, err := adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Get(ctx, impersonationProxyConfigMapName, metav1.GetOptions{})
	if oldConfigMap.Data != nil {
		t.Logf("stashing a pre-existing configmap %s", oldConfigMap.Name)
		require.NoError(t, adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Delete(ctx, impersonationProxyConfigMapName, metav1.DeleteOptions{}))
	}

	serviceUnavailableError := fmt.Sprintf(`Get "%s/api/v1/namespaces": Service Unavailable`, proxyServiceURL)
	if env.HasCapability(library.HasExternalLoadBalancerProvider) {
		// Check that load balancer has been created
		require.Eventually(t, func() bool {
			return hasLoadBalancerService(ctx, t, adminClient, env.ConciergeNamespace)
		}, 10*time.Second, 500*time.Millisecond)
	} else {
		// Check that no load balancer has been created
		require.Never(t, func() bool {
			return hasLoadBalancerService(ctx, t, adminClient, env.ConciergeNamespace)
		}, 10*time.Second, 500*time.Millisecond)

		// Check that we can't use the impersonation proxy to execute kubectl commands yet
		_, err = impersonationProxyClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		require.EqualError(t, err, serviceUnavailableError)

		// Create configuration to make the impersonation proxy turn on with a hard coded endpoint (without a LoadBalancer)
		configMap := configMapForConfig(t, impersonator.Config{
			Mode:     impersonator.ModeEnabled,
			Endpoint: proxyServiceURL,
			TLS:      nil,
		})
		t.Logf("creating configmap %s", configMap.Name)
		_, err = adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Create(ctx, &configMap, metav1.CreateOptions{})
		require.NoError(t, err)

		t.Cleanup(func() {
			ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			t.Logf("cleaning up configmap at end of test %s", impersonationProxyConfigMapName)
			err = adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Delete(ctx, impersonationProxyConfigMapName, metav1.DeleteOptions{})
			require.NoError(t, err)

			if len(oldConfigMap.Data) != 0 {
				t.Log(oldConfigMap)
				oldConfigMap.UID = "" // cant have a UID yet
				oldConfigMap.ResourceVersion = ""
				t.Logf("restoring a pre-existing configmap %s", oldConfigMap.Name)
				_, err = adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Create(ctx, oldConfigMap, metav1.CreateOptions{})
				require.NoError(t, err)
			}
		})
	}

	t.Run(
		"access as user",
		library.AccessAsUserTest(ctx, env.TestUser.ExpectedUsername, impersonationProxyClient),
	)
	for _, group := range env.TestUser.ExpectedGroups {
		group := group
		t.Run(
			"access as group "+group,
			library.AccessAsGroupTest(ctx, group, impersonationProxyClient),
		)
	}

	// Update configuration to force the proxy to disabled mode
	configMap := configMapForConfig(t, impersonator.Config{Mode: impersonator.ModeDisabled})
	if env.HasCapability(library.HasExternalLoadBalancerProvider) {
		t.Logf("creating configmap %s", configMap.Name)
		_, err = adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Create(ctx, &configMap, metav1.CreateOptions{})
		require.NoError(t, err)
	} else {
		t.Logf("updating configmap %s", configMap.Name)
		_, err = adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Update(ctx, &configMap, metav1.UpdateOptions{})
		require.NoError(t, err)
	}

	// Check that we can't use the impersonation proxy to execute kubectl commands again
	require.Eventually(t, func() bool {
		_, err = impersonationProxyClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		return err.Error() == serviceUnavailableError
	}, 10*time.Second, 500*time.Millisecond)

	if env.HasCapability(library.HasExternalLoadBalancerProvider) {
		// The load balancer should not exist after we disable the impersonation proxy.
		// Note that this can take kind of a long time on real cloud providers (e.g. ~22 seconds on EKS).
		require.Eventually(t, func() bool {
			return !hasLoadBalancerService(ctx, t, adminClient, env.ConciergeNamespace)
		}, time.Minute, 500*time.Millisecond)
	}
}

func configMapForConfig(t *testing.T, config impersonator.Config) corev1.ConfigMap {
	configString, err := yaml.Marshal(config)
	require.NoError(t, err)
	configMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: impersonationProxyConfigMapName,
		},
		Data: map[string]string{
			"config.yaml": string(configString),
		}}
	return configMap
}

func hasLoadBalancerService(ctx context.Context, t *testing.T, client kubernetes.Interface, namespace string) bool {
	t.Helper()

	services, err := client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	for _, service := range services.Items {
		if service.Spec.Type == corev1.ServiceTypeLoadBalancer {
			return true
		}
	}
	return false
}
