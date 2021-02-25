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
	v1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	k8sinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"

	"go.pinniped.dev/internal/concierge/impersonator"
	"go.pinniped.dev/internal/testutil/impersonationtoken"
	"go.pinniped.dev/test/library"
)

const (
	// TODO don't hard code "pinniped-concierge-" in these strings. It should be constructed from the env app name.
	impersonationProxyConfigMapName = "pinniped-concierge-impersonation-proxy-config"
	impersonationProxyTLSSecretName = "pinniped-concierge-impersonation-proxy-tls-serving-certificate" //nolint:gosec // this is not a credential
)

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
	proxyServiceEndpoint := fmt.Sprintf("%s-proxy.%s.svc.cluster.local", env.ConciergeAppName, env.ConciergeNamespace)
	proxyServiceURL := fmt.Sprintf("https://%s", proxyServiceEndpoint)
	t.Logf("making kubeconfig that points to %q", proxyServiceURL)

	getImpersonationProxyClient := func(caData []byte) *kubernetes.Clientset {
		kubeconfig := &rest.Config{
			Host:            proxyServiceURL,
			TLSClientConfig: rest.TLSClientConfig{Insecure: caData == nil, CAData: caData},
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
		return impersonationProxyClient
	}

	oldConfigMap, err := adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Get(ctx, impersonationProxyConfigMapName, metav1.GetOptions{})
	if oldConfigMap.Data != nil {
		t.Logf("stashing a pre-existing configmap %s", oldConfigMap.Name)
		require.NoError(t, adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Delete(ctx, impersonationProxyConfigMapName, metav1.DeleteOptions{}))
	}

	serviceUnavailableError := fmt.Sprintf(`Get "%s/api/v1/namespaces": Service Unavailable`, proxyServiceURL)
	insecureImpersonationProxyClient := getImpersonationProxyClient(nil)

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
		_, err = insecureImpersonationProxyClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		require.EqualError(t, err, serviceUnavailableError)

		// Create configuration to make the impersonation proxy turn on with a hard coded endpoint (without a LoadBalancer)
		configMap := configMapForConfig(t, impersonator.Config{
			Mode:     impersonator.ModeEnabled,
			Endpoint: proxyServiceEndpoint,
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

	// Wait for ca data to be available at the secret location.
	var caSecret *corev1.Secret
	require.Eventually(t,
		func() bool {
			caSecret, err = adminClient.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName, metav1.GetOptions{})
			return caSecret != nil && caSecret.Data["ca.crt"] != nil
		}, 5*time.Minute, 250*time.Millisecond)

	// Create an impersonation proxy client with that ca data.
	impersonationProxyClient := getImpersonationProxyClient(caSecret.Data["ca.crt"])
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

	t.Run("watching all the verbs", func(t *testing.T) {
		// Create a namespace, because it will be easier to deletecollection if we have a namespace.
		// t.Cleanup Delete the namespace.
		namespace, err := adminClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "impersonation-integration-test-"},
		}, metav1.CreateOptions{})
		require.NoError(t, err)
		t.Cleanup(func() {
			t.Logf("cleaning up test namespace %s", namespace.Name)
			err = adminClient.CoreV1().Namespaces().Delete(context.Background(), namespace.Name, metav1.DeleteOptions{})
			require.NoError(t, err)
		})

		// Create an RBAC rule to allow this user to read/write everything.
		library.CreateTestClusterRoleBinding(
			t,
			rbacv1.Subject{
				Kind:     rbacv1.UserKind,
				APIGroup: rbacv1.GroupName,
				Name:     env.TestUser.ExpectedUsername,
			},
			rbacv1.RoleRef{
				Kind:     "ClusterRole",
				APIGroup: rbacv1.GroupName,
				Name:     "cluster-admin",
			},
		)
		library.WaitForUserToHaveAccess(t, env.TestUser.ExpectedUsername, []string{}, &v1.ResourceAttributes{
			Namespace: namespace.Name,
			Verb:      "create",
			Group:     "",
			Version:   "v1",
			Resource:  "configmaps",
		})

		// Create and start informer.
		informerFactory := k8sinformers.NewSharedInformerFactoryWithOptions(
			impersonationProxyClient,
			0,
			k8sinformers.WithNamespace(namespace.Name))
		informer := informerFactory.Core().V1().ConfigMaps()
		informer.Informer() // makes sure that the informer will cache
		stopChannel := make(chan struct{})
		informerFactory.Start(stopChannel)
		t.Cleanup(func() {
			// Shut down the informer.
			close(stopChannel)
		})
		informerFactory.WaitForCacheSync(ctx.Done())

		// Test "create" verb through the impersonation proxy.
		configMapLabels := labels.Set{
			"pinniped.dev/testConfigMap": library.RandHex(t, 8),
		}
		_, err = impersonationProxyClient.CoreV1().ConfigMaps(namespace.Name).Create(ctx,
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "configmap-1", Labels: configMapLabels}},
			metav1.CreateOptions{},
		)
		require.NoError(t, err)
		_, err = impersonationProxyClient.CoreV1().ConfigMaps(namespace.Name).Create(ctx,
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "configmap-2", Labels: configMapLabels}},
			metav1.CreateOptions{},
		)
		require.NoError(t, err)
		_, err = impersonationProxyClient.CoreV1().ConfigMaps(namespace.Name).Create(ctx,
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "configmap-3", Labels: configMapLabels}},
			metav1.CreateOptions{},
		)
		require.NoError(t, err)

		// Make sure that all of the created ConfigMaps show up in the informer's cache to
		// demonstrate that the informer's "watch" verb is working through the impersonation proxy.
		require.Eventually(t, func() bool {
			_, err1 := informer.Lister().ConfigMaps(namespace.Name).Get("configmap-1")
			_, err2 := informer.Lister().ConfigMaps(namespace.Name).Get("configmap-2")
			_, err3 := informer.Lister().ConfigMaps(namespace.Name).Get("configmap-3")
			return err1 == nil && err2 == nil && err3 == nil
		}, 10*time.Second, 50*time.Millisecond)

		// Test "get" verb through the impersonation proxy.
		configMap3, err := impersonationProxyClient.CoreV1().ConfigMaps(namespace.Name).Get(ctx, "configmap-3", metav1.GetOptions{})
		require.NoError(t, err)

		// Test "list" verb through the impersonation proxy.
		listResult, err := impersonationProxyClient.CoreV1().ConfigMaps(namespace.Name).List(ctx, metav1.ListOptions{
			LabelSelector: configMapLabels.String(),
		})
		require.NoError(t, err)
		require.Len(t, listResult.Items, 3)

		// Test "update" verb through the impersonation proxy.
		configMap3.Data = map[string]string{"foo": "bar"}
		updateResult, err := impersonationProxyClient.CoreV1().ConfigMaps(namespace.Name).Update(ctx, configMap3, metav1.UpdateOptions{})
		require.NoError(t, err)
		require.Equal(t, "bar", updateResult.Data["foo"])

		// Make sure that the updated ConfigMap shows up in the informer's cache to
		// demonstrate that the informer's "watch" verb is working through the impersonation proxy.
		require.Eventually(t, func() bool {
			configMap, err := informer.Lister().ConfigMaps(namespace.Name).Get("configmap-3")
			return err == nil && configMap.Data["foo"] == "bar"
		}, 10*time.Second, 50*time.Millisecond)

		// Test "patch" verb through the impersonation proxy.
		patchResult, err := impersonationProxyClient.CoreV1().ConfigMaps(namespace.Name).Patch(ctx,
			"configmap-3",
			types.MergePatchType,
			[]byte(`{"data":{"baz":"42"}}`),
			metav1.PatchOptions{},
		)
		require.NoError(t, err)
		require.Equal(t, "bar", patchResult.Data["foo"])
		require.Equal(t, "42", patchResult.Data["baz"])

		// Make sure that the patched ConfigMap shows up in the informer's cache to
		// demonstrate that the informer's "watch" verb is working through the impersonation proxy.
		require.Eventually(t, func() bool {
			configMap, err := informer.Lister().ConfigMaps(namespace.Name).Get("configmap-3")
			return err == nil && configMap.Data["foo"] == "bar" && configMap.Data["baz"] == "42"
		}, 10*time.Second, 50*time.Millisecond)

		// Test "delete" verb through the impersonation proxy.
		err = impersonationProxyClient.CoreV1().ConfigMaps(namespace.Name).Delete(ctx, "configmap-3", metav1.DeleteOptions{})
		require.NoError(t, err)

		// Make sure that the deleted ConfigMap shows up in the informer's cache to
		// demonstrate that the informer's "watch" verb is working through the impersonation proxy.
		require.Eventually(t, func() bool {
			_, getErr := informer.Lister().ConfigMaps(namespace.Name).Get("configmap-3")
			list, listErr := informer.Lister().ConfigMaps(namespace.Name).List(configMapLabels.AsSelector())
			return k8serrors.IsNotFound(getErr) && listErr == nil && len(list) == 2
		}, 10*time.Second, 50*time.Millisecond)

		// Test "deletecollection" verb through the impersonation proxy.
		err = impersonationProxyClient.CoreV1().ConfigMaps(namespace.Name).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
		require.NoError(t, err)

		// Make sure that the deleted ConfigMaps shows up in the informer's cache to
		// demonstrate that the informer's "watch" verb is working through the impersonation proxy.
		require.Eventually(t, func() bool {
			list, listErr := informer.Lister().ConfigMaps(namespace.Name).List(configMapLabels.AsSelector())
			return listErr == nil && len(list) == 0
		}, 10*time.Second, 50*time.Millisecond)

		listResult, err = impersonationProxyClient.CoreV1().ConfigMaps(namespace.Name).List(ctx, metav1.ListOptions{
			LabelSelector: configMapLabels.String(),
		})
		require.NoError(t, err)
		require.Len(t, listResult.Items, 0)
	})

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

	// Check that the impersonation proxy has shut down
	require.Eventually(t, func() bool {
		// It's okay if this returns RBAC errors because this user has no role bindings.
		// What we want to see is that the proxy eventually shuts down entirely.
		_, err = insecureImpersonationProxyClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		return err.Error() == serviceUnavailableError
	}, 20*time.Second, 500*time.Millisecond)

	if env.HasCapability(library.HasExternalLoadBalancerProvider) {
		// The load balancer should not exist after we disable the impersonation proxy.
		// Note that this can take kind of a long time on real cloud providers (e.g. ~22 seconds on EKS).
		require.Eventually(t, func() bool {
			return !hasLoadBalancerService(ctx, t, adminClient, env.ConciergeNamespace)
		}, time.Minute, 500*time.Millisecond)
	}

	require.Eventually(t, func() bool {
		caSecret, err = adminClient.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName, metav1.GetOptions{})
		return k8serrors.IsNotFound(err)
	}, 10*time.Second, 250*time.Millisecond)
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
