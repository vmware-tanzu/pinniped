// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	v1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	k8sinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"

	conciergev1alpha "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	identityv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/identity/v1alpha1"
	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
	pinnipedconciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	"go.pinniped.dev/internal/concierge/impersonator"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/test/library"
)

// syncBuffer wraps bytes.Buffer with a mutex so we don't have races in our test code.
type syncBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (sb *syncBuffer) String() string {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.String()
}

func (sb *syncBuffer) Read(b []byte) (int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Read(b)
}

func (sb *syncBuffer) Write(b []byte) (int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Write(b)
}

// Note that this test supports being run on all of our integration test cluster types:
// - TKGS acceptance (long-running) cluster: auto mode will choose disabled, supports LBs, does not have squid.
// - GKE acceptance (long-running) cluster: auto will choose enabled, support LBs, does not have squid.
// - kind: auto mode will choose disabled, does not support LBs, has squid.
// - GKE ephemeral clusters: auto mode will choose enabled, supports LBs, has squid.
// - AKS ephemeral clusters: auto mode will choose enabled, supports LBs, has squid.
// - EKS ephemeral clusters: auto mode will choose enabled, supports LBs, has squid.
func TestImpersonationProxy(t *testing.T) { //nolint:gocyclo // yeah, it's complex.
	env := library.IntegrationEnv(t)

	impersonatorShouldHaveStartedAutomaticallyByDefault := !env.HasCapability(library.ClusterSigningKeyIsAvailable)
	clusterSupportsLoadBalancers := env.HasCapability(library.HasExternalLoadBalancerProvider)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	// Create a client using the admin kubeconfig.
	adminClient := library.NewKubernetesClientset(t)
	adminConciergeClient := library.NewConciergeClientset(t)

	// Create a WebhookAuthenticator and prepare a TokenCredentialRequestSpec using the authenticator for use later.
	credentialRequestSpecWithWorkingCredentials := loginv1alpha1.TokenCredentialRequestSpec{
		Token:         env.TestUser.Token,
		Authenticator: library.CreateTestWebhookAuthenticator(ctx, t),
	}

	// The address of the ClusterIP service that points at the impersonation proxy's port (used when there is no load balancer).
	proxyServiceEndpoint := fmt.Sprintf("%s-proxy.%s.svc.cluster.local", env.ConciergeAppName, env.ConciergeNamespace)

	newImpersonationProxyClientWithCredentials := func(credentials *loginv1alpha1.ClusterCredential, impersonationProxyURL string, impersonationProxyCACertPEM []byte, doubleImpersonateUser string) *kubeclient.Client {
		kubeconfig := impersonationProxyRestConfig(credentials, impersonationProxyURL, impersonationProxyCACertPEM, doubleImpersonateUser)
		if !clusterSupportsLoadBalancers {
			// Only if there is no possibility to send traffic through a load balancer, then send the traffic through the Squid proxy.
			// Prefer to go through a load balancer because that's how the impersonator is intended to be used in the real world.
			kubeconfig.Proxy = kubeconfigProxyFunc(t, env.Proxy)
		}
		return library.NewKubeclient(t, kubeconfig)
	}

	newAnonymousImpersonationProxyClient := func(impersonationProxyURL string, impersonationProxyCACertPEM []byte, doubleImpersonateUser string) *kubeclient.Client {
		emptyCredentials := &loginv1alpha1.ClusterCredential{}
		return newImpersonationProxyClientWithCredentials(emptyCredentials, impersonationProxyURL, impersonationProxyCACertPEM, doubleImpersonateUser)
	}

	var mostRecentTokenCredentialRequestResponse *loginv1alpha1.TokenCredentialRequest
	refreshCredential := func(t *testing.T, impersonationProxyURL string, impersonationProxyCACertPEM []byte) *loginv1alpha1.ClusterCredential {
		if mostRecentTokenCredentialRequestResponse == nil || credentialAlmostExpired(t, mostRecentTokenCredentialRequestResponse) {
			var err error
			// Make a TokenCredentialRequest. This can either return a cert signed by the Kube API server's CA (e.g. on kind)
			// or a cert signed by the impersonator's signing CA (e.g. on GKE). Either should be accepted by the impersonation
			// proxy server as a valid authentication.
			//
			// However, we issue short-lived certs, so this cert will only be valid for a few minutes.
			// Cache it until it is almost expired and then refresh it whenever it is close to expired.
			//
			// Also, use an anonymous client which goes through the impersonation proxy to make the request because that's
			// what would normally happen when a user is using a kubeconfig where the server is the impersonation proxy,
			// so it more closely simulates the normal use case, and also because we want this to work on AKS clusters
			// which do not allow anonymous requests.
			client := newAnonymousImpersonationProxyClient(impersonationProxyURL, impersonationProxyCACertPEM, "").PinnipedConcierge
			require.Eventually(t, func() bool {
				mostRecentTokenCredentialRequestResponse, err = createTokenCredentialRequest(credentialRequestSpecWithWorkingCredentials, client)
				if err != nil {
					t.Logf("failed to make TokenCredentialRequest: %s", library.Sdump(err))
					return false
				}
				return true
			}, 5*time.Minute, 5*time.Second)

			require.Nil(t, mostRecentTokenCredentialRequestResponse.Status.Message,
				"expected no error message but got: %s", library.Sdump(mostRecentTokenCredentialRequestResponse.Status.Message))
			require.NotEmpty(t, mostRecentTokenCredentialRequestResponse.Status.Credential.ClientCertificateData)
			require.NotEmpty(t, mostRecentTokenCredentialRequestResponse.Status.Credential.ClientKeyData)

			// At the moment the credential request should not have returned a token. In the future, if we make it return
			// tokens, we should revisit this test's rest config below.
			require.Empty(t, mostRecentTokenCredentialRequestResponse.Status.Credential.Token)
		}
		return mostRecentTokenCredentialRequestResponse.Status.Credential
	}

	impersonationProxyViaSquidKubeClientWithoutCredential := func() kubernetes.Interface {
		proxyURL := "https://" + proxyServiceEndpoint
		kubeconfig := impersonationProxyRestConfig(&loginv1alpha1.ClusterCredential{}, proxyURL, nil, "")
		kubeconfig.Proxy = kubeconfigProxyFunc(t, env.Proxy)
		return library.NewKubeclient(t, kubeconfig).Kubernetes
	}

	newImpersonationProxyClient := func(t *testing.T, impersonationProxyURL string, impersonationProxyCACertPEM []byte, doubleImpersonateUser string) *kubeclient.Client {
		refreshedCredentials := refreshCredential(t, impersonationProxyURL, impersonationProxyCACertPEM).DeepCopy()
		refreshedCredentials.Token = "not a valid token" // demonstrates that client certs take precedence over tokens by setting both on the requests
		return newImpersonationProxyClientWithCredentials(refreshedCredentials, impersonationProxyURL, impersonationProxyCACertPEM, doubleImpersonateUser)
	}

	oldConfigMap, err := adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Get(ctx, impersonationProxyConfigMapName(env), metav1.GetOptions{})
	if !k8serrors.IsNotFound(err) {
		require.NoError(t, err) // other errors aside from NotFound are unexpected
		t.Logf("stashing a pre-existing configmap %s", oldConfigMap.Name)
		require.NoError(t, adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Delete(ctx, impersonationProxyConfigMapName(env), metav1.DeleteOptions{}))
	}
	// At the end of the test, clean up the ConfigMap.
	t.Cleanup(func() {
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		// Delete any version that was created by this test.
		t.Logf("cleaning up configmap at end of test %s", impersonationProxyConfigMapName(env))
		err := adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Delete(ctx, impersonationProxyConfigMapName(env), metav1.DeleteOptions{})
		if !k8serrors.IsNotFound(err) {
			require.NoError(t, err) // only not found errors are acceptable
		}

		// Only recreate it if it already existed at the start of this test.
		if len(oldConfigMap.Data) != 0 {
			t.Log(oldConfigMap)
			oldConfigMap.UID = "" // cant have a UID yet
			oldConfigMap.ResourceVersion = ""
			t.Logf("restoring a pre-existing configmap %s", oldConfigMap.Name)
			_, err = adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Create(ctx, oldConfigMap, metav1.CreateOptions{})
			require.NoError(t, err)
		}

		// If we are running on an environment that has a load balancer, expect that the
		// CredentialIssuer will be updated eventually with a successful impersonation proxy frontend.
		// We do this to ensure that future tests that use the impersonation proxy (e.g.,
		// TestE2EFullIntegration) will start with a known-good state.
		if clusterSupportsLoadBalancers {
			performImpersonatorDiscovery(ctx, t, env, adminConciergeClient)
		}
	})

	// Done with set-up and ready to get started with the test. There are several states that we could be in at
	// this point depending on the capabilities of the cluster under test. We handle each possible case here.
	switch {
	case impersonatorShouldHaveStartedAutomaticallyByDefault && clusterSupportsLoadBalancers:
		// Auto mode should have decided that the impersonator will run and should have started a load balancer,
		// and we will be able to use the load balancer to access the impersonator. (e.g. GKE, AKS, EKS)
		// Check that load balancer has been automatically created by the impersonator's "auto" mode.
		library.RequireEventuallyWithoutError(t, func() (bool, error) {
			return hasImpersonationProxyLoadBalancerService(ctx, env, adminClient)
		}, 30*time.Second, 500*time.Millisecond)

	case impersonatorShouldHaveStartedAutomaticallyByDefault && !clusterSupportsLoadBalancers:
		t.Fatal("None of the clusters types that we currently test against should automatically" +
			"enable the impersonation proxy without also supporting load balancers. If we add such a" +
			"cluster type in the future then we should enhance this test.")

	case !impersonatorShouldHaveStartedAutomaticallyByDefault && clusterSupportsLoadBalancers:
		// Auto mode should have decided that the impersonator will be disabled. We need to manually enable it.
		// The cluster supports load balancers so we should enable it and let the impersonator create a load balancer
		// automatically. (e.g. TKGS)
		// The CredentialIssuer's strategies array should have been updated to include an unsuccessful impersonation
		// strategy saying that it was automatically disabled.
		requireDisabledStrategy(ctx, t, env, adminConciergeClient)

		// Create configuration to make the impersonation proxy turn on with no endpoint (i.e. automatically create a load balancer).
		configMap := impersonationProxyConfigMapForConfig(t, env, impersonator.Config{Mode: impersonator.ModeEnabled})
		t.Logf("creating configmap %s", configMap.Name)
		_, err = adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Create(ctx, &configMap, metav1.CreateOptions{})
		require.NoError(t, err)

	default:
		// Auto mode should have decided that the impersonator will be disabled. We need to manually enable it.
		// However, the cluster does not support load balancers so we should enable it without a load balancer
		// and use squid to make requests. (e.g. kind)
		if env.Proxy == "" {
			t.Skip("test cluster does not support load balancers but also doesn't have a squid proxy... " +
				"this is not a supported configuration for test clusters")
		}

		// Check that no load balancer has been created by the impersonator's "auto" mode.
		library.RequireNeverWithoutError(t, func() (bool, error) {
			return hasImpersonationProxyLoadBalancerService(ctx, env, adminClient)
		}, 10*time.Second, 500*time.Millisecond)

		// Check that we can't use the impersonation proxy to execute kubectl commands yet.
		_, err = impersonationProxyViaSquidKubeClientWithoutCredential().CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		isErr, message := isServiceUnavailableViaSquidError(err, proxyServiceEndpoint)
		require.Truef(t, isErr, "wanted error %q to be service unavailable via squid error, but: %s", err, message)

		// Create configuration to make the impersonation proxy turn on with a hard coded endpoint (without a load balancer).
		configMap := impersonationProxyConfigMapForConfig(t, env, impersonator.Config{
			Mode:     impersonator.ModeEnabled,
			Endpoint: proxyServiceEndpoint,
		})
		t.Logf("creating configmap %s", configMap.Name)
		_, err = adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Create(ctx, &configMap, metav1.CreateOptions{})
		require.NoError(t, err)
	}

	// At this point the impersonator should be starting/running. When it is ready, the CredentialIssuer's
	// strategies array should be updated to include a successful impersonation strategy which can be used
	// to discover the impersonator's URL and CA certificate. Until it has finished starting, it may not be included
	// in the strategies array or it may be included in an error state. It can be in an error state for
	// awhile when it is waiting for the load balancer to be assigned an ip/hostname.
	impersonationProxyURL, impersonationProxyCACertPEM := performImpersonatorDiscovery(ctx, t, env, adminConciergeClient)
	if !clusterSupportsLoadBalancers {
		// In this case, we specified the endpoint in the configmap, so check that it was reported correctly in the CredentialIssuer.
		require.Equal(t, "https://"+proxyServiceEndpoint, impersonationProxyURL)
	}

	// Because our credentials expire so quickly, we'll always use a new client, to give us a chance to refresh our
	// credentials before they expire. Create a closure to capture the arguments to newImpersonationProxyClient
	// so we don't have to keep repeating them.
	// This client performs TLS checks, so it also provides test coverage that the impersonation proxy server is generating TLS certs correctly.
	impersonationProxyKubeClient := func(t *testing.T) kubernetes.Interface {
		return newImpersonationProxyClient(t, impersonationProxyURL, impersonationProxyCACertPEM, "").Kubernetes
	}

	t.Run("positive tests", func(t *testing.T) {
		// Create an RBAC rule to allow this user to read/write everything.
		library.CreateTestClusterRoleBinding(t,
			rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: env.TestUser.ExpectedUsername},
			rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "edit"},
		)
		// Wait for the above RBAC rule to take effect.
		library.WaitForUserToHaveAccess(t, env.TestUser.ExpectedUsername, []string{}, &v1.ResourceAttributes{
			Verb: "get", Group: "", Version: "v1", Resource: "namespaces",
		})

		// Get pods in concierge namespace and pick one.
		// this is for tests that require performing actions against a running pod. We use the concierge pod because we already have it handy.
		// We want to make sure it's a concierge pod (not cert agent), because we need to be able to "exec echo" and port-forward a running port.
		pods, err := adminClient.CoreV1().Pods(env.ConciergeNamespace).List(ctx, metav1.ListOptions{})
		require.NoError(t, err)
		require.Greater(t, len(pods.Items), 0)
		var conciergePod *corev1.Pod
		for _, pod := range pods.Items {
			pod := pod
			if !strings.Contains(pod.Name, "kube-cert-agent") {
				conciergePod = &pod
			}
		}
		require.NotNil(t, conciergePod, "could not find a concierge pod")

		// Test that the user can perform basic actions through the client with their username and group membership
		// influencing RBAC checks correctly.
		t.Run(
			"access as user",
			library.AccessAsUserTest(ctx, env.TestUser.ExpectedUsername, impersonationProxyKubeClient(t)),
		)
		for _, group := range env.TestUser.ExpectedGroups {
			group := group
			t.Run(
				"access as group "+group,
				library.AccessAsGroupTest(ctx, group, impersonationProxyKubeClient(t)),
			)
		}

		t.Run("kubectl port-forward and keeping the connection open for over a minute (non-idle)", func(t *testing.T) {
			kubeconfigPath, envVarsWithProxy, _ := getImpersonationKubeconfig(t, env, impersonationProxyURL, impersonationProxyCACertPEM, credentialRequestSpecWithWorkingCredentials.Authenticator)

			// Run the kubectl port-forward command.
			timeout, cancelFunc := context.WithTimeout(ctx, 2*time.Minute)
			defer cancelFunc()
			portForwardCmd, _, portForwardStderr := kubectlCommand(timeout, t, kubeconfigPath, envVarsWithProxy, "port-forward", "--namespace", env.ConciergeNamespace, conciergePod.Name, "8443:8443")
			portForwardCmd.Env = envVarsWithProxy

			// Start, but don't wait for the command to finish.
			err := portForwardCmd.Start()
			require.NoError(t, err, `"kubectl port-forward" failed`)
			go func() {
				assert.EqualErrorf(t, portForwardCmd.Wait(), "signal: killed", `wanted "kubectl port-forward" to get signaled because context was cancelled (stderr: %q)`, portForwardStderr.String())
			}()

			// The server should recognize this this
			// is going to be a long-running command and keep the connection open as long as the client stays connected.

			// curl the endpoint as many times as we can within 70 seconds.
			// this will ensure that we don't run into idle timeouts.
			var curlStdOut, curlStdErr bytes.Buffer
			timeout, cancelFunc = context.WithTimeout(ctx, 75*time.Second)
			defer cancelFunc()
			startTime := time.Now()
			for time.Now().Before(startTime.Add(70 * time.Second)) {
				curlCmd := exec.CommandContext(timeout, "curl", "-k", "-sS", "https://127.0.0.1:8443") // -sS turns off the progressbar but still prints errors
				curlCmd.Stdout = &curlStdOut
				curlCmd.Stderr = &curlStdErr
				curlErr := curlCmd.Run()
				if curlErr != nil {
					t.Log("curl error: " + curlErr.Error())
					t.Log("curlStdErr: " + curlStdErr.String())
					t.Log("stdout: " + curlStdOut.String())
				}
				t.Log("time: ", time.Now())
				time.Sleep(1 * time.Second)
			}

			// curl the endpoint once more, once 70 seconds has elapsed, to make sure the connection is still open.
			timeout, cancelFunc = context.WithTimeout(ctx, 30*time.Second)
			defer cancelFunc()
			curlCmd := exec.CommandContext(timeout, "curl", "-k", "-sS", "https://127.0.0.1:8443") // -sS turns off the progressbar but still prints errors
			curlCmd.Stdout = &curlStdOut
			curlCmd.Stderr = &curlStdErr
			curlErr := curlCmd.Run()

			if curlErr != nil {
				t.Log("curl error: " + curlErr.Error())
				t.Log("curlStdErr: " + curlStdErr.String())
				t.Log("stdout: " + curlStdOut.String())
			}
			// We expect this to 403, but all we care is that it gets through.
			require.NoError(t, curlErr)
			require.Contains(t, curlStdOut.String(), "\"forbidden: User \\\"system:anonymous\\\" cannot get path \\\"/\\\"\"")
		})

		t.Run("kubectl port-forward and keeping the connection open for over a minute (idle)", func(t *testing.T) {
			kubeconfigPath, envVarsWithProxy, _ := getImpersonationKubeconfig(t, env, impersonationProxyURL, impersonationProxyCACertPEM, credentialRequestSpecWithWorkingCredentials.Authenticator)

			// Run the kubectl port-forward command.
			timeout, cancelFunc := context.WithTimeout(ctx, 2*time.Minute)
			defer cancelFunc()
			portForwardCmd, _, portForwardStderr := kubectlCommand(timeout, t, kubeconfigPath, envVarsWithProxy, "port-forward", "--namespace", env.ConciergeNamespace, conciergePod.Name, "8443:8443")
			portForwardCmd.Env = envVarsWithProxy

			// Start, but don't wait for the command to finish.
			err := portForwardCmd.Start()
			require.NoError(t, err, `"kubectl port-forward" failed`)
			go func() {
				assert.EqualErrorf(t, portForwardCmd.Wait(), "signal: killed", `wanted "kubectl port-forward" to get signaled because context was cancelled (stderr: %q)`, portForwardStderr.String())
			}()

			// Wait to see if we time out. The default timeout is 60 seconds, but the server should recognize this this
			// is going to be a long-running command and keep the connection open as long as the client stays connected.
			time.Sleep(70 * time.Second)

			timeout, cancelFunc = context.WithTimeout(ctx, 2*time.Minute)
			defer cancelFunc()
			curlCmd := exec.CommandContext(timeout, "curl", "-k", "-sS", "https://127.0.0.1:8443") // -sS turns off the progressbar but still prints errors
			var curlStdOut, curlStdErr bytes.Buffer
			curlCmd.Stdout = &curlStdOut
			curlCmd.Stderr = &curlStdErr
			err = curlCmd.Run()
			if err != nil {
				t.Log("curl error: " + err.Error())
				t.Log("curlStdErr: " + curlStdErr.String())
				t.Log("stdout: " + curlStdOut.String())
			}
			// We expect this to 403, but all we care is that it gets through.
			require.NoError(t, err)
			require.Contains(t, curlStdOut.String(), "\"forbidden: User \\\"system:anonymous\\\" cannot get path \\\"/\\\"\"")
		})

		t.Run("using and watching all the basic verbs", func(t *testing.T) {
			// Create a namespace, because it will be easier to exercise "deletecollection" if we have a namespace.
			namespaceName := createTestNamespace(t, adminClient)

			// Create and start informer to exercise the "watch" verb for us.
			informerFactory := k8sinformers.NewSharedInformerFactoryWithOptions(
				impersonationProxyKubeClient(t),
				0,
				k8sinformers.WithNamespace(namespaceName))
			informer := informerFactory.Core().V1().ConfigMaps()
			informer.Informer() // makes sure that the informer will cache
			stopChannel := make(chan struct{})
			informerFactory.Start(stopChannel)
			t.Cleanup(func() {
				// Shut down the informer.
				close(stopChannel)
			})
			informerFactory.WaitForCacheSync(ctx.Done())

			// Use labels on our created ConfigMaps to avoid accidentally listing other ConfigMaps that might
			// exist in the namespace. In Kube 1.20+ there is a default ConfigMap in every namespace.
			configMapLabels := labels.Set{
				"pinniped.dev/testConfigMap": library.RandHex(t, 8),
			}

			// Test "create" verb through the impersonation proxy.
			_, err := impersonationProxyKubeClient(t).CoreV1().ConfigMaps(namespaceName).Create(ctx,
				&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "configmap-1", Labels: configMapLabels}},
				metav1.CreateOptions{},
			)
			require.NoError(t, err)
			_, err = impersonationProxyKubeClient(t).CoreV1().ConfigMaps(namespaceName).Create(ctx,
				&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "configmap-2", Labels: configMapLabels}},
				metav1.CreateOptions{},
			)
			require.NoError(t, err)
			_, err = impersonationProxyKubeClient(t).CoreV1().ConfigMaps(namespaceName).Create(ctx,
				&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "configmap-3", Labels: configMapLabels}},
				metav1.CreateOptions{},
			)
			require.NoError(t, err)

			// Make sure that all of the created ConfigMaps show up in the informer's cache to
			// demonstrate that the informer's "watch" verb is working through the impersonation proxy.
			require.Eventually(t, func() bool {
				_, err1 := informer.Lister().ConfigMaps(namespaceName).Get("configmap-1")
				_, err2 := informer.Lister().ConfigMaps(namespaceName).Get("configmap-2")
				_, err3 := informer.Lister().ConfigMaps(namespaceName).Get("configmap-3")
				return err1 == nil && err2 == nil && err3 == nil
			}, 10*time.Second, 50*time.Millisecond)

			// Test "get" verb through the impersonation proxy.
			configMap3, err := impersonationProxyKubeClient(t).CoreV1().ConfigMaps(namespaceName).Get(ctx, "configmap-3", metav1.GetOptions{})
			require.NoError(t, err)

			// Test "list" verb through the impersonation proxy.
			listResult, err := impersonationProxyKubeClient(t).CoreV1().ConfigMaps(namespaceName).List(ctx, metav1.ListOptions{
				LabelSelector: configMapLabels.String(),
			})
			require.NoError(t, err)
			require.Len(t, listResult.Items, 3)

			// Test "update" verb through the impersonation proxy.
			configMap3.Data = map[string]string{"foo": "bar"}
			updateResult, err := impersonationProxyKubeClient(t).CoreV1().ConfigMaps(namespaceName).Update(ctx, configMap3, metav1.UpdateOptions{})
			require.NoError(t, err)
			require.Equal(t, "bar", updateResult.Data["foo"])

			// Make sure that the updated ConfigMap shows up in the informer's cache.
			require.Eventually(t, func() bool {
				configMap, err := informer.Lister().ConfigMaps(namespaceName).Get("configmap-3")
				return err == nil && configMap.Data["foo"] == "bar"
			}, 10*time.Second, 50*time.Millisecond)

			// Test "patch" verb through the impersonation proxy.
			patchResult, err := impersonationProxyKubeClient(t).CoreV1().ConfigMaps(namespaceName).Patch(ctx,
				"configmap-3",
				types.MergePatchType,
				[]byte(`{"data":{"baz":"42"}}`),
				metav1.PatchOptions{},
			)
			require.NoError(t, err)
			require.Equal(t, "bar", patchResult.Data["foo"])
			require.Equal(t, "42", patchResult.Data["baz"])

			// Make sure that the patched ConfigMap shows up in the informer's cache.
			require.Eventually(t, func() bool {
				configMap, err := informer.Lister().ConfigMaps(namespaceName).Get("configmap-3")
				return err == nil && configMap.Data["foo"] == "bar" && configMap.Data["baz"] == "42"
			}, 10*time.Second, 50*time.Millisecond)

			// Test "delete" verb through the impersonation proxy.
			err = impersonationProxyKubeClient(t).CoreV1().ConfigMaps(namespaceName).Delete(ctx, "configmap-3", metav1.DeleteOptions{})
			require.NoError(t, err)

			// Make sure that the deleted ConfigMap shows up in the informer's cache.
			require.Eventually(t, func() bool {
				_, getErr := informer.Lister().ConfigMaps(namespaceName).Get("configmap-3")
				list, listErr := informer.Lister().ConfigMaps(namespaceName).List(configMapLabels.AsSelector())
				return k8serrors.IsNotFound(getErr) && listErr == nil && len(list) == 2
			}, 10*time.Second, 50*time.Millisecond)

			// Test "deletecollection" verb through the impersonation proxy.
			err = impersonationProxyKubeClient(t).CoreV1().ConfigMaps(namespaceName).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
			require.NoError(t, err)

			// Make sure that the deleted ConfigMaps shows up in the informer's cache.
			require.Eventually(t, func() bool {
				list, listErr := informer.Lister().ConfigMaps(namespaceName).List(configMapLabels.AsSelector())
				return listErr == nil && len(list) == 0
			}, 10*time.Second, 50*time.Millisecond)

			// There should be no ConfigMaps left.
			listResult, err = impersonationProxyKubeClient(t).CoreV1().ConfigMaps(namespaceName).List(ctx, metav1.ListOptions{
				LabelSelector: configMapLabels.String(),
			})
			require.NoError(t, err)
			require.Len(t, listResult.Items, 0)
		})

		t.Run("double impersonation as a regular user is blocked", func(t *testing.T) {
			// Make a client which will send requests through the impersonation proxy and will also add
			// impersonate headers to the request.
			doubleImpersonationKubeClient := newImpersonationProxyClient(t, impersonationProxyURL, impersonationProxyCACertPEM, "other-user-to-impersonate").Kubernetes

			// Check that we can get some resource through the impersonation proxy without any impersonation headers on the request.
			// We could use any resource for this, but we happen to know that this one should exist.
			_, err := impersonationProxyKubeClient(t).CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName(env), metav1.GetOptions{})
			require.NoError(t, err)

			// Now we'll see what happens when we add an impersonation header to the request. This should generate a
			// request similar to the one above, except that it will also have an impersonation header.
			_, err = doubleImpersonationKubeClient.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName(env), metav1.GetOptions{})
			// Double impersonation is not supported yet, so we should get an error.
			require.EqualError(t, err, fmt.Sprintf(
				`users "other-user-to-impersonate" is forbidden: `+
					`User "%s" cannot impersonate resource "users" in API group "" at the cluster scope: `+
					`impersonation is not allowed or invalid verb`,
				env.TestUser.ExpectedUsername))
		})

		// This is a separate test from the above double impersonation test because the cluster admin user gets special
		// authorization treatment from the Kube API server code that we are using, and we want to ensure that we are blocking
		// double impersonation even for the cluster admin.
		t.Run("double impersonation as a cluster admin user is blocked", func(t *testing.T) {
			// Copy the admin credentials from the admin kubeconfig.
			adminClientRestConfig := library.NewClientConfig(t)

			if adminClientRestConfig.BearerToken == "" && adminClientRestConfig.CertData == nil && adminClientRestConfig.KeyData == nil {
				t.Skip("The admin kubeconfig does not include credentials, so skipping this test.")
			}

			clusterAdminCredentials := &loginv1alpha1.ClusterCredential{
				Token:                 adminClientRestConfig.BearerToken,
				ClientCertificateData: string(adminClientRestConfig.CertData),
				ClientKeyData:         string(adminClientRestConfig.KeyData),
			}

			// Make a client using the admin credentials which will send requests through the impersonation proxy
			// and will also add impersonate headers to the request.
			doubleImpersonationKubeClient := newImpersonationProxyClientWithCredentials(
				clusterAdminCredentials, impersonationProxyURL, impersonationProxyCACertPEM, "other-user-to-impersonate",
			).Kubernetes

			_, err := doubleImpersonationKubeClient.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName(env), metav1.GetOptions{})
			// Double impersonation is not supported yet, so we should get an error.
			require.Error(t, err)
			require.Regexp(t,
				`users "other-user-to-impersonate" is forbidden: `+
					`User ".*" cannot impersonate resource "users" in API group "" at the cluster scope: `+
					`impersonation is not allowed or invalid verb`,
				err.Error(),
			)
		})

		t.Run("WhoAmIRequests and different kinds of authentication through the impersonation proxy", func(t *testing.T) {
			// Test using the TokenCredentialRequest for authentication.
			impersonationProxyPinnipedConciergeClient := newImpersonationProxyClient(t,
				impersonationProxyURL, impersonationProxyCACertPEM, "",
			).PinnipedConcierge
			whoAmI, err := impersonationProxyPinnipedConciergeClient.IdentityV1alpha1().WhoAmIRequests().
				Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
			require.NoError(t, err)
			require.Equal(t,
				expectedWhoAmIRequestResponse(
					env.TestUser.ExpectedUsername,
					append(env.TestUser.ExpectedGroups, "system:authenticated"),
				),
				whoAmI,
			)

			// Test an unauthenticated request which does not include any credentials.
			impersonationProxyAnonymousPinnipedConciergeClient := newAnonymousImpersonationProxyClient(
				impersonationProxyURL, impersonationProxyCACertPEM, "",
			).PinnipedConcierge
			whoAmI, err = impersonationProxyAnonymousPinnipedConciergeClient.IdentityV1alpha1().WhoAmIRequests().
				Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
			require.NoError(t, err)
			require.Equal(t,
				expectedWhoAmIRequestResponse(
					"system:anonymous",
					[]string{"system:unauthenticated"},
				),
				whoAmI,
			)

			// Test using a service account token. Authenticating as Service Accounts through the impersonation
			// proxy is not supported, so it should fail.
			namespaceName := createTestNamespace(t, adminClient)
			impersonationProxyServiceAccountPinnipedConciergeClient := newImpersonationProxyClientWithCredentials(
				&loginv1alpha1.ClusterCredential{Token: createServiceAccountToken(ctx, t, adminClient, namespaceName)},
				impersonationProxyURL, impersonationProxyCACertPEM, "").PinnipedConcierge
			_, err = impersonationProxyServiceAccountPinnipedConciergeClient.IdentityV1alpha1().WhoAmIRequests().
				Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
			require.EqualError(t, err, "Internal error occurred: unimplemented functionality - unable to act as current user")
			require.True(t, k8serrors.IsInternalError(err), err)
			require.Equal(t, &k8serrors.StatusError{
				ErrStatus: metav1.Status{
					Status: metav1.StatusFailure,
					Code:   http.StatusInternalServerError,
					Reason: metav1.StatusReasonInternalError,
					Details: &metav1.StatusDetails{
						Causes: []metav1.StatusCause{
							{
								Message: "unimplemented functionality - unable to act as current user",
							},
						},
					},
					Message: "Internal error occurred: unimplemented functionality - unable to act as current user",
				},
			}, err)
		})

		t.Run("kubectl as a client", func(t *testing.T) {
			kubeconfigPath, envVarsWithProxy, tempDir := getImpersonationKubeconfig(t, env, impersonationProxyURL, impersonationProxyCACertPEM, credentialRequestSpecWithWorkingCredentials.Authenticator)

			// Try "kubectl exec" through the impersonation proxy.
			echoString := "hello world"
			remoteEchoFile := fmt.Sprintf("/tmp/test-impersonation-proxy-echo-file-%d.txt", time.Now().Unix())
			stdout, err := runKubectl(t, kubeconfigPath, envVarsWithProxy, "exec", "--namespace", env.ConciergeNamespace, conciergePod.Name, "--", "bash", "-c", fmt.Sprintf(`echo "%s" | tee %s`, echoString, remoteEchoFile))
			require.NoError(t, err, `"kubectl exec" failed`)
			require.Equal(t, echoString+"\n", stdout)

			// run the kubectl cp command
			localEchoFile := filepath.Join(tempDir, filepath.Base(remoteEchoFile))
			_, err = runKubectl(t, kubeconfigPath, envVarsWithProxy, "cp", fmt.Sprintf("%s/%s:%s", env.ConciergeNamespace, conciergePod.Name, remoteEchoFile), localEchoFile)
			require.NoError(t, err, `"kubectl cp" failed`)
			localEchoFileData, err := ioutil.ReadFile(localEchoFile)
			require.NoError(t, err)
			require.Equal(t, echoString+"\n", string(localEchoFileData))
			defer func() {
				_, _ = runKubectl(t, kubeconfigPath, envVarsWithProxy, "exec", "--namespace", env.ConciergeNamespace, conciergePod.Name, "--", "rm", remoteEchoFile) // cleanup remote echo file
			}()

			// run the kubectl logs command
			logLinesCount := 10
			stdout, err = runKubectl(t, kubeconfigPath, envVarsWithProxy, "logs", "--namespace", env.ConciergeNamespace, conciergePod.Name, fmt.Sprintf("--tail=%d", logLinesCount))
			require.NoError(t, err, `"kubectl logs" failed`)
			if strings.Contains(stdout, "healthz") {
				// there might be an extra line if healthz was called at the same time
				require.Equalf(t, logLinesCount+1, strings.Count(stdout, "\n"), "wanted %d newlines in kubectl logs output:\n%s", logLinesCount+1, stdout)
			} else {
				require.Equalf(t, logLinesCount, strings.Count(stdout, "\n"), "wanted %d newlines in kubectl logs output:\n%s", logLinesCount, stdout)
			}

			// run the kubectl attach command
			namespaceName := createTestNamespace(t, adminClient)
			attachPod := library.CreatePod(ctx, t, "impersonation-proxy-attach", namespaceName, corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:    "impersonation-proxy-attach",
						Image:   conciergePod.Spec.Containers[0].Image,
						Command: []string{"bash"},
						Args:    []string{"-c", `while true; do read VAR; echo "VAR: $VAR"; done`},
						Stdin:   true,
					},
				},
			})
			timeout, cancelFunc := context.WithTimeout(ctx, 2*time.Minute)
			defer cancelFunc()
			attachCmd, attachStdout, attachStderr := kubectlCommand(timeout, t, kubeconfigPath, envVarsWithProxy, "attach", "--stdin=true", "--namespace", namespaceName, attachPod.Name, "-v=10")
			attachCmd.Env = envVarsWithProxy
			attachStdin, err := attachCmd.StdinPipe()
			require.NoError(t, err)

			// start but don't wait for the attach command
			err = attachCmd.Start()
			require.NoError(t, err)
			attachExitCh := make(chan struct{})
			go func() {
				assert.NoError(t, attachCmd.Wait())
				close(attachExitCh)
			}()

			// write to stdin on the attach process
			_, err = attachStdin.Write([]byte(echoString + "\n"))
			require.NoError(t, err)

			// see that we can read stdout and it spits out stdin output back to us
			wantAttachStdout := fmt.Sprintf("VAR: %s\n", echoString)
			require.Eventuallyf(t, func() bool { return attachStdout.String() == wantAttachStdout }, time.Second*60, time.Millisecond*250, `got "kubectl attach" stdout: %q, wanted: %q (stderr: %q)`, attachStdout.String(), wantAttachStdout, attachStderr.String())

			// close stdin and attach process should exit
			err = attachStdin.Close()
			require.NoError(t, err)
			requireClose(t, attachExitCh, time.Second*20)
		})

		t.Run("websocket client", func(t *testing.T) {
			namespaceName := createTestNamespace(t, adminClient)

			impersonationRestConfig := impersonationProxyRestConfig(
				refreshCredential(t, impersonationProxyURL, impersonationProxyCACertPEM),
				impersonationProxyURL, impersonationProxyCACertPEM, "",
			)
			tlsConfig, err := rest.TLSConfigFor(impersonationRestConfig)
			require.NoError(t, err)

			wantConfigMapLabelKey, wantConfigMapLabelValue := "some-label-key", "some-label-value"
			dest, _ := url.Parse(impersonationProxyURL)
			dest.Scheme = "wss"
			dest.Path = "/api/v1/namespaces/" + namespaceName + "/configmaps"
			dest.RawQuery = url.Values{
				"watch":           {"1"},
				"labelSelector":   {fmt.Sprintf("%s=%s", wantConfigMapLabelKey, wantConfigMapLabelValue)},
				"resourceVersion": {"0"},
			}.Encode()
			dialer := websocket.Dialer{
				TLSClientConfig: tlsConfig,
			}
			if !clusterSupportsLoadBalancers {
				dialer.Proxy = func(req *http.Request) (*url.URL, error) {
					proxyURL, err := url.Parse(env.Proxy)
					require.NoError(t, err)
					t.Logf("passing request for %s through proxy %s", req.URL, proxyURL.String())
					return proxyURL, nil
				}
			}
			c, r, err := dialer.Dial(dest.String(), http.Header{"Origin": {dest.String()}})
			if r != nil {
				defer func() {
					require.NoError(t, r.Body.Close())
				}()
			}
			if err != nil && r != nil {
				body, _ := ioutil.ReadAll(r.Body)
				t.Logf("websocket dial failed: %d:%s", r.StatusCode, body)
			}
			require.NoError(t, err)

			// perform a create through the admin client
			wantConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap-1", Labels: map[string]string{wantConfigMapLabelKey: wantConfigMapLabelValue}},
			}
			wantConfigMap, err = adminClient.CoreV1().ConfigMaps(namespaceName).Create(ctx,
				wantConfigMap,
				metav1.CreateOptions{},
			)
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, adminClient.CoreV1().ConfigMaps(namespaceName).
					DeleteCollection(context.Background(), metav1.DeleteOptions{}, metav1.ListOptions{}))
			})

			// see if the websocket client received an event for the create
			_, message, err := c.ReadMessage()
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			var got watchJSON
			err = json.Unmarshal(message, &got)
			require.NoError(t, err)
			if got.Type != watch.Added {
				t.Errorf("Unexpected type: %v", got.Type)
			}
			var actualConfigMap corev1.ConfigMap
			require.NoError(t, json.Unmarshal(got.Object, &actualConfigMap))
			actualConfigMap.TypeMeta = metav1.TypeMeta{} // This isn't filled out in the wantConfigMap we got back from create.
			require.Equal(t, *wantConfigMap, actualConfigMap)
		})

		t.Run("http2 client", func(t *testing.T) {
			namespaceName := createTestNamespace(t, adminClient)

			wantConfigMapLabelKey, wantConfigMapLabelValue := "some-label-key", "some-label-value"
			wantConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap-1", Labels: map[string]string{wantConfigMapLabelKey: wantConfigMapLabelValue}},
			}
			wantConfigMap, err = adminClient.CoreV1().ConfigMaps(namespaceName).Create(ctx,
				wantConfigMap,
				metav1.CreateOptions{},
			)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = adminClient.CoreV1().ConfigMaps(namespaceName).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
			})

			// create rest client
			restConfig := impersonationProxyRestConfig(
				refreshCredential(t, impersonationProxyURL, impersonationProxyCACertPEM),
				impersonationProxyURL, impersonationProxyCACertPEM, "",
			)

			tlsConfig, err := rest.TLSConfigFor(restConfig)
			require.NoError(t, err)
			httpTransport := http.Transport{
				TLSClientConfig: tlsConfig,
			}
			if !clusterSupportsLoadBalancers {
				httpTransport.Proxy = func(req *http.Request) (*url.URL, error) {
					proxyURL, err := url.Parse(env.Proxy)
					require.NoError(t, err)
					t.Logf("passing request for %s through proxy %s", req.URL, proxyURL.String())
					return proxyURL, nil
				}
			}
			err = http2.ConfigureTransport(&httpTransport)
			require.NoError(t, err)

			httpClient := http.Client{
				Transport: &httpTransport,
			}

			dest, _ := url.Parse(impersonationProxyURL)
			dest.Path = "/api/v1/namespaces/" + namespaceName + "/configmaps/configmap-1"
			getConfigmapRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, dest.String(), nil)
			require.NoError(t, err)
			response, err := httpClient.Do(getConfigmapRequest)
			require.NoError(t, err)
			body, _ := ioutil.ReadAll(response.Body)
			t.Logf("http2 status code: %d, proto: %s, message: %s", response.StatusCode, response.Proto, body)
			require.Equal(t, "HTTP/2.0", response.Proto)
			require.Equal(t, http.StatusOK, response.StatusCode)
			defer func() {
				require.NoError(t, response.Body.Close())
			}()
			var actualConfigMap corev1.ConfigMap
			require.NoError(t, json.Unmarshal(body, &actualConfigMap))
			actualConfigMap.TypeMeta = metav1.TypeMeta{} // This isn't filled out in the wantConfigMap we got back from create.
			require.Equal(t, *wantConfigMap, actualConfigMap)

			// watch configmaps
			dest.Path = "/api/v1/namespaces/" + namespaceName + "/configmaps"
			dest.RawQuery = url.Values{
				"watch":           {"1"},
				"labelSelector":   {fmt.Sprintf("%s=%s", wantConfigMapLabelKey, wantConfigMapLabelValue)},
				"resourceVersion": {"0"},
			}.Encode()
			watchConfigmapsRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, dest.String(), nil)
			require.NoError(t, err)
			response, err = httpClient.Do(watchConfigmapsRequest)
			require.NoError(t, err)
			require.Equal(t, "HTTP/2.0", response.Proto)
			require.Equal(t, http.StatusOK, response.StatusCode)
			defer func() {
				require.NoError(t, response.Body.Close())
			}()

			// decode
			decoder := json.NewDecoder(response.Body)
			var got watchJSON
			err = decoder.Decode(&got)
			require.NoError(t, err)
			if got.Type != watch.Added {
				t.Errorf("Unexpected type: %v", got.Type)
			}
			err = json.Unmarshal(got.Object, &actualConfigMap)
			require.NoError(t, err)
			require.Equal(t, "configmap-1", actualConfigMap.Name)
			actualConfigMap.TypeMeta = metav1.TypeMeta{} // This isn't filled out in the wantConfigMap we got back from create.
			require.Equal(t, *wantConfigMap, actualConfigMap)
		})
	})

	t.Run("manually disabling the impersonation proxy feature", func(t *testing.T) {
		// Update configuration to force the proxy to disabled mode
		configMap := impersonationProxyConfigMapForConfig(t, env, impersonator.Config{Mode: impersonator.ModeDisabled})
		if clusterSupportsLoadBalancers {
			t.Logf("creating configmap %s", configMap.Name)
			_, err := adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Create(ctx, &configMap, metav1.CreateOptions{})
			require.NoError(t, err)
		} else {
			t.Logf("updating configmap %s", configMap.Name)
			_, err := adminClient.CoreV1().ConfigMaps(env.ConciergeNamespace).Update(ctx, &configMap, metav1.UpdateOptions{})
			require.NoError(t, err)
		}

		if clusterSupportsLoadBalancers {
			// The load balancer should have been deleted when we disabled the impersonation proxy.
			// Note that this can take kind of a long time on real cloud providers (e.g. ~22 seconds on EKS).
			library.RequireEventuallyWithoutError(t, func() (bool, error) {
				hasService, err := hasImpersonationProxyLoadBalancerService(ctx, env, adminClient)
				return !hasService, err
			}, 2*time.Minute, 500*time.Millisecond)
		}

		// Check that the impersonation proxy port has shut down.
		// Ideally we could always check that the impersonation proxy's port has shut down, but on clusters where we
		// do not run the squid proxy we have no easy way to see beyond the load balancer to see inside the cluster,
		// so we'll skip this check on clusters which have load balancers but don't run the squid proxy.
		// The other cluster types that do run the squid proxy will give us sufficient coverage here.
		if env.Proxy != "" {
			require.Eventually(t, func() bool {
				// It's okay if this returns RBAC errors because this user has no role bindings.
				// What we want to see is that the proxy eventually shuts down entirely.
				_, err := impersonationProxyViaSquidKubeClientWithoutCredential().CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
				isErr, _ := isServiceUnavailableViaSquidError(err, proxyServiceEndpoint)
				return isErr
			}, 20*time.Second, 500*time.Millisecond)
		}

		// Check that the generated TLS cert Secret was deleted by the controller because it's supposed to clean this up
		// when we disable the impersonator.
		require.Eventually(t, func() bool {
			_, err := adminClient.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName(env), metav1.GetOptions{})
			return k8serrors.IsNotFound(err)
		}, 10*time.Second, 250*time.Millisecond)

		// Check that the generated CA cert Secret was not deleted by the controller because it's supposed to keep this
		// around in case we decide to later re-enable the impersonator. We want to avoid generating new CA certs when
		// possible because they make their way into kubeconfigs on client machines.
		_, err := adminClient.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyCASecretName(env), metav1.GetOptions{})
		require.NoError(t, err)

		// At this point the impersonator should be stopped. The CredentialIssuer's strategies array should be updated to
		// include an unsuccessful impersonation strategy saying that it was manually configured to be disabled.
		requireDisabledStrategy(ctx, t, env, adminConciergeClient)

		if !env.HasCapability(library.ClusterSigningKeyIsAvailable) && env.HasCapability(library.AnonymousAuthenticationSupported) {
			// This cluster does not support the cluster signing key strategy, so now that we've manually disabled the
			// impersonation strategy, we should be left with no working strategies.
			// Given that there are no working strategies, a TokenCredentialRequest which would otherwise work should now
			// fail, because there is no point handing out credentials that are not going to work for any strategy.
			// Note that library.CreateTokenCredentialRequest makes an unauthenticated request, so we can't meaningfully
			// perform this part of the test on a cluster which does not allow anonymous authentication.
			tokenCredentialRequestResponse, err := library.CreateTokenCredentialRequest(ctx, t, credentialRequestSpecWithWorkingCredentials)
			require.NoError(t, err)

			require.NotNil(t, tokenCredentialRequestResponse.Status.Message, "expected an error message but got nil")
			require.Equal(t, "authentication failed", *tokenCredentialRequestResponse.Status.Message)
			require.Nil(t, tokenCredentialRequestResponse.Status.Credential)
		}
	})
}

func createTestNamespace(t *testing.T, adminClient kubernetes.Interface) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	namespace, err := adminClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "impersonation-integration-test-"},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		t.Logf("cleaning up test namespace %s", namespace.Name)
		require.NoError(t, adminClient.CoreV1().Namespaces().Delete(ctx, namespace.Name, metav1.DeleteOptions{}))
	})
	return namespace.Name
}

func createServiceAccountToken(ctx context.Context, t *testing.T, adminClient kubernetes.Interface, namespaceName string) string {
	t.Helper()

	serviceAccount, err := adminClient.CoreV1().ServiceAccounts(namespaceName).Create(ctx,
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{GenerateName: "int-test-service-account-"}}, metav1.CreateOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, adminClient.CoreV1().ServiceAccounts(namespaceName).
			Delete(context.Background(), serviceAccount.Name, metav1.DeleteOptions{}))
	})

	secret, err := adminClient.CoreV1().Secrets(namespaceName).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "int-test-service-account-token-",
			Annotations: map[string]string{
				corev1.ServiceAccountNameKey: serviceAccount.Name,
			},
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, adminClient.CoreV1().Secrets(namespaceName).
			Delete(context.Background(), secret.Name, metav1.DeleteOptions{}))
	})

	library.RequireEventuallyWithoutError(t, func() (bool, error) {
		secret, err = adminClient.CoreV1().Secrets(namespaceName).Get(ctx, secret.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return len(secret.Data[corev1.ServiceAccountTokenKey]) > 0, nil
	}, time.Minute, time.Second)

	return string(secret.Data[corev1.ServiceAccountTokenKey])
}

func expectedWhoAmIRequestResponse(username string, groups []string) *identityv1alpha1.WhoAmIRequest {
	return &identityv1alpha1.WhoAmIRequest{
		Status: identityv1alpha1.WhoAmIRequestStatus{
			KubernetesUserInfo: identityv1alpha1.KubernetesUserInfo{
				User: identityv1alpha1.UserInfo{
					Username: username,
					UID:      "", // no way to impersonate UID: https://github.com/kubernetes/kubernetes/issues/93699
					Groups:   groups,
					Extra:    nil,
				},
			},
		},
	}
}

func performImpersonatorDiscovery(ctx context.Context, t *testing.T, env *library.TestEnv, adminConciergeClient pinnipedconciergeclientset.Interface) (string, []byte) {
	t.Helper()
	var impersonationProxyURL string
	var impersonationProxyCACertPEM []byte

	t.Log("Waiting for CredentialIssuer strategy to be successful")

	library.RequireEventuallyWithoutError(t, func() (bool, error) {
		credentialIssuer, err := adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Get(ctx, credentialIssuerName(env), metav1.GetOptions{})
		if err != nil || credentialIssuer.Status.Strategies == nil {
			t.Log("Did not find any CredentialIssuer with any strategies")
			return false, nil // didn't find it, but keep trying
		}
		for _, strategy := range credentialIssuer.Status.Strategies {
			// There will be other strategy types in the list, so ignore those.
			if strategy.Type == conciergev1alpha.ImpersonationProxyStrategyType && strategy.Status == conciergev1alpha.SuccessStrategyStatus { //nolint:nestif
				if strategy.Frontend == nil {
					return false, fmt.Errorf("did not find a Frontend") // unexpected, fail the test
				}
				if strategy.Frontend.ImpersonationProxyInfo == nil {
					return false, fmt.Errorf("did not find an ImpersonationProxyInfo") // unexpected, fail the test
				}
				impersonationProxyURL = strategy.Frontend.ImpersonationProxyInfo.Endpoint
				impersonationProxyCACertPEM, err = base64.StdEncoding.DecodeString(strategy.Frontend.ImpersonationProxyInfo.CertificateAuthorityData)
				if err != nil {
					return false, err // unexpected, fail the test
				}
				return true, nil // found it, continue the test!
			} else if strategy.Type == conciergev1alpha.ImpersonationProxyStrategyType {
				t.Logf("Waiting for successful impersonation proxy strategy on %s: found status %s with reason %s and message: %s",
					credentialIssuerName(env), strategy.Status, strategy.Reason, strategy.Message)
				if strategy.Reason == conciergev1alpha.ErrorDuringSetupStrategyReason {
					// The server encountered an unexpected error while starting the impersonator, so fail the test fast.
					return false, fmt.Errorf("found impersonation strategy in %s state with message: %s", strategy.Reason, strategy.Message)
				}
			}
		}
		t.Log("Did not find any impersonation proxy strategy on CredentialIssuer")
		return false, nil // didn't find it, but keep trying
	}, 10*time.Minute, 10*time.Second)

	t.Log("Found successful CredentialIssuer strategy")
	return impersonationProxyURL, impersonationProxyCACertPEM
}

func requireDisabledStrategy(ctx context.Context, t *testing.T, env *library.TestEnv, adminConciergeClient pinnipedconciergeclientset.Interface) {
	t.Helper()

	library.RequireEventuallyWithoutError(t, func() (bool, error) {
		credentialIssuer, err := adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Get(ctx, credentialIssuerName(env), metav1.GetOptions{})
		if err != nil || credentialIssuer.Status.Strategies == nil {
			t.Log("Did not find any CredentialIssuer with any strategies")
			return false, nil // didn't find it, but keep trying
		}
		for _, strategy := range credentialIssuer.Status.Strategies {
			// There will be other strategy types in the list, so ignore those.
			if strategy.Type == conciergev1alpha.ImpersonationProxyStrategyType &&
				strategy.Status == conciergev1alpha.ErrorStrategyStatus &&
				strategy.Reason == conciergev1alpha.DisabledStrategyReason { //nolint:nestif
				return true, nil // found it, continue the test!
			} else if strategy.Type == conciergev1alpha.ImpersonationProxyStrategyType {
				t.Logf("Waiting for disabled impersonation proxy strategy on %s: found status %s with reason %s and message: %s",
					credentialIssuerName(env), strategy.Status, strategy.Reason, strategy.Message)
				if strategy.Reason == conciergev1alpha.ErrorDuringSetupStrategyReason {
					// The server encountered an unexpected error while stopping the impersonator, so fail the test fast.
					return false, fmt.Errorf("found impersonation strategy in %s state with message: %s", strategy.Reason, strategy.Message)
				}
			}
		}
		t.Log("Did not find any impersonation proxy strategy on CredentialIssuer")
		return false, nil // didn't find it, but keep trying
	}, 1*time.Minute, 500*time.Millisecond)
}

func credentialAlmostExpired(t *testing.T, credential *loginv1alpha1.TokenCredentialRequest) bool {
	t.Helper()
	pemBlock, _ := pem.Decode([]byte(credential.Status.Credential.ClientCertificateData))
	parsedCredential, err := x509.ParseCertificate(pemBlock.Bytes)
	require.NoError(t, err)
	timeRemaining := time.Until(parsedCredential.NotAfter)
	if timeRemaining < 2*time.Minute {
		t.Logf("The TokenCredentialRequest cred is almost expired and needs to be refreshed. Expires in %s.", timeRemaining)
		return true
	}
	t.Logf("The TokenCredentialRequest cred is good for some more time (%s) so using it.", timeRemaining)
	return false
}

func impersonationProxyRestConfig(credential *loginv1alpha1.ClusterCredential, host string, caData []byte, doubleImpersonateUser string) *rest.Config {
	config := rest.Config{
		Host: host,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: caData == nil,
			CAData:   caData,
			CertData: []byte(credential.ClientCertificateData),
			KeyData:  []byte(credential.ClientKeyData),
		},
		// kubectl would set both the client cert and the token, so we'll do that too.
		// The Kube API server will ignore the token if the client cert successfully authenticates.
		// Only if the client cert is not present or fails to authenticate will it use the token.
		// Historically, it works that way because some web browsers will always send your
		// corporate-assigned client cert even if it is not valid, and it doesn't want to treat
		// that as a failure if you also sent a perfectly good token.
		// We would like the impersonation proxy to imitate that behavior, so we test it here.
		BearerToken: credential.Token,
	}
	if doubleImpersonateUser != "" {
		config.Impersonate = rest.ImpersonationConfig{UserName: doubleImpersonateUser}
	}
	return &config
}

func kubeconfigProxyFunc(t *testing.T, squidProxyURL string) func(req *http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		t.Helper()
		parsedSquidProxyURL, err := url.Parse(squidProxyURL)
		require.NoError(t, err)
		t.Logf("passing request for %s through proxy %s", req.URL, parsedSquidProxyURL.String())
		return parsedSquidProxyURL, nil
	}
}

func impersonationProxyConfigMapForConfig(t *testing.T, env *library.TestEnv, config impersonator.Config) corev1.ConfigMap {
	t.Helper()
	configString, err := yaml.Marshal(config)
	require.NoError(t, err)
	configMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: impersonationProxyConfigMapName(env),
		},
		Data: map[string]string{
			"config.yaml": string(configString),
		}}
	return configMap
}

func hasImpersonationProxyLoadBalancerService(ctx context.Context, env *library.TestEnv, client kubernetes.Interface) (bool, error) {
	service, err := client.CoreV1().Services(env.ConciergeNamespace).Get(ctx, impersonationProxyLoadBalancerName(env), metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return service.Spec.Type == corev1.ServiceTypeLoadBalancer, nil
}

func impersonationProxyConfigMapName(env *library.TestEnv) string {
	return env.ConciergeAppName + "-impersonation-proxy-config"
}

func impersonationProxyTLSSecretName(env *library.TestEnv) string {
	return env.ConciergeAppName + "-impersonation-proxy-tls-serving-certificate"
}

func impersonationProxyCASecretName(env *library.TestEnv) string {
	return env.ConciergeAppName + "-impersonation-proxy-ca-certificate"
}

func impersonationProxyLoadBalancerName(env *library.TestEnv) string {
	return env.ConciergeAppName + "-impersonation-proxy-load-balancer"
}

func credentialIssuerName(env *library.TestEnv) string {
	return env.ConciergeAppName + "-config"
}

func getImpersonationKubeconfig(t *testing.T, env *library.TestEnv, impersonationProxyURL string, impersonationProxyCACertPEM []byte, authenticator corev1.TypedLocalObjectReference) (string, []string, string) {
	t.Helper()

	pinnipedExe := library.PinnipedCLIPath(t)
	tempDir := testutil.TempDir(t)

	var envVarsWithProxy []string
	if !env.HasCapability(library.HasExternalLoadBalancerProvider) {
		// Only if you don't have a load balancer, use the squid proxy when it's available.
		envVarsWithProxy = append(os.Environ(), env.ProxyEnv()...)
	}

	// Get the kubeconfig.
	getKubeConfigCmd := []string{"get", "kubeconfig",
		"--concierge-api-group-suffix", env.APIGroupSuffix,
		"--oidc-skip-browser",
		"--static-token", env.TestUser.Token,
		"--concierge-authenticator-name", authenticator.Name,
		"--concierge-authenticator-type", "webhook",
		// Force the use of impersonation proxy strategy, but let it auto-discover the endpoint and CA.
		"--concierge-mode", "ImpersonationProxy"}
	t.Log("Running:", pinnipedExe, getKubeConfigCmd)
	kubeconfigYAML, getKubeConfigStderr := runPinnipedCLI(t, envVarsWithProxy, pinnipedExe, getKubeConfigCmd...)
	// "pinniped get kubectl" prints some status messages to stderr
	t.Log(getKubeConfigStderr)
	// Make sure that the "pinniped get kubeconfig" auto-discovered the impersonation proxy and we're going to
	// make our kubectl requests through the impersonation proxy. Avoid using require.Contains because the error
	// message would contain credentials.
	require.True(t,
		strings.Contains(kubeconfigYAML, "server: "+impersonationProxyURL+"\n"),
		"the generated kubeconfig did not include the expected impersonation server address: %s",
		impersonationProxyURL,
	)
	require.True(t,
		strings.Contains(kubeconfigYAML, "- --concierge-ca-bundle-data="+base64.StdEncoding.EncodeToString(impersonationProxyCACertPEM)+"\n"),
		"the generated kubeconfig did not include the base64 encoded version of this expected impersonation CA cert: %s",
		impersonationProxyCACertPEM,
	)

	// Write the kubeconfig to a temp file.
	kubeconfigPath := filepath.Join(tempDir, "kubeconfig.yaml")
	require.NoError(t, ioutil.WriteFile(kubeconfigPath, []byte(kubeconfigYAML), 0600))

	return kubeconfigPath, envVarsWithProxy, tempDir
}

// func to create kubectl commands with a kubeconfig.
func kubectlCommand(timeout context.Context, t *testing.T, kubeconfigPath string, envVarsWithProxy []string, args ...string) (*exec.Cmd, *syncBuffer, *syncBuffer) {
	allArgs := append([]string{"--kubeconfig", kubeconfigPath}, args...)
	//nolint:gosec // we are not performing malicious argument injection against ourselves
	kubectlCmd := exec.CommandContext(timeout, "kubectl", allArgs...)
	var stdout, stderr syncBuffer
	kubectlCmd.Stdout = &stdout
	kubectlCmd.Stderr = &stderr
	kubectlCmd.Env = envVarsWithProxy

	t.Log("starting kubectl subprocess: kubectl", strings.Join(allArgs, " "))
	return kubectlCmd, &stdout, &stderr
}

// Func to run kubeconfig commands.
func runKubectl(t *testing.T, kubeconfigPath string, envVarsWithProxy []string, args ...string) (string, error) {
	timeout, cancelFunc := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelFunc()

	kubectlCmd, stdout, stderr := kubectlCommand(timeout, t, kubeconfigPath, envVarsWithProxy, args...)

	err := kubectlCmd.Run()
	t.Logf("kubectl stdout output: %s", stdout.String())
	t.Logf("kubectl stderr output: %s", stderr.String())
	return stdout.String(), err
}

// watchJSON defines the expected JSON wire equivalent of watch.Event.
type watchJSON struct {
	Type   watch.EventType `json:"type,omitempty"`
	Object json.RawMessage `json:"object,omitempty"`
}

// requireServiceUnavailableViaSquidError returns whether the provided err is the error that is
// returned by squid when the impersonation proxy port inside the cluster is not listening.
func isServiceUnavailableViaSquidError(err error, proxyServiceEndpoint string) (bool, string) {
	if err == nil {
		return false, "error is nil"
	}

	for _, wantContains := range []string{
		fmt.Sprintf(`Get "https://%s/api/v1/namespaces"`, proxyServiceEndpoint),
		": Service Unavailable",
	} {
		if !strings.Contains(err.Error(), wantContains) {
			return false, fmt.Sprintf("error does not contain %q", wantContains)
		}
	}

	return true, ""
}

func requireClose(t *testing.T, c chan struct{}, timeout time.Duration) {
	t.Helper()
	timer := time.NewTimer(timeout)
	select {
	case <-c:
		if !timer.Stop() {
			<-timer.C
		}
	case <-timer.C:
		require.FailNow(t, "failed to receive from channel within "+timeout.String())
	}
}

func createTokenCredentialRequest(
	spec loginv1alpha1.TokenCredentialRequestSpec,
	client pinnipedconciergeclientset.Interface,
) (*loginv1alpha1.TokenCredentialRequest, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return client.LoginV1alpha1().TokenCredentialRequests().Create(ctx,
		&loginv1alpha1.TokenCredentialRequest{Spec: spec}, metav1.CreateOptions{},
	)
}
