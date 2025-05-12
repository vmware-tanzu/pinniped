// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured/unstructuredscheme"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	k8sinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/certificate/csr"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	conciergeconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	identityv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/identity/v1alpha1"
	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/httputil/roundtripper"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/test/testlib"
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
	env := testlib.IntegrationEnv(t)

	impersonatorShouldHaveStartedAutomaticallyByDefault := !env.HasCapability(testlib.ClusterSigningKeyIsAvailable)
	clusterSupportsLoadBalancers := env.HasCapability(testlib.HasExternalLoadBalancerProvider)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Create a client using the admin kubeconfig.
	adminClient := testlib.NewKubernetesClientset(t)
	adminConciergeClient := testlib.NewConciergeClientset(t)

	// Create a WebhookAuthenticator and prepare a TokenCredentialRequestSpec using the authenticator for use later.
	credentialRequestSpecWithWorkingCredentials := loginv1alpha1.TokenCredentialRequestSpec{
		Token:         env.TestUser.Token,
		Authenticator: testlib.CreateTestWebhookAuthenticator(ctx, t, &testlib.IntegrationEnv(t).TestWebhook, authenticationv1alpha1.WebhookAuthenticatorPhaseReady),
	}

	// The address of the ClusterIP service that points at the impersonation proxy's port (used when there is no load balancer).
	proxyServiceEndpoint := fmt.Sprintf("%s-proxy.%s.svc.cluster.local", env.ConciergeAppName, env.ConciergeNamespace)

	var (
		mostRecentTokenCredentialRequestResponse     *loginv1alpha1.TokenCredentialRequest
		mostRecentTokenCredentialRequestResponseLock sync.Mutex
	)

	refreshCredentialHelper := func(t *testing.T, client conciergeclientset.Interface) *loginv1alpha1.ClusterCredential {
		t.Helper()

		mostRecentTokenCredentialRequestResponseLock.Lock()
		defer mostRecentTokenCredentialRequestResponseLock.Unlock()
		if mostRecentTokenCredentialRequestResponse == nil || credentialAlmostExpired(t, mostRecentTokenCredentialRequestResponse) {
			// Make a TokenCredentialRequest. This can either return a cert signed by the Kube API server's CA (e.g. on kind)
			// or a cert signed by the impersonator's signing CA (e.g. on GKE). Either should be accepted by the impersonation
			// proxy server as a valid authentication.
			//
			// However, we issue short-lived certs, so this cert will only be valid for a few minutes.
			// Cache it until it is almost expired and then refresh it whenever it is close to expired.
			//
			testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
				resp, err := createTokenCredentialRequest(credentialRequestSpecWithWorkingCredentials, client)
				requireEventually.NoError(err)
				requireEventually.NotNil(resp)
				requireEventually.NotNil(resp.Status)
				requireEventually.NotNil(resp.Status.Credential)
				requireEventually.Nilf(resp.Status.Message, "expected no error message but got: %s", testlib.Sdump(resp.Status.Message))
				requireEventually.NotEmpty(resp.Status.Credential.ClientCertificateData)
				requireEventually.NotEmpty(resp.Status.Credential.ClientKeyData)

				// At the moment the credential request should not have returned a token. In the future, if we make it return
				// tokens, we should revisit this test's rest config below.
				requireEventually.Empty(resp.Status.Credential.Token)

				mostRecentTokenCredentialRequestResponse = resp
			}, 5*time.Minute, 5*time.Second)
		}

		return mostRecentTokenCredentialRequestResponse.Status.Credential
	}

	refreshCredential := func(t *testing.T, impersonationProxyURL string, impersonationProxyCACertPEM []byte) *loginv1alpha1.ClusterCredential {
		// Use an anonymous client which goes through the impersonation proxy to make the request because that's
		// what would normally happen when a user is using a kubeconfig where the server is the impersonation proxy,
		// so it more closely simulates the normal use case, and also because we want this to work on AKS clusters
		// which do not allow anonymous requests.
		client := newAnonymousImpersonationProxyClient(t, impersonationProxyURL, impersonationProxyCACertPEM, nil).PinnipedConcierge
		return refreshCredentialHelper(t, client)
	}

	oldCredentialIssuer, err := adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Get(ctx, credentialIssuerName(env), metav1.GetOptions{})
	require.NoError(t, err)
	// At the end of the test, clean up the CredentialIssuer
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		// Delete any version that was created by this test.
		t.Logf("cleaning up credentialissuer at end of test %s", credentialIssuerName(env))
		err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			newCredentialIssuer, err := adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Get(ctx, credentialIssuerName(env), metav1.GetOptions{})
			if err != nil {
				return err
			}
			oldCredentialIssuer.Spec.DeepCopyInto(&newCredentialIssuer.Spec)
			_, err = adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Update(ctx, newCredentialIssuer, metav1.UpdateOptions{})
			return err
		})
		require.NoError(t, err)

		// If we are running on an environment that has a load balancer, expect that the
		// CredentialIssuer will be updated eventually with a successful impersonation proxy frontend.
		// We do this to ensure that future tests that use the impersonation proxy (e.g.,
		// TestE2EFullIntegration) will start with a known-good state.
		if clusterSupportsLoadBalancers {
			performImpersonatorDiscovery(ctx, t, env, adminClient, adminConciergeClient, refreshCredential)
		}
	})

	// Done with set-up and ready to get started with the test. There are several states that we could be in at
	// this point depending on the capabilities of the cluster under test. We handle each possible case here.
	switch {
	case impersonatorShouldHaveStartedAutomaticallyByDefault && clusterSupportsLoadBalancers:
		// configure the credential issuer spec to have the impersonation proxy in auto mode
		updateCredentialIssuer(ctx, t, env, adminConciergeClient, conciergeconfigv1alpha1.CredentialIssuerSpec{
			ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
				Mode: conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
				Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
					Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeLoadBalancer,
					Annotations: map[string]string{
						"service.beta.kubernetes.io/aws-load-balancer-connection-idle-timeout": "4000",
					},
				},
			},
		})
		// Auto mode should have decided that the impersonator will run and should have started a load balancer,
		// and we will be able to use the load balancer to access the impersonator. (e.g. GKE, AKS, EKS)
		// Check that load balancer has been automatically created by the impersonator's "auto" mode.
		testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
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
		updateCredentialIssuer(ctx, t, env, adminConciergeClient, conciergeconfigv1alpha1.CredentialIssuerSpec{
			ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
				Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
			},
		})

	default:
		// Auto mode should have decided that the impersonator will be disabled. We need to manually enable it.
		// However, the cluster does not support load balancers so we should enable it without a load balancer
		// and use squid to make requests. (e.g. kind)
		if env.Proxy == "" {
			t.Skip("test cluster does not support load balancers but also doesn't have a squid proxy... " +
				"this is not a supported configuration for test clusters")
		}

		// Check that no load balancer has been created by the impersonator's "auto" mode.
		testlib.RequireNeverWithoutError(t, func() (bool, error) {
			return hasImpersonationProxyLoadBalancerService(ctx, env, adminClient)
		}, 10*time.Second, 500*time.Millisecond, "there should not be a service for the impersonation proxy")

		// Check that we can't use the impersonation proxy to execute kubectl commands yet.
		_, err = impersonationProxyViaSquidKubeClientWithoutCredential(t, proxyServiceEndpoint).CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		isErr, message := isServiceUnavailableViaSquidError(err, proxyServiceEndpoint)
		require.Truef(t, isErr, "wanted error %q to be service unavailable via squid error, but: %s", err, message)

		// Create configuration to make the impersonation proxy turn on with a hard coded endpoint (without a load balancer).
		updateCredentialIssuer(ctx, t, env, adminConciergeClient, conciergeconfigv1alpha1.CredentialIssuerSpec{
			ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
				Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
				ExternalEndpoint: proxyServiceEndpoint,
				Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
					Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP,
				},
			},
		})
	}

	// At this point the impersonator should be starting/running. When it is ready, the CredentialIssuer's
	// strategies array should be updated to include a successful impersonation strategy which can be used
	// to discover the impersonator's URL and CA certificate. Until it has finished starting, it may not be included
	// in the strategies array, or it may be included in an error state. It can be in an error state for
	// a while when it is waiting for the load balancer to be assigned an ip/hostname.
	impersonationProxyURL, impersonationProxyCACertPEM := performImpersonatorDiscovery(ctx, t, env, adminClient, adminConciergeClient, refreshCredential)
	if !clusterSupportsLoadBalancers {
		// In this case, we specified the endpoint in the configmap, so check that it was reported correctly in the CredentialIssuer.
		require.Equal(t, "https://"+proxyServiceEndpoint, impersonationProxyURL)
	} else {
		// If the impersonationProxyURL is a hostname, make sure DNS will resolve before we move on.
		ensureDNSResolves(t, impersonationProxyURL)
	}

	// Because our credentials expire so quickly, we'll always use a new client, to give us a chance to refresh our
	// credentials before they expire. Create a closure to capture the arguments to newImpersonationProxyClient
	// so we don't have to keep repeating them.
	// This client performs TLS checks, so it also provides test coverage that the impersonation proxy server is generating TLS certs correctly.
	impersonationProxyKubeClient := func(t *testing.T) kubernetes.Interface {
		return newImpersonationProxyClient(t, impersonationProxyURL, impersonationProxyCACertPEM, nil, refreshCredential).Kubernetes
	}

	t.Run("positive tests", func(t *testing.T) {
		// Create an RBAC rule to allow this user to read/write everything.
		testlib.CreateTestClusterRoleBinding(t,
			rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: env.TestUser.ExpectedUsername},
			rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "edit"},
		)
		// Wait for the above RBAC rule to take effect.
		testlib.WaitForUserToHaveAccess(t, env.TestUser.ExpectedUsername, []string{}, &authorizationv1.ResourceAttributes{
			Verb: "get", Group: "", Version: "v1", Resource: "namespaces",
		})

		// Get pods in supervisor namespace and pick one.
		// this is for tests that require performing actions against a running pod.
		// We use the supervisor pod because we already have it handy and need to port-forward a running port.
		// We avoid using the concierge for this because it requires TLS 1.3 which is not support by older versions of curl.
		supervisorPods, err := adminClient.CoreV1().Pods(env.SupervisorNamespace).List(ctx,
			metav1.ListOptions{LabelSelector: "deployment.pinniped.dev=supervisor"})
		require.NoError(t, err)
		require.NotEmpty(t, supervisorPods.Items, "could not find supervisor pods")
		supervisorPod := supervisorPods.Items[0]

		// Test that the user can perform basic actions through the client with their username and group membership
		// influencing RBAC checks correctly.
		t.Run(
			"access as user",
			testlib.AccessAsUserTest(ctx, env.TestUser.ExpectedUsername, impersonationProxyKubeClient(t)),
		)
		for _, group := range env.TestUser.ExpectedGroups {
			t.Run(
				"access as group "+group,
				testlib.AccessAsGroupTest(ctx, group, impersonationProxyKubeClient(t)),
			)
		}

		if env.KubernetesDistribution == testlib.EKSDistro {
			t.Log("eks: sleeping for 10 minutes to allow DNS propagation")
			time.Sleep(10 * time.Minute)
		}

		t.Run("kubectl port-forward and keeping the connection open for over a minute (non-idle)", func(t *testing.T) {
			parallelIfNotEKS(t)
			kubeconfigPath, envVarsWithProxy, _ := getImpersonationKubeconfig(t, env, impersonationProxyURL, impersonationProxyCACertPEM, credentialRequestSpecWithWorkingCredentials.Authenticator)

			// Run the kubectl port-forward command.
			timeout, cancelFunc := context.WithTimeout(ctx, 2*time.Minute)
			defer cancelFunc()
			portForwardCmd, _, portForwardStderr := kubectlCommand(timeout, t, kubeconfigPath, envVarsWithProxy, "port-forward", "--namespace", supervisorPod.Namespace, supervisorPod.Name, "10443:8443")
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
				curlCmd := exec.CommandContext(timeout, "curl", "-k", "-sS", "https://127.0.0.1:10443/healthz") // -sS turns off the progressbar but still prints errors
				curlCmd.Stdout = &curlStdOut
				curlCmd.Stderr = &curlStdErr
				curlErr := curlCmd.Run()
				if curlErr != nil {
					t.Log("curl error: " + curlErr.Error())
					t.Log("curlStdErr: " + curlStdErr.String())
					t.Log("stdout: " + curlStdOut.String())
				}
				t.Log("Running curl through the kubectl port-forward port for 70 seconds. Elapsed time:", time.Since(startTime))
				time.Sleep(1 * time.Second)
			}

			// curl the endpoint once more, once 70 seconds has elapsed, to make sure the connection is still open.
			timeout, cancelFunc = context.WithTimeout(ctx, 30*time.Second)
			defer cancelFunc()
			curlCmd := exec.CommandContext(timeout, "curl", "-k", "-sS", "https://127.0.0.1:10443/healthz") // -sS turns off the progressbar but still prints errors
			curlCmd.Stdout = &curlStdOut
			curlCmd.Stderr = &curlStdErr
			curlErr := curlCmd.Run()

			if curlErr != nil {
				t.Log("curl error: " + curlErr.Error())
				t.Log("curlStdErr: " + curlStdErr.String())
				t.Log("stdout: " + curlStdOut.String())
			}
			require.NoError(t, curlErr)
			require.Contains(t, curlStdOut.String(), "okokokokok") // a few successful healthz responses
		})

		t.Run("kubectl port-forward and keeping the connection open for over a minute (idle)", func(t *testing.T) {
			parallelIfNotEKS(t)
			kubeconfigPath, envVarsWithProxy, _ := getImpersonationKubeconfig(t, env, impersonationProxyURL, impersonationProxyCACertPEM, credentialRequestSpecWithWorkingCredentials.Authenticator)

			// Run the kubectl port-forward command.
			timeout, cancelFunc := context.WithTimeout(ctx, 2*time.Minute)
			defer cancelFunc()
			portForwardCmd, _, portForwardStderr := kubectlCommand(timeout, t, kubeconfigPath, envVarsWithProxy, "port-forward", "--namespace", supervisorPod.Namespace, supervisorPod.Name, "10444:8443")
			portForwardCmd.Env = envVarsWithProxy

			// Start, but don't wait for the command to finish.
			err := portForwardCmd.Start()
			require.NoError(t, err, `"kubectl port-forward" failed`)
			go func() {
				assert.EqualErrorf(t, portForwardCmd.Wait(), "signal: killed", `wanted "kubectl port-forward" to get signaled because context was cancelled (stderr: %q)`, portForwardStderr.String())
			}()

			// Wait to see if we time out. The default timeout is 60 seconds, but the server should recognize that this
			// is going to be a long-running command and keep the connection open as long as the client stays connected.
			time.Sleep(70 * time.Second)

			timeout, cancelFunc = context.WithTimeout(ctx, 2*time.Minute)
			defer cancelFunc()
			curlCmd := exec.CommandContext(timeout, "curl", "-k", "-sS", "https://127.0.0.1:10444/healthz") // -sS turns off the progressbar but still prints errors
			var curlStdOut, curlStdErr bytes.Buffer
			curlCmd.Stdout = &curlStdOut
			curlCmd.Stderr = &curlStdErr
			err = curlCmd.Run()
			if err != nil {
				t.Log("curl error: " + err.Error())
				t.Log("curlStdErr: " + curlStdErr.String())
				t.Log("stdout: " + curlStdOut.String())
			}
			require.NoError(t, err)
			require.Equal(t, curlStdOut.String(), "ok")
		})

		t.Run("using and watching all the basic verbs", func(t *testing.T) {
			parallelIfNotEKS(t)
			// Create a namespace, because it will be easier to exercise "deletecollection" if we have a namespace.
			namespaceName := testlib.CreateNamespace(ctx, t, "impersonation").Name

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
				"pinniped.dev/testConfigMap": testlib.RandHex(t, 8),
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
			testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
				_, err := informer.Lister().ConfigMaps(namespaceName).Get("configmap-1")
				requireEventually.NoError(err)
				_, err = informer.Lister().ConfigMaps(namespaceName).Get("configmap-2")
				requireEventually.NoError(err)
				_, err = informer.Lister().ConfigMaps(namespaceName).Get("configmap-3")
				requireEventually.NoError(err)
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
			testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
				configMap, err := informer.Lister().ConfigMaps(namespaceName).Get("configmap-3")
				requireEventually.NoError(err)
				requireEventually.Equal("bar", configMap.Data["foo"])
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
			testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
				configMap, err := informer.Lister().ConfigMaps(namespaceName).Get("configmap-3")
				requireEventually.NoError(err)
				requireEventually.Equal("bar", configMap.Data["foo"])
				requireEventually.Equal("42", configMap.Data["baz"])
			}, 10*time.Second, 50*time.Millisecond)

			// Test "delete" verb through the impersonation proxy.
			err = impersonationProxyKubeClient(t).CoreV1().ConfigMaps(namespaceName).Delete(ctx, "configmap-3", metav1.DeleteOptions{})
			require.NoError(t, err)

			// Make sure that the deleted ConfigMap shows up in the informer's cache.
			testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
				_, err := informer.Lister().ConfigMaps(namespaceName).Get("configmap-3")
				requireEventually.Truef(apierrors.IsNotFound(err), "expected a NotFound error from get, got %v", err)

				list, err := informer.Lister().ConfigMaps(namespaceName).List(configMapLabels.AsSelector())
				requireEventually.NoError(err)
				requireEventually.Len(list, 2)
			}, 10*time.Second, 50*time.Millisecond)

			// Test "deletecollection" verb through the impersonation proxy.
			err = impersonationProxyKubeClient(t).CoreV1().ConfigMaps(namespaceName).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
			require.NoError(t, err)

			// Make sure that the deleted ConfigMaps shows up in the informer's cache.
			testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
				list, err := informer.Lister().ConfigMaps(namespaceName).List(configMapLabels.AsSelector())
				requireEventually.NoError(err)
				requireEventually.Empty(list)
			}, 10*time.Second, 50*time.Millisecond)

			// There should be no ConfigMaps left.
			listResult, err = impersonationProxyKubeClient(t).CoreV1().ConfigMaps(namespaceName).List(ctx, metav1.ListOptions{
				LabelSelector: configMapLabels.String(),
			})
			require.NoError(t, err)
			require.Len(t, listResult.Items, 0)
		})

		t.Run("nested impersonation as a regular user is allowed if they have enough RBAC permissions", func(t *testing.T) {
			parallelIfNotEKS(t)
			// Make a client which will send requests through the impersonation proxy and will also add
			// impersonate headers to the request.
			nestedImpersonationClient := newImpersonationProxyClient(t, impersonationProxyURL, impersonationProxyCACertPEM,
				&rest.ImpersonationConfig{UserName: "other-user-to-impersonate"}, refreshCredential)

			// Check that we can get some resource through the impersonation proxy without any impersonation headers on the request.
			// We could use any resource for this, but we happen to know that this one should exist.
			_, err := impersonationProxyKubeClient(t).CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName(env), metav1.GetOptions{})
			require.NoError(t, err)

			// Now we'll see what happens when we add an impersonation header to the request. This should generate a
			// request similar to the one above, except that it will also have an impersonation header.
			_, err = nestedImpersonationClient.Kubernetes.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName(env), metav1.GetOptions{})
			// this user is not allowed to impersonate other users
			require.True(t, apierrors.IsForbidden(err), err)
			require.EqualError(t, err, fmt.Sprintf(
				`users "other-user-to-impersonate" is forbidden: `+
					`User "%s" cannot impersonate resource "users" in API group "" at the cluster scope: `+
					`decision made by impersonation-proxy.concierge.pinniped.dev`,
				env.TestUser.ExpectedUsername))

			// impersonate the GC service account instead which can read anything (the binding to edit allows this)
			nestedImpersonationClientAsSA := newImpersonationProxyClient(t, impersonationProxyURL, impersonationProxyCACertPEM,
				&rest.ImpersonationConfig{UserName: "system:serviceaccount:kube-system:generic-garbage-collector"}, refreshCredential)

			_, err = nestedImpersonationClientAsSA.Kubernetes.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName(env), metav1.GetOptions{})
			require.NoError(t, err)

			expectedGroups := make([]string, 0, len(env.TestUser.ExpectedGroups)+1) // make sure we do not mutate env.TestUser.ExpectedGroups
			expectedGroups = slices.Concat(expectedGroups, env.TestUser.ExpectedGroups)
			expectedGroups = append(expectedGroups, "system:authenticated")
			expectedOriginalUserInfo := authenticationv1.UserInfo{
				Username: env.TestUser.ExpectedUsername,
				Groups:   expectedGroups,
			}
			expectedOriginalUserInfoJSON, err := json.Marshal(expectedOriginalUserInfo)
			require.NoError(t, err)

			// check that we impersonated the correct user and that the original user is retained in the extra
			whoAmI, err := nestedImpersonationClientAsSA.PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
				Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
			require.NoError(t, err)
			require.Equal(t,
				expectedWhoAmIRequestResponse(
					"system:serviceaccount:kube-system:generic-garbage-collector",
					[]string{"system:serviceaccounts", "system:serviceaccounts:kube-system", "system:authenticated"},
					map[string]identityv1alpha1.ExtraValue{
						"original-user-info.impersonation-proxy.concierge.pinniped.dev": {string(expectedOriginalUserInfoJSON)},
					},
				),
				whoAmI,
			)

			_, err = newImpersonationProxyClient(t, impersonationProxyURL, impersonationProxyCACertPEM,
				&rest.ImpersonationConfig{
					UserName: "system:serviceaccount:kube-system:generic-garbage-collector",
					Extra: map[string][]string{
						"some-fancy-key": {"with a dangerous value"},
					},
				},
				refreshCredential).PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
				Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
			// this user should not be able to impersonate extra
			require.True(t, apierrors.IsForbidden(err), err)
			require.EqualError(t, err, fmt.Sprintf(
				`userextras.authentication.k8s.io "with a dangerous value" is forbidden: `+
					`User "%s" cannot impersonate resource "userextras/some-fancy-key" in API group "authentication.k8s.io" at the cluster scope: `+
					`decision made by impersonation-proxy.concierge.pinniped.dev`,
				env.TestUser.ExpectedUsername))
		})

		t.Run("nested impersonation as a cluster admin user is allowed", func(t *testing.T) {
			parallelIfNotEKS(t)
			// Copy the admin credentials from the admin kubeconfig.
			adminClientRestConfig := testlib.NewClientConfig(t)
			clusterAdminCredentials := getCredForConfig(t, adminClientRestConfig)

			// figure out who the admin user is
			whoAmIAdmin, err := newImpersonationProxyClientWithCredentials(t,
				clusterAdminCredentials, impersonationProxyURL, impersonationProxyCACertPEM, nil).
				PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
				Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
			require.NoError(t, err, testlib.Sdump(err))

			// The WhoAmI API is lossy:
			// - It drops UID
			// - It lowercases all extra keys
			// the admin user on EKS has both a UID set and an extra key with uppercase characters
			// Thus we fallback to the CSR API to grab the UID and Extra to handle this scenario
			uid, extra := getUIDAndExtraViaCSR(ctx, t, whoAmIAdmin.Status.KubernetesUserInfo.User.UID,
				newImpersonationProxyClientWithCredentials(t,
					clusterAdminCredentials, impersonationProxyURL, impersonationProxyCACertPEM, nil).
					Kubernetes,
			)

			expectedExtra := make(map[string]authenticationv1.ExtraValue, len(extra))
			for k, v := range extra {
				expectedExtra[k] = authenticationv1.ExtraValue(v)
			}
			expectedOriginalUserInfo := authenticationv1.UserInfo{
				Username: whoAmIAdmin.Status.KubernetesUserInfo.User.Username,
				UID:      uid,
				Groups:   whoAmIAdmin.Status.KubernetesUserInfo.User.Groups,
				Extra:    expectedExtra,
			}
			expectedOriginalUserInfoJSON, err := json.Marshal(expectedOriginalUserInfo)
			require.NoError(t, err)

			// Make a client using the admin credentials which will send requests through the impersonation proxy
			// and will also add impersonate headers to the request.
			nestedImpersonationClient := newImpersonationProxyClientWithCredentials(t,
				clusterAdminCredentials, impersonationProxyURL, impersonationProxyCACertPEM,
				&rest.ImpersonationConfig{
					UserName: "other-user-to-impersonate",
					Groups:   []string{"other-group-1", "other-group-2"},
					Extra: map[string][]string{
						"this-key": {"to this value"},
					},
				},
			)

			_, err = nestedImpersonationClient.Kubernetes.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName(env), metav1.GetOptions{})
			// the impersonated user lacks the RBAC to perform this call
			require.True(t, apierrors.IsForbidden(err), err)
			require.EqualError(t, err, fmt.Sprintf(
				`secrets "%s" is forbidden: User "other-user-to-impersonate" cannot get resource "secrets" in API group "" in the namespace "%s": `+
					`decision made by impersonation-proxy.concierge.pinniped.dev`,
				impersonationProxyTLSSecretName(env), env.ConciergeNamespace,
			))

			// check that we impersonated the correct user and that the original user is retained in the extra
			whoAmI, err := nestedImpersonationClient.PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
				Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
			require.NoError(t, err, testlib.Sdump(err))
			require.Equal(t,
				expectedWhoAmIRequestResponse(
					"other-user-to-impersonate",
					[]string{"other-group-1", "other-group-2", "system:authenticated"},
					map[string]identityv1alpha1.ExtraValue{
						"this-key": {"to this value"},
						"original-user-info.impersonation-proxy.concierge.pinniped.dev": {string(expectedOriginalUserInfoJSON)},
					},
				),
				whoAmI,
			)
		})

		t.Run("nested impersonation as a cluster admin fails on reserved key", func(t *testing.T) {
			parallelIfNotEKS(t)
			adminClientRestConfig := testlib.NewClientConfig(t)
			clusterAdminCredentials := getCredForConfig(t, adminClientRestConfig)

			nestedImpersonationClient := newImpersonationProxyClientWithCredentials(t,
				clusterAdminCredentials, impersonationProxyURL, impersonationProxyCACertPEM,
				&rest.ImpersonationConfig{
					UserName: "other-user-to-impersonate",
					Groups:   []string{"other-group-1", "other-group-2", "system:masters"}, // impersonate system:masters so we get past authorization checks
					Extra: map[string][]string{
						"this-good-key": {"to this good value"},
						"something.impersonation-proxy.concierge.pinniped.dev": {"super sneaky value"},
					},
				},
			)

			_, err := nestedImpersonationClient.Kubernetes.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName(env), metav1.GetOptions{})
			require.EqualError(t, err, "Internal error occurred: unimplemented functionality - unable to act as current user")
			require.True(t, apierrors.IsInternalError(err), err)
			require.Equal(t, &apierrors.StatusError{
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

		t.Run("nested impersonation as a cluster admin fails if UID impersonation is attempted", func(t *testing.T) {
			parallelIfNotEKS(t)
			adminClientRestConfig := testlib.NewClientConfig(t)
			clusterAdminCredentials := getCredForConfig(t, adminClientRestConfig)

			nestedImpersonationUIDOnly := newImpersonationProxyConfigWithCredentials(t,
				clusterAdminCredentials, impersonationProxyURL, impersonationProxyCACertPEM, nil,
			)
			nestedImpersonationUIDOnly.Wrap(func(rt http.RoundTripper) http.RoundTripper {
				return roundtripper.WrapFunc(rt, func(r *http.Request) (*http.Response, error) {
					r.Header.Set("iMperSONATE-uid", "some-awesome-uid")
					return rt.RoundTrip(r)
				})
			})

			_, errUID := testlib.NewKubeclient(t, nestedImpersonationUIDOnly).Kubernetes.CoreV1().Secrets("foo").Get(ctx, "bar", metav1.GetOptions{})
			msg := `Internal Server Error: "/api/v1/namespaces/foo/secrets/bar": requested [{UID  some-awesome-uid  authentication.k8s.io/v1  }] without impersonating a user`
			full := fmt.Sprintf(`an error on the server (%q) has prevented the request from succeeding (get secrets bar)`, msg)
			require.EqualError(t, errUID, full)
			require.True(t, apierrors.IsInternalError(errUID), errUID)
			require.Equal(t, &apierrors.StatusError{
				ErrStatus: metav1.Status{
					Status: metav1.StatusFailure,
					Code:   http.StatusInternalServerError,
					Reason: metav1.StatusReasonInternalError,
					Details: &metav1.StatusDetails{
						Name: "bar",
						Kind: "secrets",
						Causes: []metav1.StatusCause{
							{
								Type:    metav1.CauseTypeUnexpectedServerResponse,
								Message: msg,
							},
						},
					},
					Message: full,
				},
			}, errUID)

			nestedImpersonationUID := newImpersonationProxyConfigWithCredentials(t,
				clusterAdminCredentials, impersonationProxyURL, impersonationProxyCACertPEM,
				&rest.ImpersonationConfig{
					UserName: "other-user-to-impersonate",
					Groups:   []string{"system:masters"}, // impersonate system:masters so we get past authorization checks
				},
			)
			nestedImpersonationUID.Wrap(func(rt http.RoundTripper) http.RoundTripper {
				return roundtripper.WrapFunc(rt, func(r *http.Request) (*http.Response, error) {
					r.Header.Set("imperSONate-uiD", "some-fancy-uid")
					return rt.RoundTrip(r)
				})
			})

			_, err := testlib.NewKubeclient(t, nestedImpersonationUID).Kubernetes.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName(env), metav1.GetOptions{})
			require.EqualError(t, err, "Internal error occurred: unimplemented functionality - unable to act as current user")
			require.True(t, apierrors.IsInternalError(err), err)
			require.Equal(t, &apierrors.StatusError{
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

		// this works because impersonation cannot set UID and thus the final user info the proxy sees has no UID
		t.Run("nested impersonation as a service account is allowed if it has enough RBAC permissions", func(t *testing.T) {
			parallelIfNotEKS(t)
			namespaceName := testlib.CreateNamespace(ctx, t, "impersonation").Name
			saName, saToken, saUID := createServiceAccountToken(ctx, t, adminClient, namespaceName)
			nestedImpersonationClient := newImpersonationProxyClientWithCredentials(t,
				&loginv1alpha1.ClusterCredential{Token: saToken}, impersonationProxyURL, impersonationProxyCACertPEM,
				&rest.ImpersonationConfig{UserName: "system:serviceaccount:kube-system:root-ca-cert-publisher"}).PinnipedConcierge
			_, err := nestedImpersonationClient.IdentityV1alpha1().WhoAmIRequests().
				Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
			// this SA is not yet allowed to impersonate SAs
			require.True(t, apierrors.IsForbidden(err), err)
			require.EqualError(t, err, fmt.Sprintf(
				`serviceaccounts "root-ca-cert-publisher" is forbidden: `+
					`User "%s" cannot impersonate resource "serviceaccounts" in API group "" in the namespace "kube-system": `+
					`decision made by impersonation-proxy.concierge.pinniped.dev`,
				serviceaccount.MakeUsername(namespaceName, saName)))

			// webhook authorizer deny cache TTL is 10 seconds so we need to wait long enough for it to drain
			time.Sleep(15 * time.Second)

			// allow the test SA to impersonate any SA
			testlib.CreateTestClusterRoleBinding(t,
				rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: saName, Namespace: namespaceName},
				rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "edit"},
			)
			testlib.WaitForUserToHaveAccess(t, serviceaccount.MakeUsername(namespaceName, saName), []string{}, &authorizationv1.ResourceAttributes{
				Verb: "impersonate", Group: "", Version: "v1", Resource: "serviceaccounts",
			})

			whoAmI, err := nestedImpersonationClient.IdentityV1alpha1().WhoAmIRequests().
				Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
			require.NoError(t, err, testlib.Sdump(err))
			require.Equal(t,
				expectedWhoAmIRequestResponse(
					"system:serviceaccount:kube-system:root-ca-cert-publisher",
					[]string{"system:serviceaccounts", "system:serviceaccounts:kube-system", "system:authenticated"},
					map[string]identityv1alpha1.ExtraValue{
						"original-user-info.impersonation-proxy.concierge.pinniped.dev": {
							fmt.Sprintf(`{"username":"%s","uid":"%s","groups":["system:serviceaccounts","system:serviceaccounts:%s","system:authenticated"]}`,
								serviceaccount.MakeUsername(namespaceName, saName), saUID, namespaceName),
						},
					},
				),
				whoAmI,
			)
		})

		t.Run("WhoAmIRequests and different kinds of authentication through the impersonation proxy", func(t *testing.T) {
			parallelIfNotEKS(t)
			// Test using the TokenCredentialRequest for authentication.
			impersonationProxyPinnipedConciergeClient := newImpersonationProxyClient(t,
				impersonationProxyURL, impersonationProxyCACertPEM, nil, refreshCredential,
			).PinnipedConcierge
			whoAmI, err := impersonationProxyPinnipedConciergeClient.IdentityV1alpha1().WhoAmIRequests().
				Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
			require.NoError(t, err, testlib.Sdump(err))
			expectedGroups := make([]string, 0, len(env.TestUser.ExpectedGroups)+1) // make sure we do not mutate env.TestUser.ExpectedGroups
			expectedGroups = slices.Concat(expectedGroups, env.TestUser.ExpectedGroups)
			expectedGroups = append(expectedGroups, "system:authenticated")
			require.Equal(t,
				expectedWhoAmIRequestResponse(
					env.TestUser.ExpectedUsername,
					expectedGroups,
					nil,
				),
				whoAmI,
			)

			// Test an unauthenticated request which does not include any credentials.
			impersonationProxyAnonymousPinnipedConciergeClient := newAnonymousImpersonationProxyClient(
				t, impersonationProxyURL, impersonationProxyCACertPEM, nil,
			).PinnipedConcierge
			whoAmI, err = impersonationProxyAnonymousPinnipedConciergeClient.IdentityV1alpha1().WhoAmIRequests().
				Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})

			// we expect the impersonation proxy to match the behavior of KAS in regards to anonymous requests
			if env.HasCapability(testlib.AnonymousAuthenticationSupported) {
				require.NoError(t, err, testlib.Sdump(err))
				require.Equal(t,
					expectedWhoAmIRequestResponse(
						"system:anonymous",
						[]string{"system:unauthenticated"},
						nil,
					),
					whoAmI,
				)
			} else {
				require.True(t, apierrors.IsUnauthorized(err), testlib.Sdump(err))
			}

			// Test using a service account token.
			namespaceName := testlib.CreateNamespace(ctx, t, "impersonation").Name
			saName, saToken, _ := createServiceAccountToken(ctx, t, adminClient, namespaceName)
			impersonationProxyServiceAccountPinnipedConciergeClient := newImpersonationProxyClientWithCredentials(t,
				&loginv1alpha1.ClusterCredential{Token: saToken},
				impersonationProxyURL, impersonationProxyCACertPEM, nil).PinnipedConcierge
			whoAmI, err = impersonationProxyServiceAccountPinnipedConciergeClient.IdentityV1alpha1().WhoAmIRequests().
				Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
			require.NoError(t, err, testlib.Sdump(err))
			require.Equal(t,
				expectedWhoAmIRequestResponse(
					serviceaccount.MakeUsername(namespaceName, saName),
					[]string{"system:serviceaccounts", "system:serviceaccounts:" + namespaceName, "system:authenticated"},
					nil,
				),
				whoAmI,
			)
		})

		t.Run("WhoAmIRequests and SA token request", func(t *testing.T) {
			namespaceName := testlib.CreateNamespace(ctx, t, "impersonation").Name
			kubeClient := adminClient.CoreV1()
			saName, _, saUID := createServiceAccountToken(ctx, t, adminClient, namespaceName)
			expectedUsername := serviceaccount.MakeUsername(namespaceName, saName)
			expectedUID := string(saUID)
			expectedGroups := []string{"system:serviceaccounts", "system:serviceaccounts:" + namespaceName, "system:authenticated"}

			_, tokenRequestProbeErr := kubeClient.ServiceAccounts(namespaceName).CreateToken(ctx, saName, &authenticationv1.TokenRequest{}, metav1.CreateOptions{})
			if apierrors.IsNotFound(tokenRequestProbeErr) && tokenRequestProbeErr.Error() == "the server could not find the requested resource" {
				return // stop test early since the token request API is not enabled on this cluster - other errors are caught below
			}

			pod := testlib.CreatePod(ctx, t, "impersonation-proxy", namespaceName,
				corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            "sleeper",
							Image:           env.ShellContainerImage,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         []string{"sh", "-c", "sleep 3600"},
							// Use a restrictive security context just in case the test cluster has PSAs enabled.
							SecurityContext: testlib.RestrictiveSecurityContext(),
						},
					},
					ServiceAccountName: saName,
				})

			tokenRequestBadAudience, err := kubeClient.ServiceAccounts(namespaceName).CreateToken(ctx, saName, &authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{
					Audiences: []string{"should-fail-because-wrong-audience"}, // anything that is not an API server audience
					BoundObjectRef: &authenticationv1.BoundObjectReference{
						Kind:       "Pod",
						APIVersion: "",
						Name:       pod.Name,
						UID:        pod.UID,
					},
				},
			}, metav1.CreateOptions{})
			require.NoError(t, err)

			impersonationProxySABadAudPinnipedConciergeClient := newImpersonationProxyClientWithCredentials(t,
				&loginv1alpha1.ClusterCredential{Token: tokenRequestBadAudience.Status.Token},
				impersonationProxyURL, impersonationProxyCACertPEM, nil).PinnipedConcierge

			_, badAudErr := impersonationProxySABadAudPinnipedConciergeClient.IdentityV1alpha1().WhoAmIRequests().
				Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
			require.True(t, apierrors.IsUnauthorized(badAudErr), testlib.Sdump(badAudErr))

			tokenRequest, err := kubeClient.ServiceAccounts(namespaceName).CreateToken(ctx, saName, &authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{
					Audiences: []string{},
					BoundObjectRef: &authenticationv1.BoundObjectReference{
						Kind:       "Pod",
						APIVersion: "",
						Name:       pod.Name,
						UID:        pod.UID,
					},
				},
			}, metav1.CreateOptions{})
			require.NoError(t, err)

			impersonationProxySAClient := newImpersonationProxyClientWithCredentials(t,
				&loginv1alpha1.ClusterCredential{Token: tokenRequest.Status.Token},
				impersonationProxyURL, impersonationProxyCACertPEM, nil)

			whoAmITokenReq, err := impersonationProxySAClient.PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
				Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
			require.NoError(t, err, testlib.Sdump(err))

			// new service account tokens include the pod info in the extra fields
			require.Equal(t,
				expectedWhoAmIRequestResponse(
					expectedUsername,
					expectedGroups,
					whoAmITokenReq.Status.KubernetesUserInfo.User.Extra, // This will be a dynamic assertion below based on the version of K8s
				),
				whoAmITokenReq,
			)

			testutil.CheckServiceAccountExtraFieldsAccountingForChangesInK8s1_30[map[string]identityv1alpha1.ExtraValue](
				t,
				adminClient.Discovery(),
				whoAmITokenReq.Status.KubernetesUserInfo.User.Extra,
				pod,
			)

			// allow the test SA to create CSRs
			testlib.CreateTestClusterRoleBinding(t,
				rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: saName, Namespace: namespaceName},
				rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "system:node-bootstrapper"},
			)
			testlib.WaitForUserToHaveAccess(t, expectedUsername, []string{}, &authorizationv1.ResourceAttributes{
				Verb: "create", Group: certificatesv1.GroupName, Version: "*", Resource: "certificatesigningrequests",
			})

			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			csrPEM, err := cert.MakeCSR(privateKey, &pkix.Name{
				CommonName:   "panda-man",
				Organization: []string{"living-the-dream", "need-more-sleep"},
			}, nil, nil)
			require.NoError(t, err)

			csrName, _, err := csr.RequestCertificate(
				impersonationProxySAClient.Kubernetes,
				csrPEM,
				"",
				certificatesv1.KubeAPIServerClientSignerName,
				nil,
				[]certificatesv1.KeyUsage{certificatesv1.UsageClientAuth},
				privateKey,
			)
			require.NoError(t, err)

			if testutil.KubeServerSupportsCertificatesV1API(t, adminClient.Discovery()) {
				saCSR, err := impersonationProxySAClient.Kubernetes.CertificatesV1().CertificateSigningRequests().Get(ctx, csrName, metav1.GetOptions{})
				require.NoError(t, err)
				err = adminClient.CertificatesV1().CertificateSigningRequests().Delete(ctx, csrName, metav1.DeleteOptions{})
				require.NoError(t, err)
				// make sure the user info that the CSR captured matches the SA, including the UID
				require.Equal(t, expectedUsername, saCSR.Spec.Username)
				require.Equal(t, expectedUID, saCSR.Spec.UID)
				require.Equal(t, expectedGroups, saCSR.Spec.Groups)
				testutil.CheckServiceAccountExtraFieldsAccountingForChangesInK8s1_30[map[string]certificatesv1.ExtraValue](
					t,
					adminClient.Discovery(),
					saCSR.Spec.Extra,
					pod,
				)
			} else {
				// On old Kubernetes clusters use CertificatesV1beta1
				saCSR, err := impersonationProxySAClient.Kubernetes.CertificatesV1beta1().CertificateSigningRequests().Get(ctx, csrName, metav1.GetOptions{})
				require.NoError(t, err)
				err = adminClient.CertificatesV1beta1().CertificateSigningRequests().Delete(ctx, csrName, metav1.DeleteOptions{})
				require.NoError(t, err)
				// make sure the user info that the CSR captured matches the SA, including the UID
				require.Equal(t, expectedUsername, saCSR.Spec.Username)
				require.Equal(t, expectedUID, saCSR.Spec.UID)
				require.Equal(t, expectedGroups, saCSR.Spec.Groups)
				testutil.CheckServiceAccountExtraFieldsAccountingForChangesInK8s1_30[map[string]certificatesv1beta1.ExtraValue](
					t,
					adminClient.Discovery(),
					saCSR.Spec.Extra,
					pod,
				)
			}
		})

		t.Run("kubectl as a client", func(t *testing.T) {
			parallelIfNotEKS(t)
			kubeconfigPath, envVarsWithProxy, tempDir := getImpersonationKubeconfig(t, env, impersonationProxyURL, impersonationProxyCACertPEM, credentialRequestSpecWithWorkingCredentials.Authenticator)

			// Run a new test pod so we can interact with it using kubectl. We use a fresh pod here rather than the
			// existing Concierge pod because we need more tools than we can get from a scratch/distroless base image.
			runningTestPod := testlib.CreatePod(ctx, t, "impersonation-proxy", env.ConciergeNamespace, corev1.PodSpec{Containers: []corev1.Container{{
				Name:            "impersonation-proxy-test",
				Image:           env.ShellContainerImage,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         []string{"bash", "-c", `while true; do read VAR; echo "VAR: $VAR"; done`},
				Stdin:           true,
				// Use a restrictive security context just in case the test cluster has PSAs enabled.
				SecurityContext: testlib.RestrictiveSecurityContext(),
			}}})

			// Try "kubectl exec" through the impersonation proxy.
			echoString := "hello world"
			remoteEchoFile := fmt.Sprintf("/tmp/test-impersonation-proxy-echo-file-%d.txt", time.Now().Unix())
			stdout, err := runKubectl(t, kubeconfigPath, envVarsWithProxy, "exec", "--namespace", runningTestPod.Namespace, runningTestPod.Name, "--", "bash", "-c", fmt.Sprintf(`echo "%s" | tee %s`, echoString, remoteEchoFile))
			require.NoError(t, err, `"kubectl exec" failed`)
			require.Equal(t, echoString+"\n", stdout)

			// run the kubectl cp command
			localEchoFile := filepath.Join(tempDir, filepath.Base(remoteEchoFile))
			_, err = runKubectl(t, kubeconfigPath, envVarsWithProxy, "cp", fmt.Sprintf("%s/%s:%s", runningTestPod.Namespace, runningTestPod.Name, remoteEchoFile), localEchoFile)
			require.NoError(t, err, `"kubectl cp" failed`)
			localEchoFileData, err := os.ReadFile(localEchoFile)
			require.NoError(t, err)
			require.Equal(t, echoString+"\n", string(localEchoFileData))

			// run the kubectl logs command
			logLinesCount := 10
			stdout, err = runKubectl(t, kubeconfigPath, envVarsWithProxy, "logs", "--namespace", supervisorPod.Namespace, supervisorPod.Name, fmt.Sprintf("--tail=%d", logLinesCount))
			require.NoError(t, err, `"kubectl logs" failed`)
			// Expect _approximately_ logLinesCount lines in the output
			// (we can't match 100% exactly due to https://github.com/kubernetes/kubernetes/issues/72628).
			require.InDeltaf(t, logLinesCount, strings.Count(stdout, "\n"), 1, "wanted %d newlines in kubectl logs output:\n%s", logLinesCount, stdout)

			// run the kubectl attach command
			timeout, cancelFunc := context.WithTimeout(ctx, 2*time.Minute)
			defer cancelFunc()
			attachCmd, attachStdout, attachStderr := kubectlCommand(timeout, t, kubeconfigPath, envVarsWithProxy, "attach", "--stdin=true", "--namespace", runningTestPod.Namespace, runningTestPod.Name, "-v=10")
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
			testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
				requireEventually.Equal(
					wantAttachStdout,
					attachStdout.String(),
					`got "kubectl attach" stdout: %q, wanted: %q (stderr: %q)`,
					attachStdout.String(),
					wantAttachStdout,
					attachStderr.String(),
				)
			}, time.Second*60, time.Millisecond*250)

			// close stdin and attach process should exit
			err = attachStdin.Close()
			require.NoError(t, err)
			requireClose(t, attachExitCh, time.Second*20)
		})

		t.Run("websocket client", func(t *testing.T) {
			parallelIfNotEKS(t)
			namespaceName := testlib.CreateNamespace(ctx, t, "impersonation").Name

			impersonationRestConfig := impersonationProxyRestConfig(
				refreshCredential(t, impersonationProxyURL, impersonationProxyCACertPEM),
				impersonationProxyURL, impersonationProxyCACertPEM, nil,
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
					t.Logf("passing request for %s through proxy %s", testlib.RedactURLParams(req.URL), proxyURL.String())
					return proxyURL, nil
				}
			}
			var (
				resp *http.Response
				conn *websocket.Conn
			)
			testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
				var err error
				conn, resp, err = dialer.Dial(dest.String(), http.Header{"Origin": {dest.String()}})
				if resp != nil {
					defer func() { requireEventually.NoError(resp.Body.Close()) }()
				}
				if err != nil && resp != nil {
					body, _ := io.ReadAll(resp.Body)
					t.Logf("websocket dial failed: %d:%s", resp.StatusCode, body)
				}
				requireEventually.NoError(err)
			}, time.Minute, time.Second)

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
			_, message, err := conn.ReadMessage()
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
			parallelIfNotEKS(t)
			namespaceName := testlib.CreateNamespace(ctx, t, "impersonation").Name

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
				impersonationProxyURL, impersonationProxyCACertPEM, nil,
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
					t.Logf("passing request for %s through proxy %s", testlib.RedactURLParams(req.URL), proxyURL.String())
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
			body, _ := io.ReadAll(response.Body)
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

		t.Run("honors anonymous authentication of KAS", func(t *testing.T) {
			parallelIfNotEKS(t)

			impersonationProxyAnonymousClient := newAnonymousImpersonationProxyClient(
				t, impersonationProxyURL, impersonationProxyCACertPEM, nil,
			)

			copyConfig := rest.CopyConfig(impersonationProxyAnonymousClient.JSONConfig)
			copyConfig.GroupVersion = &schema.GroupVersion{}
			copyConfig.NegotiatedSerializer = unstructuredscheme.NewUnstructuredNegotiatedSerializer()
			impersonationProxyAnonymousRestClient, err := rest.RESTClientFor(copyConfig)
			require.NoError(t, err)

			adminClientRestConfig := testlib.NewClientConfig(t)
			clusterAdminCredentials := getCredForConfig(t, adminClientRestConfig)
			impersonationProxyAdminClientAsAnonymousConfig := newImpersonationProxyClientWithCredentials(t,
				clusterAdminCredentials,
				impersonationProxyURL, impersonationProxyCACertPEM,
				&rest.ImpersonationConfig{UserName: user.Anonymous}).
				JSONConfig
			impersonationProxyAdminClientAsAnonymousConfigCopy := rest.CopyConfig(impersonationProxyAdminClientAsAnonymousConfig)
			impersonationProxyAdminClientAsAnonymousConfigCopy.GroupVersion = &schema.GroupVersion{}
			impersonationProxyAdminClientAsAnonymousConfigCopy.NegotiatedSerializer = unstructuredscheme.NewUnstructuredNegotiatedSerializer()
			impersonationProxyAdminRestClientAsAnonymous, err := rest.RESTClientFor(impersonationProxyAdminClientAsAnonymousConfigCopy)
			require.NoError(t, err)

			t.Run("anonymous authentication irrelevant", func(t *testing.T) {
				parallelIfNotEKS(t)

				// - hit the token credential request endpoint with an empty body
				//   - through the impersonation proxy
				//   - should succeed as an invalid request whether anonymous authentication is enabled or disabled
				//   - should not reject as unauthorized
				t.Run("token credential request", func(t *testing.T) {
					parallelIfNotEKS(t)

					tkr, err := impersonationProxyAnonymousClient.PinnipedConcierge.LoginV1alpha1().TokenCredentialRequests().
						Create(ctx, &loginv1alpha1.TokenCredentialRequest{
							Spec: loginv1alpha1.TokenCredentialRequestSpec{
								Authenticator: corev1.TypedLocalObjectReference{APIGroup: ptr.To("anything.pinniped.dev")},
							},
						}, metav1.CreateOptions{})
					require.True(t, apierrors.IsInvalid(err), testlib.Sdump(err))
					require.Equal(t, `.login.concierge.pinniped.dev "" is invalid: spec.token.value: Required value: token must be supplied`, err.Error())
					require.Equal(t, &loginv1alpha1.TokenCredentialRequest{}, tkr)
				})

				// - hit the healthz endpoint (non-resource endpoint)
				//   - through the impersonation proxy
				//   - as cluster admin, impersonating anonymous user
				//   - should succeed, authentication happens as cluster-admin
				//   - whoami should confirm we are using impersonation
				//   - healthz should succeed, anonymous users can request this endpoint
				//   - healthz/log should fail, forbidden anonymous
				t.Run("non-resource request while impersonating anonymous - nested impersonation", func(t *testing.T) {
					parallelIfNotEKS(t)

					whoami, errWho := impersonationProxyAdminRestClientAsAnonymous.Post().Body([]byte(`{}`)).AbsPath("/apis/identity.concierge." + env.APIGroupSuffix + "/v1alpha1/whoamirequests").DoRaw(ctx)
					require.NoError(t, errWho, testlib.Sdump(errWho))
					require.True(t, strings.HasPrefix(string(whoami), `{"kind":"WhoAmIRequest","apiVersion":"identity.concierge.`+env.APIGroupSuffix+`/v1alpha1","metadata":{"creationTimestamp":null},"spec":{},"status":{"kubernetesUserInfo":{"user":{"username":"system:anonymous","groups":["system:unauthenticated"],"extra":{"original-user-info.impersonation-proxy.concierge.pinniped.dev":["{\"username\":`), string(whoami))

					healthz, errHealth := impersonationProxyAdminRestClientAsAnonymous.Get().AbsPath("/healthz").DoRaw(ctx)
					require.NoError(t, errHealth, testlib.Sdump(errHealth))
					require.Equal(t, "ok", string(healthz))

					healthzLog, errHealthzLog := impersonationProxyAdminRestClientAsAnonymous.Get().AbsPath("/healthz/log").DoRaw(ctx)
					require.True(t, apierrors.IsForbidden(errHealthzLog), "%s\n%s", testlib.Sdump(errHealthzLog), string(healthzLog))
					require.Equal(t, `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User \"system:anonymous\" cannot get path \"/healthz/log\": decision made by impersonation-proxy.concierge.pinniped.dev","reason":"Forbidden","details":{},"code":403}`+"\n", string(healthzLog))
				})
			})

			t.Run("anonymous authentication enabled", func(t *testing.T) {
				testlib.IntegrationEnv(t).WithCapability(testlib.AnonymousAuthenticationSupported)
				parallelIfNotEKS(t)

				// anonymous auth enabled
				// - hit the healthz endpoint (non-resource endpoint)
				//   - through the impersonation proxy
				//   - should succeed 200
				//   - should respond "ok"
				t.Run("non-resource request", func(t *testing.T) {
					parallelIfNotEKS(t)

					healthz, errHealth := impersonationProxyAnonymousRestClient.Get().AbsPath("/healthz").DoRaw(ctx)
					require.NoError(t, errHealth, testlib.Sdump(errHealth))
					require.Equal(t, "ok", string(healthz))
				})

				// - hit the pods endpoint (a resource endpoint)
				//   - through the impersonation proxy
				//   - should fail forbidden
				//   - system:anonymous cannot get pods
				t.Run("resource", func(t *testing.T) {
					parallelIfNotEKS(t)

					pod, err := impersonationProxyAnonymousClient.Kubernetes.CoreV1().Pods(metav1.NamespaceSystem).
						Get(ctx, "does-not-matter", metav1.GetOptions{})
					require.True(t, apierrors.IsForbidden(err), testlib.Sdump(err))
					require.EqualError(t, err, `pods "does-not-matter" is forbidden: User "system:anonymous" cannot get resource "pods" in API group "" in the namespace "kube-system": `+
						`decision made by impersonation-proxy.concierge.pinniped.dev`, testlib.Sdump(err))
					require.Equal(t, &corev1.Pod{}, pod)
				})

				// - request to whoami (pinniped resource endpoint)
				//   - through the impersonation proxy
				//   - should succeed 200
				//   - should respond "you are system:anonymous"
				t.Run("pinniped resource request", func(t *testing.T) {
					parallelIfNotEKS(t)

					whoAmI, err := impersonationProxyAnonymousClient.PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
						Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
					require.NoError(t, err, testlib.Sdump(err))
					require.Equal(t,
						expectedWhoAmIRequestResponse(
							"system:anonymous",
							[]string{"system:unauthenticated"},
							nil,
						),
						whoAmI,
					)
				})
			})

			t.Run("anonymous authentication disabled", func(t *testing.T) {
				testlib.IntegrationEnv(t).WithoutCapability(testlib.AnonymousAuthenticationSupported)
				parallelIfNotEKS(t)

				// - hit the healthz endpoint (non-resource endpoint)
				//   - through the impersonation proxy
				//   - should fail unauthorized
				//   - kube api server should reject it
				t.Run("non-resource request", func(t *testing.T) {
					parallelIfNotEKS(t)

					healthz, err := impersonationProxyAnonymousRestClient.Get().AbsPath("/healthz").DoRaw(ctx)
					require.True(t, apierrors.IsUnauthorized(err), testlib.Sdump(err))
					require.Equal(t, `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}`+"\n", string(healthz))
				})

				// - hit the pods endpoint (a resource endpoint)
				//   - through the impersonation proxy
				//   - should fail unauthorized
				//   - kube api server should reject it
				t.Run("resource", func(t *testing.T) {
					parallelIfNotEKS(t)

					pod, err := impersonationProxyAnonymousClient.Kubernetes.CoreV1().Pods(metav1.NamespaceSystem).
						Get(ctx, "does-not-matter", metav1.GetOptions{})
					require.True(t, apierrors.IsUnauthorized(err), testlib.Sdump(err))
					require.Equal(t, &corev1.Pod{}, pod)
				})

				// - request to whoami (pinniped resource endpoing)
				//   - through the impersonation proxy
				//   - should fail unauthorized
				//   - kube api server should reject it
				t.Run("pinniped resource request", func(t *testing.T) {
					parallelIfNotEKS(t)

					whoAmI, err := impersonationProxyAnonymousClient.PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
						Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
					require.True(t, apierrors.IsUnauthorized(err), testlib.Sdump(err))
					require.Equal(t, &identityv1alpha1.WhoAmIRequest{}, whoAmI)
				})
			})
		})

		t.Run("assert impersonator runs with secure TLS config", func(t *testing.T) {
			parallelIfNotEKS(t)

			cancelCtx, cancel := context.WithCancel(ctx)
			t.Cleanup(cancel)

			startKubectlPortForward(cancelCtx, t, "10445", "443", env.ConciergeAppName+"-proxy", env.ConciergeNamespace)

			stdout, stderr := testlib.RunNmapSSLEnum(t, "127.0.0.1", 10445)

			require.Empty(t, stderr)
			require.Contains(t, stdout, testlib.GetExpectedCiphers(ptls.Default(nil), testlib.DefaultCipherSuitePreference), "stdout:\n%s", stdout)
		})
	})

	t.Run("assert correct impersonator service account is being used", func(t *testing.T) {
		// pick an API that everyone can access but always make invalid requests to it
		// we can tell that the request is reaching KAS because only it has the validation logic
		impersonationProxySSRRClient := impersonationProxyKubeClient(t).AuthorizationV1().SelfSubjectRulesReviews()
		crbClient := adminClient.RbacV1().ClusterRoleBindings()
		impersonationProxyName := env.ConciergeAppName + "-impersonation-proxy"
		saFullName := serviceaccount.MakeUsername(env.ConciergeNamespace, impersonationProxyName)
		invalidSSRR := &authorizationv1.SelfSubjectRulesReview{}

		// sanity check default expected error message
		_, err := impersonationProxySSRRClient.Create(ctx, invalidSSRR, metav1.CreateOptions{})
		require.True(t, apierrors.IsBadRequest(err), testlib.Sdump(err))
		require.EqualError(t, err, "no namespace on request")

		// remove the impersonation proxy SA's permissions
		crb, err := crbClient.Get(ctx, impersonationProxyName, metav1.GetOptions{})
		require.NoError(t, err)

		// sanity check the subject
		require.Len(t, crb.Subjects, 1)
		sub := crb.Subjects[0].DeepCopy()
		require.Equal(t, &rbacv1.Subject{
			Kind:      "ServiceAccount",
			APIGroup:  "",
			Name:      impersonationProxyName,
			Namespace: env.ConciergeNamespace,
		}, sub)

		crb.Subjects = nil
		_, err = crbClient.Update(ctx, crb, metav1.UpdateOptions{})
		require.NoError(t, err)

		// make sure to put the permissions back at the end
		t.Cleanup(func() {
			crbEnd, errEnd := crbClient.Get(ctx, impersonationProxyName, metav1.GetOptions{})
			require.NoError(t, errEnd)

			crbEnd.Subjects = []rbacv1.Subject{*sub}
			_, errUpdate := crbClient.Update(ctx, crbEnd, metav1.UpdateOptions{})
			require.NoError(t, errUpdate)

			testlib.WaitForUserToHaveAccess(t, saFullName, nil, &authorizationv1.ResourceAttributes{
				Verb:     "impersonate",
				Resource: "users",
			})
		})

		// assert that the impersonation proxy stops working when we remove its permissions
		testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
			_, errCreate := impersonationProxySSRRClient.Create(ctx, invalidSSRR, metav1.CreateOptions{})

			switch {
			case errCreate == nil:
				return false, fmt.Errorf("unexpected nil error for test user create invalid SSRR")

			case apierrors.IsBadRequest(errCreate) && errCreate.Error() == "no namespace on request":
				t.Log("waiting for impersonation proxy service account to lose impersonate permissions")
				return false, nil // RBAC change has not rolled out yet

			case apierrors.IsForbidden(errCreate) && errCreate.Error() ==
				`users "`+env.TestUser.ExpectedUsername+`" is forbidden: User "`+saFullName+
					`" cannot impersonate resource "users" in API group "" at the cluster scope`:
				return true, nil // expected RBAC error

			default:
				return false, fmt.Errorf("unexpected error for test user create invalid SSRR: %w", errCreate)
			}
		}, time.Minute, time.Second)
	})

	t.Run("adding an annotation reconciles the LoadBalancer service", func(t *testing.T) {
		//nolint:staticcheck // De Morgan's doesn't make this more readable
		if !(impersonatorShouldHaveStartedAutomaticallyByDefault && clusterSupportsLoadBalancers) {
			t.Skip("only running when the cluster is meant to be using LoadBalancer services")
		}

		// Use this string in all annotation keys added by this test, so the assertions can ignore annotation keys
		// which might exist on the Service which are not related to this test.
		recognizableAnnotationKeyString := "pinniped.dev"

		// Grab the state of the CredentialIssuer prior to this test, so we can restore things back afterwards.
		previous, err := adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Get(ctx, credentialIssuerName(env), metav1.GetOptions{})
		require.NoError(t, err)

		updateServiceAnnotations := func(annotations map[string]string) {
			require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
				service, err := adminClient.CoreV1().Services(env.ConciergeNamespace).Get(ctx, impersonationProxyLoadBalancerName(env), metav1.GetOptions{})
				if err != nil {
					return err
				}
				updated := service.DeepCopy()
				if updated.Annotations == nil {
					updated.Annotations = map[string]string{}
				}
				// Add/update each requested annotation, without overwriting others that are already there.
				for k, v := range annotations {
					updated.Annotations[k] = v
				}
				if equality.Semantic.DeepEqual(service, updated) {
					return nil
				}

				t.Logf("updating Service with annotations: %v", annotations)
				_, err = adminClient.CoreV1().Services(env.ConciergeNamespace).Update(ctx, updated, metav1.UpdateOptions{})
				return err
			}))
		}

		deleteServiceAnnotations := func(annotations map[string]string) {
			require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
				service, err := adminClient.CoreV1().Services(env.ConciergeNamespace).Get(ctx, impersonationProxyLoadBalancerName(env), metav1.GetOptions{})
				if err != nil {
					return err
				}
				updated := service.DeepCopy()
				if updated.Annotations != nil {
					for k := range annotations {
						delete(updated.Annotations, k)
					}
				}
				if equality.Semantic.DeepEqual(service, updated) {
					return nil
				}

				t.Logf("updating Service to remove annotations: %v", annotations)
				_, err = adminClient.CoreV1().Services(env.ConciergeNamespace).Update(ctx, updated, metav1.UpdateOptions{})
				return err
			}))
		}

		applyCredentialIssuerAnnotations := func(annotations map[string]string) {
			require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
				issuer, err := adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Get(ctx, credentialIssuerName(env), metav1.GetOptions{})
				if err != nil {
					return err
				}
				updated := issuer.DeepCopy()
				updated.Spec.ImpersonationProxy.Service.Annotations = annotations
				if equality.Semantic.DeepEqual(issuer, updated) {
					return nil
				}

				t.Logf("updating CredentialIssuer with spec.impersonationProxy.service.annotations: %v", annotations)
				_, err = adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Update(ctx, updated, metav1.UpdateOptions{})
				return err
			}))
		}

		waitForServiceAnnotations := func(wantAnnotations map[string]string, annotationKeyFilter string) {
			testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
				service, err := adminClient.CoreV1().Services(env.ConciergeNamespace).Get(ctx, impersonationProxyLoadBalancerName(env), metav1.GetOptions{})
				if err != nil {
					return false, err
				}
				filteredActualAnnotations := map[string]string{}
				for k, v := range service.Annotations {
					// We do want to pay attention to any annotation for which we intend to make an explicit assertion,
					// e.g. "service.beta.kubernetes.io/aws-load-balancer-connection-idle-timeout" which is from our
					// default CredentialIssuer spec.
					_, wantToMakeAssertionOnThisAnnotation := wantAnnotations[k]
					// We do not want to pay attention to Service annotations added by other controllers,
					// e.g. the "cloud.google.com/neg" annotation that is sometimes added by GKE on Services.
					// These can come and go in time intervals outside of our control.
					annotationContainsFilterString := strings.Contains(k, annotationKeyFilter)
					if wantToMakeAssertionOnThisAnnotation || annotationContainsFilterString {
						filteredActualAnnotations[k] = v
					}
				}
				t.Logf("found Service %s of type %s with actual annotations %q; filtered by interesting keys results in %q; expected annotations %q",
					service.Name, service.Spec.Type, service.Annotations, filteredActualAnnotations, wantAnnotations)
				return equality.Semantic.DeepEqual(filteredActualAnnotations, wantAnnotations), nil
			}, 1*time.Minute, 1*time.Second)
		}

		expectedAnnotations := func(credentialIssuerSpecAnnotations map[string]string, otherAnnotations map[string]string) map[string]string {
			credentialIssuerSpecAnnotationKeys := []string{}
			expectedAnnotations := map[string]string{}
			// Expect the annotations specified on the CredentialIssuer spec to be present.
			for k, v := range credentialIssuerSpecAnnotations {
				credentialIssuerSpecAnnotationKeys = append(credentialIssuerSpecAnnotationKeys, k)
				expectedAnnotations[k] = v
			}
			// Aside from the annotations requested on the CredentialIssuer spec, also expect the other annotation to still be there too.
			for k, v := range otherAnnotations {
				expectedAnnotations[k] = v
			}
			// Also expect the internal bookkeeping annotation to be present. It tracks the requested keys from the spec.
			// Our controller sorts these keys to make the order in the annotation's value predictable.
			sort.Strings(credentialIssuerSpecAnnotationKeys)
			credentialIssuerSpecAnnotationKeysJSON, err := json.Marshal(credentialIssuerSpecAnnotationKeys)
			require.NoError(t, err)
			// The name of this annotation key is decided by our controller.
			expectedAnnotations["credentialissuer."+recognizableAnnotationKeyString+"/annotation-keys"] = string(credentialIssuerSpecAnnotationKeysJSON)
			return expectedAnnotations
		}

		otherActorAnnotations := map[string]string{
			recognizableAnnotationKeyString + "/test-other-actor-" + testlib.RandHex(t, 8): "test-other-actor-" + testlib.RandHex(t, 8),
		}

		// Whatever happens, set the annotations back to the original value and expect the Service to be updated.
		t.Cleanup(func() {
			t.Log("reverting CredentialIssuer back to previous configuration")
			deleteServiceAnnotations(otherActorAnnotations)
			applyCredentialIssuerAnnotations(previous.Spec.ImpersonationProxy.Service.DeepCopy().Annotations)
			waitForServiceAnnotations(
				expectedAnnotations(previous.Spec.ImpersonationProxy.Service.DeepCopy().Annotations, map[string]string{}),
				recognizableAnnotationKeyString,
			)
		})

		// Having another actor, like a human or a non-Pinniped controller, add unrelated annotations to the Service
		// should not cause the Pinniped controllers to overwrite those annotations.
		updateServiceAnnotations(otherActorAnnotations)

		// Set a new annotation in the CredentialIssuer spec.impersonationProxy.service.annotations field.
		newAnnotationKey := recognizableAnnotationKeyString + "/test-" + testlib.RandHex(t, 8)
		newAnnotationValue := "test-" + testlib.RandHex(t, 8)
		updatedAnnotations := previous.Spec.ImpersonationProxy.Service.DeepCopy().Annotations
		updatedAnnotations[newAnnotationKey] = newAnnotationValue
		applyCredentialIssuerAnnotations(updatedAnnotations)

		// Expect them to be applied to the Service.
		waitForServiceAnnotations(
			expectedAnnotations(updatedAnnotations, otherActorAnnotations),
			recognizableAnnotationKeyString,
		)
	})

	t.Run("running impersonation proxy with ClusterIP service", func(t *testing.T) {
		if env.Proxy == "" {
			t.Skip("Skipping ClusterIP test because squid proxy is not present")
		}
		clusterIPServiceURL := fmt.Sprintf("%s.%s.svc.cluster.local", impersonationProxyClusterIPName(env), env.ConciergeNamespace)
		updateCredentialIssuer(ctx, t, env, adminConciergeClient, conciergeconfigv1alpha1.CredentialIssuerSpec{
			ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
				Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
				ExternalEndpoint: clusterIPServiceURL,
				Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
					Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP,
				},
			},
		})

		// wait until the credential issuer is updated with the new url
		testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
			newImpersonationProxyURL, _ := performImpersonatorDiscoveryURL(ctx, t, env, adminConciergeClient)
			return newImpersonationProxyURL == "https://"+clusterIPServiceURL, nil
		}, 30*time.Second, 500*time.Millisecond)
		newImpersonationProxyURL, newImpersonationProxyCACertPEM := performImpersonatorDiscovery(ctx, t, env, adminClient, adminConciergeClient, refreshCredential)

		anonymousClient := newAnonymousImpersonationProxyClientWithProxy(t, newImpersonationProxyURL, newImpersonationProxyCACertPEM, nil).PinnipedConcierge
		refreshedCredentials := refreshCredentialHelper(t, anonymousClient)

		client := newImpersonationProxyClientWithCredentialsAndProxy(t, refreshedCredentials, newImpersonationProxyURL, newImpersonationProxyCACertPEM, nil).Kubernetes

		// everything should work properly through the cluster ip service
		t.Run(
			"access as user",
			testlib.AccessAsUserTest(ctx, env.TestUser.ExpectedUsername, client),
		)
	})

	t.Run("using externally provided TLS serving cert with stringData", func(t *testing.T) {
		var externallyProvidedCA *certauthority.CA
		externallyProvidedCA, err = certauthority.New("Impersonation Proxy Integration Test CA", 1*time.Hour)
		require.NoError(t, err)

		externallyProvidedTLSServingCertPEM, err := externallyProvidedCA.IssueServerCertPEM([]string{proxyServiceEndpoint}, nil, 1*time.Hour)
		require.NoError(t, err)

		// Specifically use corev1.Secret.StringData
		// https://kubernetes.io/docs/tasks/configmap-secret/managing-secret-using-config-file/#create-the-config-file
		externallyProvidedTLSServingCertSecret := testlib.CreateTestSecret(
			t,
			env.ConciergeNamespace,
			"external-tls-cert-secret-name",
			corev1.SecretTypeTLS,
			map[string]string{
				"ca.crt":                string(externallyProvidedCA.Bundle()),
				corev1.TLSCertKey:       string(externallyProvidedTLSServingCertPEM.CertPEM),
				corev1.TLSPrivateKeyKey: string(externallyProvidedTLSServingCertPEM.KeyPEM),
			})

		_, originalInternallyGeneratedCAPEM := performImpersonatorDiscoveryURL(ctx, t, env, adminConciergeClient)

		t.Cleanup(func() {
			// Remove the TLS block from the CredentialIssuer, which should revert the ImpersonationProxy to using an
			// internally generated TLS serving cert derived from the original CA.
			updateCredentialIssuer(ctx, t, env, adminConciergeClient, conciergeconfigv1alpha1.CredentialIssuerSpec{
				ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
					Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
					ExternalEndpoint: proxyServiceEndpoint,
					Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
						Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP,
					},
				},
			})

			// Wait for the CredentialIssuer's impersonation proxy frontend strategy to be updated to the original CA bundle
			testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
				_, impersonationProxyCACertPEM = performImpersonatorDiscoveryURL(ctx, t, env, adminConciergeClient)

				return bytes.Equal(impersonationProxyCACertPEM, originalInternallyGeneratedCAPEM), nil
			}, 2*time.Minute, 500*time.Millisecond)
		})

		updateCredentialIssuer(ctx, t, env, adminConciergeClient, conciergeconfigv1alpha1.CredentialIssuerSpec{
			ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
				Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
				ExternalEndpoint: proxyServiceEndpoint,
				Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
					Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP,
				},
				TLS: &conciergeconfigv1alpha1.ImpersonationProxyTLSSpec{
					CertificateAuthorityData: base64.StdEncoding.EncodeToString(externallyProvidedCA.Bundle()),
					SecretName:               externallyProvidedTLSServingCertSecret.Name,
				},
			},
		})

		// Wait for the CredentialIssuer's impersonation proxy frontend strategy to be updated with the right CA bundle
		testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
			_, impersonationProxyCACertPEM = performImpersonatorDiscoveryURL(ctx, t, env, adminConciergeClient)
			return bytes.Equal(impersonationProxyCACertPEM, externallyProvidedCA.Bundle()), nil
		}, 2*time.Minute, 500*time.Millisecond)

		// Do a login via performImpersonatorDiscovery
		testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
			_, newImpersonationProxyCACertPEM := performImpersonatorDiscovery(ctx, t, env, adminClient, adminConciergeClient, refreshCredential)
			return bytes.Equal(newImpersonationProxyCACertPEM, externallyProvidedCA.Bundle()), err
		}, 2*time.Minute, 500*time.Millisecond)
	})

	t.Run("using externally provided TLS serving cert with data []byte arrays", func(t *testing.T) {
		var externallyProvidedCA *certauthority.CA
		externallyProvidedCA, err = certauthority.New("Impersonation Proxy Integration Test CA", 1*time.Hour)
		require.NoError(t, err)

		externallyProvidedTLSServingCertPEM, err := externallyProvidedCA.IssueServerCertPEM([]string{proxyServiceEndpoint}, nil, 1*time.Hour)
		require.NoError(t, err)

		// Specifically use corev1.Secret.Data
		// https://kubernetes.io/docs/tasks/configmap-secret/managing-secret-using-config-file/#create-the-config-file
		externallyProvidedTLSServingCertSecret := testlib.CreateTestSecretBytes(
			t,
			env.ConciergeNamespace,
			"external-tls-cert-secret-name-integration-tests",
			corev1.SecretTypeTLS,
			map[string][]byte{
				"ca.crt":                externallyProvidedCA.Bundle(),
				corev1.TLSCertKey:       externallyProvidedTLSServingCertPEM.CertPEM,
				corev1.TLSPrivateKeyKey: externallyProvidedTLSServingCertPEM.KeyPEM,
			})

		_, originalInternallyGeneratedCAPEM := performImpersonatorDiscoveryURL(ctx, t, env, adminConciergeClient)

		t.Cleanup(func() {
			// Remove the TLS block from the CredentialIssuer, which should revert the ImpersonationProxy to using an
			// internally generated TLS serving cert derived from the original CA.
			updateCredentialIssuer(ctx, t, env, adminConciergeClient, conciergeconfigv1alpha1.CredentialIssuerSpec{
				ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
					Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
					ExternalEndpoint: proxyServiceEndpoint,
					Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
						Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP,
					},
				},
			})

			// Wait for the CredentialIssuer's impersonation proxy frontend strategy to be updated to the original CA bundle
			testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
				_, impersonationProxyCACertPEM = performImpersonatorDiscoveryURL(ctx, t, env, adminConciergeClient)

				return bytes.Equal(impersonationProxyCACertPEM, originalInternallyGeneratedCAPEM), nil
			}, 2*time.Minute, 500*time.Millisecond)
		})

		updateCredentialIssuer(ctx, t, env, adminConciergeClient, conciergeconfigv1alpha1.CredentialIssuerSpec{
			ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
				Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
				ExternalEndpoint: proxyServiceEndpoint,
				Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
					Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP,
				},
				TLS: &conciergeconfigv1alpha1.ImpersonationProxyTLSSpec{
					CertificateAuthorityData: base64.StdEncoding.EncodeToString(externallyProvidedCA.Bundle()),
					SecretName:               externallyProvidedTLSServingCertSecret.Name,
				},
			},
		})

		// Wait for the CredentialIssuer's impersonation proxy frontend strategy to be updated with the right CA bundle
		testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
			_, impersonationProxyCACertPEM = performImpersonatorDiscoveryURL(ctx, t, env, adminConciergeClient)
			return bytes.Equal(impersonationProxyCACertPEM, externallyProvidedCA.Bundle()), nil
		}, 2*time.Minute, 500*time.Millisecond)

		// Do a login via performImpersonatorDiscovery
		testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
			_, newImpersonationProxyCACertPEM := performImpersonatorDiscovery(ctx, t, env, adminClient, adminConciergeClient, refreshCredential)
			return bytes.Equal(newImpersonationProxyCACertPEM, externallyProvidedCA.Bundle()), err
		}, 2*time.Minute, 500*time.Millisecond)
	})

	t.Run("manually disabling the impersonation proxy feature", func(t *testing.T) {
		// Update configuration to force the proxy to disabled mode
		updateCredentialIssuer(ctx, t, env, adminConciergeClient, conciergeconfigv1alpha1.CredentialIssuerSpec{
			ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
				Mode: conciergeconfigv1alpha1.ImpersonationProxyModeDisabled,
			},
		})

		if clusterSupportsLoadBalancers {
			// The load balancer should have been deleted when we disabled the impersonation proxy.
			// Note that this can take kind of a long time on real cloud providers (e.g. ~22 seconds on EKS).
			testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
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
			testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
				// It's okay if this returns RBAC errors because this user has no role bindings.
				// What we want to see is that the proxy eventually shuts down entirely.
				_, err := impersonationProxyViaSquidKubeClientWithoutCredential(t, proxyServiceEndpoint).CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
				isErr, _ := isServiceUnavailableViaSquidError(err, proxyServiceEndpoint)
				requireEventually.Truef(isErr, "wanted service unavailable via squid error, got %v", err)
			}, 20*time.Second, 500*time.Millisecond)
		}

		// Check that the generated TLS cert Secret was deleted by the controller because it's supposed to clean this up
		// when we disable the impersonator.
		testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
			_, err := adminClient.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyTLSSecretName(env), metav1.GetOptions{})
			requireEventually.Truef(apierrors.IsNotFound(err), "expected NotFound error, got %v", err)
		}, 2*time.Minute, time.Second)

		// Check that the generated CA cert Secret was not deleted by the controller because it's supposed to keep this
		// around in case we decide to later re-enable the impersonator. We want to avoid generating new CA certs when
		// possible because they make their way into kubeconfigs on client machines.
		_, err := adminClient.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, impersonationProxyCASecretName(env), metav1.GetOptions{})
		require.NoError(t, err)

		// At this point the impersonator should be stopped. The CredentialIssuer's strategies array should be updated to
		// include an unsuccessful impersonation strategy saying that it was manually configured to be disabled.
		requireDisabledStrategy(ctx, t, env, adminConciergeClient)

		if !env.HasCapability(testlib.ClusterSigningKeyIsAvailable) && env.HasCapability(testlib.AnonymousAuthenticationSupported) {
			// This cluster does not support the cluster signing key strategy, so now that we've manually disabled the
			// impersonation strategy, we should be left with no working strategies.
			// Given that there are no working strategies, a TokenCredentialRequest which would otherwise work should now
			// fail, because there is no point handing out credentials that are not going to work for any strategy.
			// Note that library.CreateTokenCredentialRequest makes an unauthenticated request, so we can't meaningfully
			// perform this part of the test on a cluster which does not allow anonymous authentication.
			tokenCredentialRequestResponse, err := testlib.CreateTokenCredentialRequest(ctx, t, credentialRequestSpecWithWorkingCredentials)
			require.NoError(t, err, testlib.Sdump(err))

			require.NotNil(t, tokenCredentialRequestResponse.Status.Message, "expected an error message but got nil")
			require.Equal(t, "authentication failed", *tokenCredentialRequestResponse.Status.Message)
			require.Nil(t, tokenCredentialRequestResponse.Status.Credential)
		}
	})
}

func ensureDNSResolves(t *testing.T, urlString string) {
	t.Helper()

	parsedURL, err := url.Parse(urlString)
	require.NoError(t, err)

	host := parsedURL.Hostname()

	if net.ParseIP(host) != nil {
		return // ignore IPs
	}

	var d net.Dialer
	loggingDialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		t.Logf("dns lookup, network=%s address=%s", network, address)
		conn, connErr := d.DialContext(ctx, network, address)
		if connErr != nil {
			t.Logf("dns lookup, err=%v", connErr)
		} else {
			local := conn.LocalAddr()
			remote := conn.RemoteAddr()
			t.Logf("dns lookup, local conn network=%s addr=%s", local.Network(), local.String())
			t.Logf("dns lookup, remote conn network=%s addr=%s", remote.Network(), remote.String())
		}
		return conn, connErr
	}

	goResolver := &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial:         loggingDialer,
	}
	notGoResolver := &net.Resolver{
		PreferGo:     false,
		StrictErrors: true,
		Dial:         loggingDialer,
	}

	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		for _, resolver := range []*net.Resolver{goResolver, notGoResolver} {
			ips, ipErr := resolver.LookupIPAddr(ctx, host)
			requireEventually.NoError(ipErr)
			requireEventually.NotEmpty(ips)
		}
	}, 5*time.Minute, 1*time.Second)
}

func createServiceAccountToken(ctx context.Context, t *testing.T, adminClient kubernetes.Interface, namespaceName string) (name, token string, uid types.UID) {
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

	testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
		secret, err = adminClient.CoreV1().Secrets(namespaceName).Get(ctx, secret.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return len(secret.Data[corev1.ServiceAccountTokenKey]) > 0, nil
	}, time.Minute, time.Second)

	return serviceAccount.Name, string(secret.Data[corev1.ServiceAccountTokenKey]), serviceAccount.UID
}

func expectedWhoAmIRequestResponse(username string, groups []string, extra map[string]identityv1alpha1.ExtraValue) *identityv1alpha1.WhoAmIRequest {
	return &identityv1alpha1.WhoAmIRequest{
		Status: identityv1alpha1.WhoAmIRequestStatus{
			KubernetesUserInfo: identityv1alpha1.KubernetesUserInfo{
				User: identityv1alpha1.UserInfo{
					Username: username,
					UID:      "", // no way to impersonate UID: https://github.com/kubernetes/kubernetes/issues/93699
					Groups:   groups,
					Extra:    extra,
				},
			},
		},
	}
}

func performImpersonatorDiscovery(ctx context.Context, t *testing.T, env *testlib.TestEnv,
	adminClient kubernetes.Interface, adminConciergeClient conciergeclientset.Interface,
	refreshCredential func(t *testing.T, impersonationProxyURL string, impersonationProxyCACertPEM []byte) *loginv1alpha1.ClusterCredential) (string, []byte) {
	t.Helper()

	impersonationProxyURL, impersonationProxyCACertPEM := performImpersonatorDiscoveryURL(ctx, t, env, adminConciergeClient)

	if len(env.Proxy) == 0 {
		t.Log("no test proxy is available, skipping readiness checks for concierge impersonation proxy pods")
		return impersonationProxyURL, impersonationProxyCACertPEM
	}

	impersonationProxyParsedURL, err := url.Parse(impersonationProxyURL)
	require.NoError(t, err)

	expectedGroups := make([]string, 0, len(env.TestUser.ExpectedGroups)+1) // make sure we do not mutate env.TestUser.ExpectedGroups
	expectedGroups = slices.Concat(expectedGroups, env.TestUser.ExpectedGroups)
	expectedGroups = append(expectedGroups, "system:authenticated")

	// probe each pod directly for readiness since the concierge status is a lie - it just means a single pod is ready
	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		pods, err := adminClient.CoreV1().Pods(env.ConciergeNamespace).List(ctx,
			metav1.ListOptions{LabelSelector: "deployment.pinniped.dev=concierge"})
		requireEventually.NoError(err)
		requireEventually.Len(pods.Items, 2) // has to stay in sync with the defaults in our YAML

		for _, pod := range pods.Items {
			t.Logf("checking if concierge impersonation proxy pod %q is ready", pod.Name)

			requireEventually.NotEmptyf(pod.Status.PodIP, "pod %q does not have an IP", pod.Name)

			credentials := refreshCredential(t, impersonationProxyURL, impersonationProxyCACertPEM).DeepCopy()
			credentials.Token = "not a valid token" // demonstrates that client certs take precedence over tokens by setting both on the requests

			config := newImpersonationProxyConfigWithCredentials(t, credentials, impersonationProxyURL, impersonationProxyCACertPEM, nil)
			config = rest.CopyConfig(config)
			config.Proxy = kubeconfigProxyFunc(t, env.Proxy)           // always use the proxy since we are talking directly to a pod IP
			config.Host = "https://" + pod.Status.PodIP + ":8444"      // hardcode the internal port - it should not change
			config.ServerName = impersonationProxyParsedURL.Hostname() // make SNI hostname TLS verification work even when using IP

			whoAmI, err := testlib.NewKubeclient(t, config).PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
				Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
			requireEventually.NoError(err)
			requireEventually.Equal(
				expectedWhoAmIRequestResponse(
					env.TestUser.ExpectedUsername,
					expectedGroups,
					nil,
				),
				whoAmI,
			)
		}
	}, 10*time.Minute, 10*time.Second)

	return impersonationProxyURL, impersonationProxyCACertPEM
}

func performImpersonatorDiscoveryURL(ctx context.Context, t *testing.T, env *testlib.TestEnv, adminConciergeClient conciergeclientset.Interface) (string, []byte) {
	t.Helper()

	var impersonationProxyURL string
	var impersonationProxyCACertPEM []byte

	t.Log("Waiting for CredentialIssuer strategy to be successful")

	testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
		credentialIssuer, err := adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Get(ctx, credentialIssuerName(env), metav1.GetOptions{})
		if err != nil || credentialIssuer.Status.Strategies == nil {
			t.Log("Did not find any CredentialIssuer with any strategies")
			return false, nil // didn't find it, but keep trying
		}
		for _, strategy := range credentialIssuer.Status.Strategies {
			// There will be other strategy types in the list, so ignore those.
			if strategy.Type == conciergeconfigv1alpha1.ImpersonationProxyStrategyType && strategy.Status == conciergeconfigv1alpha1.SuccessStrategyStatus { //nolint:nestif
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
			} else if strategy.Type == conciergeconfigv1alpha1.ImpersonationProxyStrategyType {
				t.Logf("Waiting for successful impersonation proxy strategy on %s: found status %s with reason %s and message: %s",
					credentialIssuerName(env), strategy.Status, strategy.Reason, strategy.Message)
				if strategy.Reason == conciergeconfigv1alpha1.ErrorDuringSetupStrategyReason {
					// The server encountered an unexpected error while starting the impersonator, so fail the test fast.
					return false, fmt.Errorf("found impersonation strategy in %s state with message: %s", strategy.Reason, strategy.Message)
				}
			}
		}
		t.Log("Did not find any successful impersonation proxy strategy on CredentialIssuer")
		return false, nil // didn't find it, but keep trying
	}, 10*time.Minute, 10*time.Second)

	t.Log("Found successful CredentialIssuer strategy")
	return impersonationProxyURL, impersonationProxyCACertPEM
}

func requireDisabledStrategy(ctx context.Context, t *testing.T, env *testlib.TestEnv, adminConciergeClient conciergeclientset.Interface) {
	t.Helper()

	testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
		credentialIssuer, err := adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Get(ctx, credentialIssuerName(env), metav1.GetOptions{})
		if err != nil || credentialIssuer.Status.Strategies == nil {
			t.Log("Did not find any CredentialIssuer with any strategies")
			return false, nil // didn't find it, but keep trying
		}
		for _, strategy := range credentialIssuer.Status.Strategies {
			// There will be other strategy types in the list, so ignore those.
			if strategy.Type == conciergeconfigv1alpha1.ImpersonationProxyStrategyType &&
				strategy.Status == conciergeconfigv1alpha1.ErrorStrategyStatus &&
				strategy.Reason == conciergeconfigv1alpha1.DisabledStrategyReason {
				return true, nil // found it, continue the test!
			} else if strategy.Type == conciergeconfigv1alpha1.ImpersonationProxyStrategyType {
				t.Logf("Waiting for disabled impersonation proxy strategy on %s: found status %s with reason %s and message: %s",
					credentialIssuerName(env), strategy.Status, strategy.Reason, strategy.Message)
				if strategy.Reason == conciergeconfigv1alpha1.ErrorDuringSetupStrategyReason {
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

func impersonationProxyRestConfig(credential *loginv1alpha1.ClusterCredential, host string, caData []byte, nestedImpersonationConfig *rest.ImpersonationConfig) *rest.Config {
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
	if nestedImpersonationConfig != nil {
		config.Impersonate = *nestedImpersonationConfig
	}
	return &config
}

func kubeconfigProxyFunc(t *testing.T, squidProxyURL string) func(req *http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		t.Helper()

		parsedSquidProxyURL, err := url.Parse(squidProxyURL)
		require.NoError(t, err)
		t.Logf("passing request for %s through proxy %s", testlib.RedactURLParams(req.URL), parsedSquidProxyURL.String())
		return parsedSquidProxyURL, nil
	}
}

func updateCredentialIssuer(ctx context.Context, t *testing.T, env *testlib.TestEnv, adminConciergeClient conciergeclientset.Interface, spec conciergeconfigv1alpha1.CredentialIssuerSpec) {
	t.Helper()

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		newCredentialIssuer, err := adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Get(ctx, credentialIssuerName(env), metav1.GetOptions{})
		if err != nil {
			return err
		}

		spec.DeepCopyInto(&newCredentialIssuer.Spec)
		_, err = adminConciergeClient.ConfigV1alpha1().CredentialIssuers().Update(ctx, newCredentialIssuer, metav1.UpdateOptions{})
		return err
	})
	require.NoError(t, err)
}

func hasImpersonationProxyLoadBalancerService(ctx context.Context, env *testlib.TestEnv, client kubernetes.Interface) (bool, error) {
	service, err := client.CoreV1().Services(env.ConciergeNamespace).Get(ctx, impersonationProxyLoadBalancerName(env), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return service.Spec.Type == corev1.ServiceTypeLoadBalancer, nil
}

func impersonationProxyTLSSecretName(env *testlib.TestEnv) string {
	return env.ConciergeAppName + "-impersonation-proxy-tls-serving-certificate"
}

func impersonationProxyCASecretName(env *testlib.TestEnv) string {
	return env.ConciergeAppName + "-impersonation-proxy-ca-certificate"
}

func impersonationProxyLoadBalancerName(env *testlib.TestEnv) string {
	return env.ConciergeAppName + "-impersonation-proxy-load-balancer"
}

func impersonationProxyClusterIPName(env *testlib.TestEnv) string {
	return env.ConciergeAppName + "-impersonation-proxy-cluster-ip"
}

func credentialIssuerName(env *testlib.TestEnv) string {
	return env.ConciergeAppName + "-config"
}

func getImpersonationKubeconfig(t *testing.T, env *testlib.TestEnv, impersonationProxyURL string, impersonationProxyCACertPEM []byte, authenticator corev1.TypedLocalObjectReference) (string, []string, string) {
	t.Helper()

	pinnipedExe := testlib.PinnipedCLIPath(t)
	tempDir := t.TempDir()

	var envVarsWithProxy []string
	if !env.HasCapability(testlib.HasExternalLoadBalancerProvider) {
		// Only if you don't have a load balancer, use the squid proxy when it's available.
		envVarsWithProxy = slices.Concat(os.Environ(), env.ProxyEnv())
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
	require.NoError(t, os.WriteFile(kubeconfigPath, []byte(kubeconfigYAML), 0600))

	return kubeconfigPath, envVarsWithProxy, tempDir
}

// func to create kubectl commands with a kubeconfig.
func kubectlCommand(timeout context.Context, t *testing.T, kubeconfigPath string, envVarsWithProxy []string, args ...string) (*exec.Cmd, *syncBuffer, *syncBuffer) {
	t.Helper()

	allArgs := slices.Concat([]string{"--kubeconfig", kubeconfigPath}, args)
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
	client conciergeclientset.Interface,
) (*loginv1alpha1.TokenCredentialRequest, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return client.LoginV1alpha1().TokenCredentialRequests().Create(ctx,
		&loginv1alpha1.TokenCredentialRequest{Spec: spec}, metav1.CreateOptions{},
	)
}

func newImpersonationProxyClientWithCredentials(t *testing.T, credentials *loginv1alpha1.ClusterCredential, impersonationProxyURL string, impersonationProxyCACertPEM []byte, nestedImpersonationConfig *rest.ImpersonationConfig) *kubeclient.Client {
	t.Helper()

	kubeconfig := newImpersonationProxyConfigWithCredentials(t, credentials, impersonationProxyURL, impersonationProxyCACertPEM, nestedImpersonationConfig)
	return testlib.NewKubeclient(t, kubeconfig)
}

func newImpersonationProxyConfigWithCredentials(t *testing.T, credentials *loginv1alpha1.ClusterCredential, impersonationProxyURL string, impersonationProxyCACertPEM []byte, nestedImpersonationConfig *rest.ImpersonationConfig) *rest.Config {
	t.Helper()

	env := testlib.IntegrationEnv(t)
	clusterSupportsLoadBalancers := env.HasCapability(testlib.HasExternalLoadBalancerProvider)

	kubeconfig := impersonationProxyRestConfig(credentials, impersonationProxyURL, impersonationProxyCACertPEM, nestedImpersonationConfig)
	if !clusterSupportsLoadBalancers {
		// Only if there is no possibility to send traffic through a load balancer, then send the traffic through the Squid proxy.
		// Prefer to go through a load balancer because that's how the impersonator is intended to be used in the real world.
		kubeconfig.Proxy = kubeconfigProxyFunc(t, env.Proxy)
	}
	return kubeconfig
}

func newAnonymousImpersonationProxyClient(t *testing.T, impersonationProxyURL string, impersonationProxyCACertPEM []byte, nestedImpersonationConfig *rest.ImpersonationConfig) *kubeclient.Client {
	t.Helper()

	emptyCredentials := &loginv1alpha1.ClusterCredential{}
	return newImpersonationProxyClientWithCredentials(t, emptyCredentials, impersonationProxyURL, impersonationProxyCACertPEM, nestedImpersonationConfig)
}

func newImpersonationProxyClientWithCredentialsAndProxy(t *testing.T, credentials *loginv1alpha1.ClusterCredential, impersonationProxyURL string, impersonationProxyCACertPEM []byte, nestedImpersonationConfig *rest.ImpersonationConfig) *kubeclient.Client {
	t.Helper()

	env := testlib.IntegrationEnv(t)

	kubeconfig := impersonationProxyRestConfig(credentials, impersonationProxyURL, impersonationProxyCACertPEM, nestedImpersonationConfig)
	kubeconfig.Proxy = kubeconfigProxyFunc(t, env.Proxy)
	return testlib.NewKubeclient(t, kubeconfig)
}

// this uses a proxy in all cases, the other will only use it if you don't have load balancer capabilities.
func newAnonymousImpersonationProxyClientWithProxy(t *testing.T, impersonationProxyURL string, impersonationProxyCACertPEM []byte, nestedImpersonationConfig *rest.ImpersonationConfig) *kubeclient.Client {
	t.Helper()
	env := testlib.IntegrationEnv(t)

	emptyCredentials := &loginv1alpha1.ClusterCredential{}
	kubeconfig := impersonationProxyRestConfig(emptyCredentials, impersonationProxyURL, impersonationProxyCACertPEM, nestedImpersonationConfig)

	kubeconfig.Proxy = kubeconfigProxyFunc(t, env.Proxy)

	return testlib.NewKubeclient(t, kubeconfig)
}

func impersonationProxyViaSquidKubeClientWithoutCredential(t *testing.T, proxyServiceEndpoint string) kubernetes.Interface {
	t.Helper()

	env := testlib.IntegrationEnv(t)
	proxyURL := "https://" + proxyServiceEndpoint
	kubeconfig := impersonationProxyRestConfig(&loginv1alpha1.ClusterCredential{}, proxyURL, nil, nil)
	kubeconfig.Proxy = kubeconfigProxyFunc(t, env.Proxy)
	return testlib.NewKubeclient(t, kubeconfig).Kubernetes
}

func newImpersonationProxyClient(
	t *testing.T,
	impersonationProxyURL string,
	impersonationProxyCACertPEM []byte,
	nestedImpersonationConfig *rest.ImpersonationConfig,
	refreshCredentialFunc func(t *testing.T, impersonationProxyURL string, impersonationProxyCACertPEM []byte) *loginv1alpha1.ClusterCredential,
) *kubeclient.Client {
	t.Helper()

	refreshedCredentials := refreshCredentialFunc(t, impersonationProxyURL, impersonationProxyCACertPEM).DeepCopy()
	refreshedCredentials.Token = "not a valid token" // demonstrates that client certs take precedence over tokens by setting both on the requests
	return newImpersonationProxyClientWithCredentials(t, refreshedCredentials, impersonationProxyURL, impersonationProxyCACertPEM, nestedImpersonationConfig)
}

// getCredForConfig is mostly just a hacky workaround for impersonationProxyRestConfig needing creds directly.
func getCredForConfig(t *testing.T, config *rest.Config) *loginv1alpha1.ClusterCredential {
	t.Helper()

	out := &loginv1alpha1.ClusterCredential{}

	config = rest.CopyConfig(config)

	config.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return roundtripper.WrapFunc(rt, func(req *http.Request) (*http.Response, error) {
			resp, err := rt.RoundTrip(req)

			r := req
			if resp != nil && resp.Request != nil {
				r = resp.Request
			}

			_, _, _ = bearertoken.New(authenticator.TokenFunc(func(_ context.Context, token string) (*authenticator.Response, bool, error) {
				out.Token = token
				return nil, false, nil
			})).AuthenticateRequest(r)

			return resp, err
		})
	})

	transportConfig, err := config.TransportConfig()
	require.NoError(t, err)

	rt, err := transport.New(transportConfig)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://localhost", nil)
	require.NoError(t, err)
	resp, _ := rt.RoundTrip(req)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}

	tlsConfig, err := transport.TLSConfigFor(transportConfig)
	require.NoError(t, err)

	if tlsConfig != nil && tlsConfig.GetClientCertificate != nil {
		cert, err := tlsConfig.GetClientCertificate(nil)
		require.NoError(t, err)
		if len(cert.Certificate) > 0 {
			require.Len(t, cert.Certificate, 1)
			publicKey := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Certificate[0],
			})
			out.ClientCertificateData = string(publicKey)

			privateKey, err := keyutil.MarshalPrivateKeyToPEM(cert.PrivateKey)
			require.NoError(t, err)
			out.ClientKeyData = string(privateKey)
		}
	}

	if *out == (loginv1alpha1.ClusterCredential{}) {
		t.Fatal("failed to get creds for config")
	}

	return out
}

func getUIDAndExtraViaCSR(ctx context.Context, t *testing.T, uid string, client kubernetes.Interface) (string, map[string][]string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csrPEM, err := cert.MakeCSR(privateKey, &pkix.Name{
		CommonName:   "panda-man",
		Organization: []string{"living-the-dream", "need-more-sleep"},
	}, nil, nil)
	require.NoError(t, err)

	csrName, _, err := csr.RequestCertificate(
		client,
		csrPEM,
		"",
		certificatesv1.KubeAPIServerClientSignerName,
		nil,
		[]certificatesv1.KeyUsage{certificatesv1.UsageClientAuth},
		privateKey,
	)
	require.NoError(t, err)

	outUID := uid // in the future this may not be empty on some clusters
	extrasAsStrings := map[string][]string{}

	if testutil.KubeServerSupportsCertificatesV1API(t, client.Discovery()) {
		csReq, err := client.CertificatesV1().CertificateSigningRequests().Get(ctx, csrName, metav1.GetOptions{})
		require.NoError(t, err)

		err = client.CertificatesV1().CertificateSigningRequests().Delete(ctx, csrName, metav1.DeleteOptions{})
		require.NoError(t, err)

		if len(outUID) == 0 {
			outUID = csReq.Spec.UID
		}

		// Convert each `ExtraValue` to `[]string` to return, so we don't have to deal with v1beta1 types versus v1 types
		for k, v := range csReq.Spec.Extra {
			extrasAsStrings[k] = v
		}
	} else {
		// On old Kubernetes clusters use CertificatesV1beta1
		csReq, err := client.CertificatesV1beta1().CertificateSigningRequests().Get(ctx, csrName, metav1.GetOptions{})
		require.NoError(t, err)

		err = client.CertificatesV1beta1().CertificateSigningRequests().Delete(ctx, csrName, metav1.DeleteOptions{})
		require.NoError(t, err)

		if len(outUID) == 0 {
			outUID = csReq.Spec.UID
		}

		// Convert each `ExtraValue` to `[]string` to return, so we don't have to deal with v1beta1 types versus v1 types
		for k, v := range csReq.Spec.Extra {
			extrasAsStrings[k] = v
		}
	}

	return outUID, extrasAsStrings
}

func parallelIfNotEKS(t *testing.T) {
	if testlib.IntegrationEnv(t).KubernetesDistribution == testlib.EKSDistro {
		return
	}

	t.Parallel()
}
