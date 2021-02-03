// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package library

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	auth1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/authentication/v1alpha1"
	configv1alpha1 "go.pinniped.dev/generated/1.20/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/1.20/apis/supervisor/idp/v1alpha1"
	conciergeclientset "go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned"
	supervisorclientset "go.pinniped.dev/generated/1.20/client/supervisor/clientset/versioned"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/kubeclient"

	// Import to initialize client auth plugins - the kubeconfig that we use for
	// testing may use gcloud, az, oidc, etc.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func NewClientConfig(t *testing.T) *rest.Config {
	t.Helper()

	return newClientConfigWithOverrides(t, &clientcmd.ConfigOverrides{})
}

func NewClientsetForKubeConfig(t *testing.T, kubeConfig string) kubernetes.Interface {
	t.Helper()
	return newClientsetWithConfig(t, NewRestConfigFromKubeconfig(t, kubeConfig))
}

func NewRestConfigFromKubeconfig(t *testing.T, kubeConfig string) *rest.Config {
	kubeConfigFile, err := ioutil.TempFile("", "pinniped-cli-test-*")
	require.NoError(t, err)
	defer os.Remove(kubeConfigFile.Name())

	_, err = kubeConfigFile.Write([]byte(kubeConfig))
	require.NoError(t, err)

	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile.Name())
	require.NoError(t, err)
	return restConfig
}

func NewClientsetWithCertAndKey(t *testing.T, clientCertificateData, clientKeyData string) kubernetes.Interface {
	t.Helper()

	return newClientsetWithConfig(t, newAnonymousClientRestConfigWithCertAndKeyAdded(t, clientCertificateData, clientKeyData))
}

func NewKubernetesClientset(t *testing.T) kubernetes.Interface {
	t.Helper()

	return newKubeclient(t, NewClientConfig(t)).Kubernetes
}

func NewSupervisorClientset(t *testing.T) supervisorclientset.Interface {
	t.Helper()

	return newKubeclient(t, NewClientConfig(t)).PinnipedSupervisor
}

func NewConciergeClientset(t *testing.T) conciergeclientset.Interface {
	t.Helper()

	return newKubeclient(t, NewClientConfig(t)).PinnipedConcierge
}

func NewAnonymousConciergeClientset(t *testing.T) conciergeclientset.Interface {
	t.Helper()

	return newKubeclient(t, newAnonymousClientRestConfig(t)).PinnipedConcierge
}

func NewAggregatedClientset(t *testing.T) aggregatorclient.Interface {
	t.Helper()

	return aggregatorclient.NewForConfigOrDie(NewClientConfig(t))
}

func newClientConfigWithOverrides(t *testing.T, overrides *clientcmd.ConfigOverrides) *rest.Config {
	t.Helper()

	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides)
	config, err := clientConfig.ClientConfig()
	require.NoError(t, err)
	return config
}

func newClientsetWithConfig(t *testing.T, config *rest.Config) kubernetes.Interface {
	t.Helper()

	result, err := kubernetes.NewForConfig(config)
	require.NoError(t, err, "unexpected failure from kubernetes.NewForConfig()")
	return result
}

// Returns a rest.Config without any user authentication info.
func newAnonymousClientRestConfig(t *testing.T) *rest.Config {
	t.Helper()

	return rest.AnonymousClientConfig(NewClientConfig(t))
}

// Starting with an anonymous client config, add a cert and key to use for authentication in the API server.
func newAnonymousClientRestConfigWithCertAndKeyAdded(t *testing.T, clientCertificateData, clientKeyData string) *rest.Config {
	t.Helper()

	config := newAnonymousClientRestConfig(t)
	config.CertData = []byte(clientCertificateData)
	config.KeyData = []byte(clientKeyData)
	return config
}

func newKubeclient(t *testing.T, config *rest.Config) *kubeclient.Client {
	t.Helper()
	env := IntegrationEnv(t)
	client, err := kubeclient.New(
		kubeclient.WithConfig(config),
		kubeclient.WithMiddleware(groupsuffix.New(env.APIGroupSuffix)),
	)
	require.NoError(t, err)
	return client
}

// CreateTestWebhookAuthenticator creates and returns a test WebhookAuthenticator in $PINNIPED_TEST_CONCIERGE_NAMESPACE, which will be
// automatically deleted at the end of the current test's lifetime. It returns a corev1.TypedLocalObjectReference which
// describes the test webhook authenticator within the test namespace.
func CreateTestWebhookAuthenticator(ctx context.Context, t *testing.T) corev1.TypedLocalObjectReference {
	t.Helper()
	testEnv := IntegrationEnv(t)

	client := NewConciergeClientset(t)
	webhooks := client.AuthenticationV1alpha1().WebhookAuthenticators(testEnv.ConciergeNamespace)

	createContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	webhook, err := webhooks.Create(createContext, &auth1alpha1.WebhookAuthenticator{
		ObjectMeta: testObjectMeta(t, "webhook"),
		Spec:       testEnv.TestWebhook,
	}, metav1.CreateOptions{})
	require.NoError(t, err, "could not create test WebhookAuthenticator")
	t.Logf("created test WebhookAuthenticator %s/%s", webhook.Namespace, webhook.Name)

	t.Cleanup(func() {
		t.Helper()

		if t.Failed() {
			t.Logf("skipping deletion of test WebhookAuthenticator %s/%s", webhook.Namespace, webhook.Name)
			return
		}

		t.Logf("cleaning up test WebhookAuthenticator %s/%s", webhook.Namespace, webhook.Name)
		deleteCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := webhooks.Delete(deleteCtx, webhook.Name, metav1.DeleteOptions{})
		require.NoErrorf(t, err, "could not cleanup test WebhookAuthenticator %s/%s", webhook.Namespace, webhook.Name)
	})

	return corev1.TypedLocalObjectReference{
		APIGroup: &auth1alpha1.SchemeGroupVersion.Group,
		Kind:     "WebhookAuthenticator",
		Name:     webhook.Name,
	}
}

// CreateTestJWTAuthenticatorForCLIUpstream creates and returns a test JWTAuthenticator in
// $PINNIPED_TEST_CONCIERGE_NAMESPACE, which will be automatically deleted at the end of the current
// test's lifetime. It returns a corev1.TypedLocalObjectReference which describes the test JWT
// authenticator within the test namespace.
//
// CreateTestJWTAuthenticatorForCLIUpstream gets the OIDC issuer info from IntegrationEnv().CLITestUpstream.
func CreateTestJWTAuthenticatorForCLIUpstream(ctx context.Context, t *testing.T) corev1.TypedLocalObjectReference {
	t.Helper()
	testEnv := IntegrationEnv(t)
	spec := auth1alpha1.JWTAuthenticatorSpec{
		Issuer:   testEnv.CLITestUpstream.Issuer,
		Audience: testEnv.CLITestUpstream.ClientID,
		// The default UsernameClaim is "username" but the upstreams that we use for
		// integration tests won't necessarily have that claim, so use "sub" here.
		Claims: auth1alpha1.JWTTokenClaims{Username: "sub"},
	}
	// If the test upstream does not have a CA bundle specified, then don't configure one in the
	// JWTAuthenticator. Leaving TLSSpec set to nil will result in OIDC discovery using the OS's root
	// CA store.
	if testEnv.CLITestUpstream.CABundle != "" {
		spec.TLS = &auth1alpha1.TLSSpec{
			CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(testEnv.CLITestUpstream.CABundle)),
		}
	}
	return CreateTestJWTAuthenticator(ctx, t, spec)
}

// CreateTestJWTAuthenticator creates and returns a test JWTAuthenticator in
// $PINNIPED_TEST_CONCIERGE_NAMESPACE, which will be automatically deleted at the end of the current
// test's lifetime. It returns a corev1.TypedLocalObjectReference which describes the test JWT
// authenticator within the test namespace.
func CreateTestJWTAuthenticator(ctx context.Context, t *testing.T, spec auth1alpha1.JWTAuthenticatorSpec) corev1.TypedLocalObjectReference {
	t.Helper()
	testEnv := IntegrationEnv(t)

	client := NewConciergeClientset(t)
	jwtAuthenticators := client.AuthenticationV1alpha1().JWTAuthenticators(testEnv.ConciergeNamespace)

	createContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	jwtAuthenticator, err := jwtAuthenticators.Create(createContext, &auth1alpha1.JWTAuthenticator{
		ObjectMeta: testObjectMeta(t, "jwt-authenticator"),
		Spec:       spec,
	}, metav1.CreateOptions{})
	require.NoError(t, err, "could not create test JWTAuthenticator")
	t.Logf("created test JWTAuthenticator %s/%s", jwtAuthenticator.Namespace, jwtAuthenticator.Name)

	t.Cleanup(func() {
		t.Helper()

		if t.Failed() {
			t.Logf("skipping deletion of test JWTAuthenticator %s/%s", jwtAuthenticator.Namespace, jwtAuthenticator.Name)
			return
		}

		t.Logf("cleaning up test JWTAuthenticator %s/%s", jwtAuthenticator.Namespace, jwtAuthenticator.Name)
		deleteCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := jwtAuthenticators.Delete(deleteCtx, jwtAuthenticator.Name, metav1.DeleteOptions{})
		require.NoErrorf(t, err, "could not cleanup test JWTAuthenticator %s/%s", jwtAuthenticator.Namespace, jwtAuthenticator.Name)
	})

	return corev1.TypedLocalObjectReference{
		APIGroup: &auth1alpha1.SchemeGroupVersion.Group,
		Kind:     "JWTAuthenticator",
		Name:     jwtAuthenticator.Name,
	}
}

// CreateTestFederationDomain creates and returns a test FederationDomain in
// $PINNIPED_TEST_SUPERVISOR_NAMESPACE, which will be automatically deleted at the end of the
// current test's lifetime. It generates a random, valid, issuer for the FederationDomain.
//
// If the provided issuer is not the empty string, then it will be used for the
// FederationDomain.Spec.Issuer field. Else, a random issuer will be generated.
func CreateTestFederationDomain(ctx context.Context, t *testing.T, issuer string, certSecretName string, expectStatus configv1alpha1.FederationDomainStatusCondition) *configv1alpha1.FederationDomain {
	t.Helper()
	testEnv := IntegrationEnv(t)

	createContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if issuer == "" {
		issuer = fmt.Sprintf("http://test-issuer-%s.pinniped.dev", RandHex(t, 8))
	}

	federationDomains := NewSupervisorClientset(t).ConfigV1alpha1().FederationDomains(testEnv.SupervisorNamespace)
	federationDomain, err := federationDomains.Create(createContext, &configv1alpha1.FederationDomain{
		ObjectMeta: testObjectMeta(t, "oidc-provider"),
		Spec: configv1alpha1.FederationDomainSpec{
			Issuer: issuer,
			TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: certSecretName},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err, "could not create test FederationDomain")
	t.Logf("created test FederationDomain %s/%s", federationDomain.Namespace, federationDomain.Name)

	t.Cleanup(func() {
		t.Helper()
		t.Logf("cleaning up test FederationDomain %s/%s", federationDomain.Namespace, federationDomain.Name)
		deleteCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := federationDomains.Delete(deleteCtx, federationDomain.Name, metav1.DeleteOptions{})
		notFound := k8serrors.IsNotFound(err)
		// It's okay if it is not found, because it might have been deleted by another part of this test.
		if !notFound {
			require.NoErrorf(t, err, "could not cleanup test FederationDomain %s/%s", federationDomain.Namespace, federationDomain.Name)
		}
	})

	// If we're not expecting any particular status, just return the new FederationDomain immediately.
	if expectStatus == "" {
		return federationDomain
	}

	// Wait for the FederationDomain to enter the expected phase (or time out).
	var result *configv1alpha1.FederationDomain
	assert.Eventuallyf(t, func() bool {
		var err error
		result, err = federationDomains.Get(ctx, federationDomain.Name, metav1.GetOptions{})
		require.NoError(t, err)
		return result.Status.Status == expectStatus
	}, 60*time.Second, 1*time.Second, "expected the FederationDomain to have status %q", expectStatus)
	require.Equal(t, expectStatus, result.Status.Status)

	// If the FederationDomain was successfully created, ensure all secrets are present before continuing
	if result.Status.Status == configv1alpha1.SuccessFederationDomainStatusCondition {
		assert.Eventually(t, func() bool {
			var err error
			result, err = federationDomains.Get(ctx, federationDomain.Name, metav1.GetOptions{})
			require.NoError(t, err)
			return result.Status.Secrets.JWKS.Name != "" &&
				result.Status.Secrets.TokenSigningKey.Name != "" &&
				result.Status.Secrets.StateSigningKey.Name != "" &&
				result.Status.Secrets.StateEncryptionKey.Name != ""
		}, 60*time.Second, 1*time.Second, "expected the FederationDomain to have secrets populated")
		require.NotEmpty(t, result.Status.Secrets.JWKS.Name)
		require.NotEmpty(t, result.Status.Secrets.TokenSigningKey.Name)
		require.NotEmpty(t, result.Status.Secrets.StateSigningKey.Name)
		require.NotEmpty(t, result.Status.Secrets.StateEncryptionKey.Name)
	}
	return federationDomain
}

func RandHex(t *testing.T, numBytes int) string {
	buf := make([]byte, numBytes)
	_, err := io.ReadFull(rand.Reader, buf)
	require.NoError(t, err)
	return hex.EncodeToString(buf)
}

func CreateTestSecret(t *testing.T, namespace string, baseName string, secretType corev1.SecretType, stringData map[string]string) *corev1.Secret {
	t.Helper()
	client := NewKubernetesClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	created, err := client.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: testObjectMeta(t, baseName),
		Type:       secretType,
		StringData: stringData,
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
		t.Logf("cleaning up test Secret %s/%s", created.Namespace, created.Name)
		err := client.CoreV1().Secrets(namespace).Delete(context.Background(), created.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})
	t.Logf("created test Secret %s", created.Name)
	return created
}

func CreateClientCredsSecret(t *testing.T, clientID string, clientSecret string) *corev1.Secret {
	t.Helper()
	env := IntegrationEnv(t)
	return CreateTestSecret(t,
		env.SupervisorNamespace,
		"client-creds",
		"secrets.pinniped.dev/oidc-client",
		map[string]string{
			"clientID":     clientID,
			"clientSecret": clientSecret,
		},
	)
}

func CreateTestOIDCIdentityProvider(t *testing.T, spec idpv1alpha1.OIDCIdentityProviderSpec, expectedPhase idpv1alpha1.OIDCIdentityProviderPhase) *idpv1alpha1.OIDCIdentityProvider {
	t.Helper()
	env := IntegrationEnv(t)
	client := NewSupervisorClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create the OIDCIdentityProvider using GenerateName to get a random name.
	upstreams := client.IDPV1alpha1().OIDCIdentityProviders(env.SupervisorNamespace)

	created, err := upstreams.Create(ctx, &idpv1alpha1.OIDCIdentityProvider{
		ObjectMeta: testObjectMeta(t, "upstream"),
		Spec:       spec,
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	// Always clean this up after this point.
	t.Cleanup(func() {
		t.Logf("cleaning up test OIDCIdentityProvider %s/%s", created.Namespace, created.Name)
		err := upstreams.Delete(context.Background(), created.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})
	t.Logf("created test OIDCIdentityProvider %s", created.Name)

	// Wait for the OIDCIdentityProvider to enter the expected phase (or time out).
	var result *idpv1alpha1.OIDCIdentityProvider
	require.Eventuallyf(t, func() bool {
		var err error
		result, err = upstreams.Get(ctx, created.Name, metav1.GetOptions{})
		require.NoError(t, err)
		return result.Status.Phase == expectedPhase
	}, 60*time.Second, 1*time.Second, "expected the OIDCIdentityProvider to go into phase %s", expectedPhase)
	return result
}

func CreateTestClusterRoleBinding(t *testing.T, subject rbacv1.Subject, roleRef rbacv1.RoleRef) *rbacv1.ClusterRoleBinding {
	t.Helper()
	client := NewKubernetesClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create the ClusterRoleBinding using GenerateName to get a random name.
	clusterRoles := client.RbacV1().ClusterRoleBindings()

	created, err := clusterRoles.Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: testObjectMeta(t, "cluster-role"),
		Subjects:   []rbacv1.Subject{subject},
		RoleRef:    roleRef,
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	t.Logf("created test ClusterRoleBinding %s", created.Name)

	t.Cleanup(func() {
		t.Logf("cleaning up test ClusterRoleBinding %s", created.Name)
		err := clusterRoles.Delete(context.Background(), created.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})
	return created
}

func testObjectMeta(t *testing.T, baseName string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		GenerateName: fmt.Sprintf("test-%s-", baseName),
		Labels:       map[string]string{"pinniped.dev/test": ""},
		Annotations:  map[string]string{"pinniped.dev/testName": t.Name()},
	}
}
