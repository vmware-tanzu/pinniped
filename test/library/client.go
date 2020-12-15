// Copyright 2020 the Pinniped contributors. All Rights Reserved.
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

	auth1alpha1 "go.pinniped.dev/generated/1.19/apis/concierge/authentication/v1alpha1"
	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/1.19/apis/supervisor/idp/v1alpha1"
	conciergeclientset "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned"
	supervisorclientset "go.pinniped.dev/generated/1.19/client/supervisor/clientset/versioned"

	// Import to initialize client auth plugins - the kubeconfig that we use for
	// testing may use gcloud, az, oidc, etc.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func NewClientConfig(t *testing.T) *rest.Config {
	t.Helper()

	return newClientConfigWithOverrides(t, &clientcmd.ConfigOverrides{})
}

func NewClientset(t *testing.T) kubernetes.Interface {
	t.Helper()

	return newClientsetWithConfig(t, NewClientConfig(t))
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

func NewSupervisorClientset(t *testing.T) supervisorclientset.Interface {
	t.Helper()

	return supervisorclientset.NewForConfigOrDie(NewClientConfig(t))
}

func NewConciergeClientset(t *testing.T) conciergeclientset.Interface {
	t.Helper()

	return conciergeclientset.NewForConfigOrDie(NewClientConfig(t))
}

func NewAnonymousConciergeClientset(t *testing.T) conciergeclientset.Interface {
	t.Helper()

	return conciergeclientset.NewForConfigOrDie(newAnonymousClientRestConfig(t))
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

// CreateTestOIDCProvider creates and returns a test OIDCProvider in
// $PINNIPED_TEST_SUPERVISOR_NAMESPACE, which will be automatically deleted at the end of the
// current test's lifetime. It generates a random, valid, issuer for the OIDCProvider.
//
// If the provided issuer is not the empty string, then it will be used for the
// OIDCProvider.Spec.Issuer field. Else, a random issuer will be generated.
func CreateTestOIDCProvider(ctx context.Context, t *testing.T, issuer string, certSecretName string, expectStatus configv1alpha1.OIDCProviderStatusCondition) *configv1alpha1.OIDCProvider {
	t.Helper()
	testEnv := IntegrationEnv(t)

	createContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if issuer == "" {
		issuer = fmt.Sprintf("http://test-issuer-%s.pinniped.dev", RandHex(t, 8))
	}

	opcs := NewSupervisorClientset(t).ConfigV1alpha1().OIDCProviders(testEnv.SupervisorNamespace)
	opc, err := opcs.Create(createContext, &configv1alpha1.OIDCProvider{
		ObjectMeta: testObjectMeta(t, "oidc-provider"),
		Spec: configv1alpha1.OIDCProviderSpec{
			Issuer: issuer,
			TLS:    &configv1alpha1.OIDCProviderTLSSpec{SecretName: certSecretName},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err, "could not create test OIDCProvider")
	t.Logf("created test OIDCProvider %s/%s", opc.Namespace, opc.Name)

	t.Cleanup(func() {
		t.Helper()
		t.Logf("cleaning up test OIDCProvider %s/%s", opc.Namespace, opc.Name)
		deleteCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := opcs.Delete(deleteCtx, opc.Name, metav1.DeleteOptions{})
		notFound := k8serrors.IsNotFound(err)
		// It's okay if it is not found, because it might have been deleted by another part of this test.
		if !notFound {
			require.NoErrorf(t, err, "could not cleanup test OIDCProvider %s/%s", opc.Namespace, opc.Name)
		}
	})

	// If we're not expecting any particular status, just return the new OIDCProvider immediately.
	if expectStatus == "" {
		return opc
	}

	// Wait for the OIDCProvider to enter the expected phase (or time out).
	var result *configv1alpha1.OIDCProvider
	assert.Eventuallyf(t, func() bool {
		var err error
		result, err = opcs.Get(ctx, opc.Name, metav1.GetOptions{})
		require.NoError(t, err)
		return result.Status.Status == expectStatus
	}, 60*time.Second, 1*time.Second, "expected the OIDCProvider to have status %q", expectStatus)
	require.Equal(t, expectStatus, result.Status.Status)

	return opc
}

func RandHex(t *testing.T, numBytes int) string {
	buf := make([]byte, numBytes)
	_, err := io.ReadFull(rand.Reader, buf)
	require.NoError(t, err)
	return hex.EncodeToString(buf)
}

func CreateTestSecret(t *testing.T, namespace string, baseName string, secretType string, stringData map[string]string) *corev1.Secret {
	t.Helper()
	client := NewClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	created, err := client.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: testObjectMeta(t, baseName),
		Type:       corev1.SecretType(secretType),
		StringData: stringData,
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
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
		"test-client-creds",
		"secrets.pinniped.dev/oidc-client",
		map[string]string{
			"clientID":     clientID,
			"clientSecret": clientSecret,
		},
	)
}

func CreateTestUpstreamOIDCProvider(t *testing.T, spec idpv1alpha1.UpstreamOIDCProviderSpec, expectedPhase idpv1alpha1.UpstreamOIDCProviderPhase) *idpv1alpha1.UpstreamOIDCProvider {
	t.Helper()
	env := IntegrationEnv(t)
	client := NewSupervisorClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create the UpstreamOIDCProvider using GenerateName to get a random name.
	upstreams := client.IDPV1alpha1().UpstreamOIDCProviders(env.SupervisorNamespace)

	created, err := upstreams.Create(ctx, &idpv1alpha1.UpstreamOIDCProvider{
		ObjectMeta: testObjectMeta(t, "upstream"),
		Spec:       spec,
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	// Always clean this up after this point.
	t.Cleanup(func() {
		err := upstreams.Delete(context.Background(), created.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})
	t.Logf("created test UpstreamOIDCProvider %s", created.Name)

	// Wait for the UpstreamOIDCProvider to enter the expected phase (or time out).
	var result *idpv1alpha1.UpstreamOIDCProvider
	require.Eventuallyf(t, func() bool {
		var err error
		result, err = upstreams.Get(ctx, created.Name, metav1.GetOptions{})
		require.NoError(t, err)
		return result.Status.Phase == expectedPhase
	}, 60*time.Second, 1*time.Second, "expected the UpstreamOIDCProvider to go into phase %s", expectedPhase)
	return result
}

func CreateTestClusterRoleBinding(t *testing.T, subject rbacv1.Subject, roleRef rbacv1.RoleRef) *rbacv1.ClusterRoleBinding {
	t.Helper()
	client := NewClientset(t)
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
