// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testlib

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	"k8s.io/utils/ptr"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	"go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
	clientsecretv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/clientsecret/v1alpha1"
	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	supervisorclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	alpha1 "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/typed/idp/v1alpha1"
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
	kubeConfigFile, err := os.CreateTemp("", "pinniped-cli-test-*")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, os.Remove(kubeConfigFile.Name()))
	}()

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

	return NewKubeclient(t, NewClientConfig(t)).Kubernetes
}

func NewSupervisorClientset(t *testing.T) supervisorclientset.Interface {
	t.Helper()

	return NewKubeclient(t, NewClientConfig(t)).PinnipedSupervisor
}

func NewAnonymousSupervisorClientset(t *testing.T) supervisorclientset.Interface {
	t.Helper()

	return NewKubeclient(t, NewAnonymousClientRestConfig(t)).PinnipedSupervisor
}

func NewConciergeClientset(t *testing.T) conciergeclientset.Interface {
	t.Helper()

	return NewKubeclient(t, NewClientConfig(t)).PinnipedConcierge
}

func NewAnonymousConciergeClientset(t *testing.T) conciergeclientset.Interface {
	t.Helper()

	return NewKubeclient(t, NewAnonymousClientRestConfig(t)).PinnipedConcierge
}

func NewAggregatedClientset(t *testing.T) aggregatorclient.Interface {
	t.Helper()

	return aggregatorclient.NewForConfigOrDie(NewClientConfig(t))
}

func NewAPIExtensionsV1Client(t *testing.T) apiextensionsv1.ApiextensionsV1Interface {
	t.Helper()

	return apiextensionsv1.NewForConfigOrDie(NewClientConfig(t))
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
func NewAnonymousClientRestConfig(t *testing.T) *rest.Config {
	t.Helper()

	return kubeclient.SecureAnonymousClientConfig(NewClientConfig(t))
}

// Starting with an anonymous client config, add a cert and key to use for authentication in the API server.
func newAnonymousClientRestConfigWithCertAndKeyAdded(t *testing.T, clientCertificateData, clientKeyData string) *rest.Config {
	t.Helper()

	config := NewAnonymousClientRestConfig(t)
	config.CertData = []byte(clientCertificateData)
	config.KeyData = []byte(clientKeyData)
	return config
}

func NewKubeclientOptions(t *testing.T, config *rest.Config) []kubeclient.Option {
	t.Helper()

	return []kubeclient.Option{
		kubeclient.WithConfig(config),
		kubeclient.WithMiddleware(groupsuffix.New(IntegrationEnv(t).APIGroupSuffix)),
	}
}

func NewKubeclient(t *testing.T, config *rest.Config) *kubeclient.Client {
	t.Helper()

	client, err := kubeclient.New(NewKubeclientOptions(t, config)...)
	require.NoError(t, err)
	return client
}

// CreateTestWebhookAuthenticator creates and returns a test WebhookAuthenticator in $PINNIPED_TEST_CONCIERGE_NAMESPACE, which will be
// automatically deleted at the end of the current test's lifetime. It returns a corev1.TypedLocalObjectReference which
// describes the test webhook authenticator within the test namespace.
func CreateTestWebhookAuthenticator(
	ctx context.Context,
	t *testing.T,
	webhookSpec *authenticationv1alpha1.WebhookAuthenticatorSpec,
	expectedStatus authenticationv1alpha1.WebhookAuthenticatorPhase) corev1.TypedLocalObjectReference {
	t.Helper()

	client := NewConciergeClientset(t)
	webhooks := client.AuthenticationV1alpha1().WebhookAuthenticators()

	createContext, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	webhook, err := webhooks.Create(createContext, &authenticationv1alpha1.WebhookAuthenticator{
		ObjectMeta: TestObjectMeta(t, "webhook"),
		Spec:       *webhookSpec,
	}, metav1.CreateOptions{})
	require.NoError(t, err, "could not create test WebhookAuthenticator")
	t.Logf("created test WebhookAuthenticator %s", webhook.Name)

	t.Cleanup(func() {
		t.Helper()
		t.Logf("cleaning up test WebhookAuthenticator %s", webhook.Name)
		deleteCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err := webhooks.Delete(deleteCtx, webhook.Name, metav1.DeleteOptions{})
		require.NoErrorf(t, err, "could not cleanup test WebhookAuthenticator %s/%s", webhook.Namespace, webhook.Name)
	})

	if expectedStatus != "" {
		WaitForWebhookAuthenticatorStatusPhase(ctx, t, webhook.Name, expectedStatus)
	}

	return corev1.TypedLocalObjectReference{
		APIGroup: &authenticationv1alpha1.SchemeGroupVersion.Group,
		Kind:     "WebhookAuthenticator",
		Name:     webhook.Name,
	}
}

func WaitForWebhookAuthenticatorStatusPhase(
	ctx context.Context,
	t *testing.T,
	webhookName string,
	expectPhase authenticationv1alpha1.WebhookAuthenticatorPhase) {
	t.Helper()
	webhookAuthenticatorClientSet := NewConciergeClientset(t).AuthenticationV1alpha1().WebhookAuthenticators()

	RequireEventuallyf(t, func(requireEventually *require.Assertions) {
		webhookA, err := webhookAuthenticatorClientSet.Get(ctx, webhookName, metav1.GetOptions{})
		requireEventually.NoError(err)
		requireEventually.Equalf(expectPhase, webhookA.Status.Phase, "actual status conditions were: %#v", webhookA.Status.Conditions)
	}, 60*time.Second, 1*time.Second, "expected the WebhookAuthenticator to have status %q", expectPhase)
}

func WaitForWebhookAuthenticatorStatusConditions(ctx context.Context, t *testing.T, webhookName string, expectConditions []metav1.Condition) {
	t.Helper()
	webhookClient := NewConciergeClientset(t).AuthenticationV1alpha1().WebhookAuthenticators()
	RequireEventuallyf(t, func(requireEventually *require.Assertions) {
		fd, err := webhookClient.Get(ctx, webhookName, metav1.GetOptions{})
		requireEventually.NoError(err)

		requireEventually.Lenf(fd.Status.Conditions, len(expectConditions),
			"wanted status conditions: %#v", expectConditions)

		for i, wantCond := range expectConditions {
			actualCond := fd.Status.Conditions[i]

			// This is a cheat to avoid needing to make equality assertions on these fields.
			requireEventually.NotZero(actualCond.LastTransitionTime)
			wantCond.LastTransitionTime = actualCond.LastTransitionTime
			requireEventually.NotZero(actualCond.ObservedGeneration)
			wantCond.ObservedGeneration = actualCond.ObservedGeneration

			requireEventually.Equalf(wantCond, actualCond,
				"wanted status conditions: %#v\nactual status conditions were: %#v\nnot equal at index %d",
				expectConditions, fd.Status.Conditions, i)
		}
	}, 60*time.Second, 1*time.Second, "wanted WebhookAuthenticator conditions")
}

// CreateTestJWTAuthenticatorForCLIUpstream creates and returns a test JWTAuthenticator which will be automatically
// deleted at the end of the current test's lifetime.
//
// CreateTestJWTAuthenticatorForCLIUpstream gets the OIDC issuer info from IntegrationEnv().CLIUpstreamOIDC.
func CreateTestJWTAuthenticatorForCLIUpstream(ctx context.Context, t *testing.T) *authenticationv1alpha1.JWTAuthenticator {
	t.Helper()
	testEnv := IntegrationEnv(t)
	spec := authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   testEnv.CLIUpstreamOIDC.Issuer,
		Audience: testEnv.CLIUpstreamOIDC.ClientID,
		// The default UsernameClaim is "username" but the upstreams that we use for
		// integration tests won't necessarily have that claim, so use "sub" here.
		Claims: authenticationv1alpha1.JWTTokenClaims{Username: "sub"},
	}
	// If the test upstream does not have a CA bundle specified, then don't configure one in the
	// JWTAuthenticator. Leaving TLSSpec set to nil will result in OIDC discovery using the OS's root
	// CA store.
	if testEnv.CLIUpstreamOIDC.CABundle != "" {
		spec.TLS = &authenticationv1alpha1.TLSSpec{
			CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(testEnv.CLIUpstreamOIDC.CABundle)),
		}
	}
	authenticator := CreateTestJWTAuthenticator(ctx, t, spec, authenticationv1alpha1.JWTAuthenticatorPhaseReady)
	return authenticator
}

// CreateTestJWTAuthenticator creates and returns a test JWTAuthenticator which will be automatically deleted
// at the end of the current test's lifetime.
func CreateTestJWTAuthenticator(
	ctx context.Context,
	t *testing.T,
	spec authenticationv1alpha1.JWTAuthenticatorSpec,
	expectedStatus authenticationv1alpha1.JWTAuthenticatorPhase) *authenticationv1alpha1.JWTAuthenticator {
	t.Helper()

	client := NewConciergeClientset(t)
	jwtAuthenticators := client.AuthenticationV1alpha1().JWTAuthenticators()

	createContext, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	jwtAuthenticator, err := jwtAuthenticators.Create(createContext, &authenticationv1alpha1.JWTAuthenticator{
		ObjectMeta: TestObjectMeta(t, "jwt-authenticator"),
		Spec:       spec,
	}, metav1.CreateOptions{})
	require.NoError(t, err, "could not create test JWTAuthenticator")
	t.Logf("created test JWTAuthenticator %s", jwtAuthenticator.Name)

	t.Cleanup(func() {
		t.Helper()
		t.Logf("cleaning up test JWTAuthenticator %s/%s", jwtAuthenticator.Namespace, jwtAuthenticator.Name)
		deleteCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err := jwtAuthenticators.Delete(deleteCtx, jwtAuthenticator.Name, metav1.DeleteOptions{})
		require.NoErrorf(t, err, "could not cleanup test JWTAuthenticator %s", jwtAuthenticator.Name)
	})

	WaitForJWTAuthenticatorStatusPhase(ctx, t, jwtAuthenticator.Name, expectedStatus)

	return jwtAuthenticator
}

func WaitForJWTAuthenticatorStatusPhase(ctx context.Context, t *testing.T, jwtAuthenticatorName string, expectPhase authenticationv1alpha1.JWTAuthenticatorPhase) {
	t.Helper()
	jwtAuthenticatorClientSet := NewConciergeClientset(t).AuthenticationV1alpha1().JWTAuthenticators()

	RequireEventuallyf(t, func(requireEventually *require.Assertions) {
		jwtA, err := jwtAuthenticatorClientSet.Get(ctx, jwtAuthenticatorName, metav1.GetOptions{})
		requireEventually.NoError(err)
		requireEventually.Equalf(expectPhase, jwtA.Status.Phase, "actual status conditions were: %#v", jwtA.Status.Conditions)
	}, 60*time.Second, 1*time.Second, "expected the JWTAuthenticator to have status %q", expectPhase)
}

func WaitForJWTAuthenticatorStatusConditions(ctx context.Context, t *testing.T, jwtAuthenticatorName string, expectConditions []metav1.Condition) {
	t.Helper()
	jwtAuthenticatorClient := NewConciergeClientset(t).AuthenticationV1alpha1().JWTAuthenticators()
	RequireEventuallyf(t, func(requireEventually *require.Assertions) {
		fd, err := jwtAuthenticatorClient.Get(ctx, jwtAuthenticatorName, metav1.GetOptions{})
		requireEventually.NoError(err)

		requireEventually.Lenf(fd.Status.Conditions, len(expectConditions),
			"wanted status conditions: %#v", expectConditions)

		for i, wantCond := range expectConditions {
			actualCond := fd.Status.Conditions[i]

			// This is a cheat to avoid needing to make equality assertions on these fields.
			requireEventually.NotZero(actualCond.LastTransitionTime)
			wantCond.LastTransitionTime = actualCond.LastTransitionTime
			requireEventually.NotZero(actualCond.ObservedGeneration)
			wantCond.ObservedGeneration = actualCond.ObservedGeneration

			requireEventually.Equalf(wantCond, actualCond,
				"wanted status conditions: %#v\nactual status conditions were: %#v\nnot equal at index %d",
				expectConditions, fd.Status.Conditions, i)
		}
	}, 60*time.Second, 1*time.Second, "wanted JWTAuthenticator conditions")
}

// CreateTestFederationDomain creates and returns a test FederationDomain in the
// $PINNIPED_TEST_SUPERVISOR_NAMESPACE, which will be automatically deleted at the end of the
// current test's lifetime.
func CreateTestFederationDomain(
	ctx context.Context,
	t *testing.T,
	spec supervisorconfigv1alpha1.FederationDomainSpec,
	expectStatus supervisorconfigv1alpha1.FederationDomainPhase,
) *supervisorconfigv1alpha1.FederationDomain {
	t.Helper()
	testEnv := IntegrationEnv(t)

	createContext, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	// If the issuer is an IP address, then we have to update the DEFAULT cert, and there's no secret associated with this FederationDomain
	if NewSupervisorIssuer(t, spec.Issuer).IsIPAddress() {
		spec.TLS = nil
	}

	federationDomainsClient := NewSupervisorClientset(t).ConfigV1alpha1().FederationDomains(testEnv.SupervisorNamespace)
	federationDomain, err := federationDomainsClient.Create(createContext, &supervisorconfigv1alpha1.FederationDomain{
		ObjectMeta: TestObjectMeta(t, "oidc-provider"),
		Spec:       spec,
	}, metav1.CreateOptions{})
	require.NoError(t, err, "could not create test FederationDomain")
	t.Logf("created test FederationDomain %s/%s", federationDomain.Namespace, federationDomain.Name)

	t.Cleanup(func() {
		t.Helper()
		t.Logf("cleaning up test FederationDomain %s/%s", federationDomain.Namespace, federationDomain.Name)
		deleteCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err := federationDomainsClient.Delete(deleteCtx, federationDomain.Name, metav1.DeleteOptions{})
		notFound := apierrors.IsNotFound(err)
		// It's okay if it is not found, because it might have been deleted by another part of this test.
		if !notFound {
			require.NoErrorf(t, err, "could not cleanup test FederationDomain %s/%s", federationDomain.Namespace, federationDomain.Name)
		}
	})

	// Wait for the FederationDomain to enter the expected phase (or time out).
	WaitForFederationDomainStatusPhase(ctx, t, federationDomain.Name, expectStatus)

	return federationDomain
}

func WaitForFederationDomainStatusPhase(ctx context.Context, t *testing.T, federationDomainName string, expectPhase supervisorconfigv1alpha1.FederationDomainPhase) {
	t.Helper()
	testEnv := IntegrationEnv(t)
	federationDomainsClient := NewSupervisorClientset(t).ConfigV1alpha1().FederationDomains(testEnv.SupervisorNamespace)

	RequireEventuallyf(t, func(requireEventually *require.Assertions) {
		fd, err := federationDomainsClient.Get(ctx, federationDomainName, metav1.GetOptions{})
		requireEventually.NoError(err)
		requireEventually.Equalf(expectPhase, fd.Status.Phase, "actual status conditions were: %#v", fd.Status.Conditions)

		// If the FederationDomain was successfully created, ensure all secrets are present before continuing
		if expectPhase == supervisorconfigv1alpha1.FederationDomainPhaseReady {
			requireEventually.NotEmpty(fd.Status.Secrets.JWKS.Name, "expected status.secrets.jwks.name not to be empty")
			requireEventually.NotEmpty(fd.Status.Secrets.TokenSigningKey.Name, "expected status.secrets.tokenSigningKey.name not to be empty")
			requireEventually.NotEmpty(fd.Status.Secrets.StateSigningKey.Name, "expected status.secrets.stateSigningKey.name not to be empty")
			requireEventually.NotEmpty(fd.Status.Secrets.StateEncryptionKey.Name, "expected status.secrets.stateEncryptionKey.name not to be empty")
		}
	}, 60*time.Second, 1*time.Second, "expected the FederationDomain to have status %q", expectPhase)
}

func WaitForFederationDomainStatusConditions(ctx context.Context, t *testing.T, federationDomainName string, expectConditions []metav1.Condition) {
	t.Helper()
	testEnv := IntegrationEnv(t)
	federationDomainsClient := NewSupervisorClientset(t).ConfigV1alpha1().FederationDomains(testEnv.SupervisorNamespace)

	RequireEventuallyf(t, func(requireEventually *require.Assertions) {
		fd, err := federationDomainsClient.Get(ctx, federationDomainName, metav1.GetOptions{})
		requireEventually.NoError(err)

		requireEventually.Lenf(fd.Status.Conditions, len(expectConditions),
			"wanted status conditions: %#v", expectConditions)

		for i, wantCond := range expectConditions {
			actualCond := fd.Status.Conditions[i]

			// This is a cheat to avoid needing to make equality assertions on these fields.
			requireEventually.NotZero(actualCond.LastTransitionTime)
			wantCond.LastTransitionTime = actualCond.LastTransitionTime
			requireEventually.NotZero(actualCond.ObservedGeneration)
			wantCond.ObservedGeneration = actualCond.ObservedGeneration

			requireEventually.Equalf(wantCond, actualCond,
				"wanted status conditions: %#v\nactual status conditions were: %#v\nnot equal at index %d",
				expectConditions, fd.Status.Conditions, i)
		}
	}, 60*time.Second, 1*time.Second, "wanted FederationDomain conditions")
}

func RandBytes(t *testing.T, numBytes int) []byte {
	buf := make([]byte, numBytes)
	_, err := io.ReadFull(rand.Reader, buf)
	require.NoError(t, err)
	return buf
}

func RandHex(t *testing.T, numBytes int) string {
	return hex.EncodeToString(RandBytes(t, numBytes))
}

func CreateTestConfigMap(t *testing.T, namespace string, baseName string, stringData map[string]string) *corev1.ConfigMap {
	t.Helper()
	client := NewKubernetesClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	created, err := client.CoreV1().ConfigMaps(namespace).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: TestObjectMeta(t, baseName),
		Data:       stringData,
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
		t.Logf("cleaning up test Configmap %s/%s", created.Namespace, created.Name)
		err := client.CoreV1().ConfigMaps(namespace).Delete(context.Background(), created.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})
	t.Logf("created test ConfigMap %s/%s", created.Namespace, created.Name)
	return created
}

func createTestSecret(t *testing.T, namespace string, secret *corev1.Secret) *corev1.Secret {
	t.Helper()
	client := NewKubernetesClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	created, err := client.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
		t.Logf("cleaning up test Secret %s/%s", created.Namespace, created.Name)
		err := client.CoreV1().Secrets(namespace).Delete(context.Background(), created.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})
	t.Logf("created test Secret %s/%s", created.Namespace, created.Name)
	return created
}

func CreateTestSecret(t *testing.T, namespace string, baseName string, secretType corev1.SecretType, stringData map[string]string) *corev1.Secret {
	return createTestSecret(t, namespace, &corev1.Secret{
		ObjectMeta: TestObjectMeta(t, baseName),
		Type:       secretType,
		StringData: stringData,
	})
}

func CreateTestSecretWithName(t *testing.T, namespace string, name string, secretType corev1.SecretType, stringData map[string]string) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: TestObjectMeta(t, ""),
		Type:       secretType,
		StringData: stringData,
	}
	secret.GenerateName = ""
	secret.Name = name
	return createTestSecret(t, namespace, secret)
}

func CreateTestSecretBytes(t *testing.T, namespace string, baseName string, secretType corev1.SecretType, data map[string][]byte) *corev1.Secret {
	t.Helper()
	client := NewKubernetesClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	created, err := client.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: TestObjectMeta(t, baseName),
		Type:       secretType,
		Data:       data,
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

func CreateOIDCClientCredentialsSecret(t *testing.T, clientID string, clientSecret string) *corev1.Secret {
	t.Helper()
	return createClientCredentialsSecret(t, clientID, clientSecret, "secrets.pinniped.dev/oidc-client")
}

func CreateGitHubClientCredentialsSecret(t *testing.T, clientID string, clientSecret string) *corev1.Secret {
	t.Helper()
	return createClientCredentialsSecret(t, clientID, clientSecret, "secrets.pinniped.dev/github-client")
}

func createClientCredentialsSecret(t *testing.T, clientID string, clientSecret string, secretType string) *corev1.Secret {
	t.Helper()
	env := IntegrationEnv(t)
	return CreateTestSecret(t,
		env.SupervisorNamespace,
		"client-creds",
		corev1.SecretType(secretType),
		map[string]string{
			"clientID":     clientID,
			"clientSecret": clientSecret,
		},
	)
}

func CreateOIDCClient(t *testing.T, spec supervisorconfigv1alpha1.OIDCClientSpec, expectedPhase supervisorconfigv1alpha1.OIDCClientPhase) (string, string) {
	t.Helper()
	env := IntegrationEnv(t)
	client := NewSupervisorClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	oidcClientClient := client.ConfigV1alpha1().OIDCClients(env.SupervisorNamespace)

	// Create the OIDCClient using GenerateName to get a random name.
	created, err := oidcClientClient.Create(ctx, &supervisorconfigv1alpha1.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "client.oauth.pinniped.dev-test-", // use the required name prefix
			Labels:       map[string]string{"pinniped.dev/test": ""},
			Annotations:  map[string]string{"pinniped.dev/testName": t.Name()},
		},
		Spec: spec,
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	// Always clean this up after this point.
	t.Cleanup(func() {
		t.Logf("cleaning up test OIDCClient %s/%s", created.Namespace, created.Name)
		err := oidcClientClient.Delete(context.Background(), created.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})
	t.Logf("created test OIDCClient %s", created.Name)

	// Create a client secret for the new OIDCClient.
	clientSecret := createOIDCClientSecret(t, created)

	// Wait for the OIDCClient to enter the expected phase (or time out).
	var result *supervisorconfigv1alpha1.OIDCClient
	RequireEventuallyf(t, func(requireEventually *require.Assertions) {
		var err error
		result, err = oidcClientClient.Get(ctx, created.Name, metav1.GetOptions{})
		requireEventually.NoErrorf(err, "error while getting OIDCClient %s/%s", created.Namespace, created.Name)
		requireEventually.Equal(expectedPhase, result.Status.Phase)
	}, 60*time.Second, 1*time.Second, "expected the OIDCClient to go into phase %s, OIDCClient was: %s", expectedPhase, Sdump(result))

	return created.Name, clientSecret
}

func createOIDCClientSecret(t *testing.T, forOIDCClient *supervisorconfigv1alpha1.OIDCClient) string {
	t.Helper()
	env := IntegrationEnv(t)
	supervisorClient := NewSupervisorClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Call the OIDCClientSecretRequest using the "create" verb to generate a new random client secret for the
	// client of the given name.
	secretRequest, err := supervisorClient.ClientsecretV1alpha1().OIDCClientSecretRequests(env.SupervisorNamespace).Create(ctx,
		&clientsecretv1alpha1.OIDCClientSecretRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name: forOIDCClient.Name,
			},
			Spec: clientsecretv1alpha1.OIDCClientSecretRequestSpec{
				GenerateNewSecret: true,
				RevokeOldSecrets:  false,
			},
		},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)

	// The response should be present in the status.
	generatedSecret := secretRequest.Status.GeneratedSecret
	require.Len(t, generatedSecret, 64) // randomly generated long secret
	require.Equal(t, 1, secretRequest.Status.TotalClientSecrets)

	return generatedSecret
}

func CreateTestGitHubIdentityProvider(t *testing.T, spec idpv1alpha1.GitHubIdentityProviderSpec, expectedPhase idpv1alpha1.GitHubIdentityProviderPhase) *idpv1alpha1.GitHubIdentityProvider {
	t.Helper()
	return CreateTestGitHubIdentityProviderWithObjectMeta(t, spec, TestObjectMeta(t, "upstream-github-idp"), expectedPhase)
}

func CreateTestGitHubIdentityProviderWithObjectMeta(t *testing.T, spec idpv1alpha1.GitHubIdentityProviderSpec, objectMeta metav1.ObjectMeta, expectedPhase idpv1alpha1.GitHubIdentityProviderPhase) *idpv1alpha1.GitHubIdentityProvider {
	t.Helper()
	env := IntegrationEnv(t)
	client := NewSupervisorClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	upstreams := client.IDPV1alpha1().GitHubIdentityProviders(env.SupervisorNamespace)

	// Create the GitHubIdentityProvider using GenerateName to get a random name.
	created, err := upstreams.Create(ctx, &idpv1alpha1.GitHubIdentityProvider{
		ObjectMeta: objectMeta,
		Spec:       spec,
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	// Always clean this up after this point.
	t.Cleanup(func() {
		t.Logf("cleaning up test GitHubIdentityProvider %s/%s", created.Namespace, created.Name)
		err := upstreams.Delete(context.Background(), created.Name, metav1.DeleteOptions{})
		notFound := apierrors.IsNotFound(err)
		// It's okay if it is not found, because it might have been deleted by another part of this test.
		if !notFound {
			require.NoErrorf(t, err, "could not cleanup test GitHubIdentityProvider %s/%s", created.Namespace, created.Name)
		}
	})
	t.Logf("created test GitHubIdentityProvider %s", created.Name)

	// Wait for the GitHubIdentityProvider to enter the expected phase (or time out).
	var result *idpv1alpha1.GitHubIdentityProvider
	RequireEventuallyf(t, func(requireEventually *require.Assertions) {
		var err error
		result, err = upstreams.Get(ctx, created.Name, metav1.GetOptions{})
		requireEventually.NoErrorf(err, "error while getting GitHubIdentityProvider %s/%s", created.Namespace, created.Name)
		requireEventually.Equal(expectedPhase, result.Status.Phase)
	}, 60*time.Second, 1*time.Second, "expected the GitHubIdentityProvider to go into phase %s, GitHubIdentityProvider was: %s", expectedPhase, Sdump(result))
	return result
}

func CreateTestOIDCIdentityProvider(t *testing.T, spec idpv1alpha1.OIDCIdentityProviderSpec, expectedPhase idpv1alpha1.OIDCIdentityProviderPhase) *idpv1alpha1.OIDCIdentityProvider {
	t.Helper()
	return CreateTestOIDCIdentityProviderWithObjectMeta(t, spec, TestObjectMeta(t, "upstream-oidc-idp"), expectedPhase)
}

func CreateTestOIDCIdentityProviderWithObjectMeta(t *testing.T, spec idpv1alpha1.OIDCIdentityProviderSpec, objectMeta metav1.ObjectMeta, expectedPhase idpv1alpha1.OIDCIdentityProviderPhase) *idpv1alpha1.OIDCIdentityProvider {
	t.Helper()
	env := IntegrationEnv(t)
	client := NewSupervisorClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	upstreams := client.IDPV1alpha1().OIDCIdentityProviders(env.SupervisorNamespace)

	// Create the OIDCIdentityProvider using GenerateName to get a random name.
	created, err := upstreams.Create(ctx, &idpv1alpha1.OIDCIdentityProvider{
		ObjectMeta: objectMeta,
		Spec:       spec,
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	// Always clean this up after this point.
	t.Cleanup(func() {
		t.Logf("cleaning up test OIDCIdentityProvider %s/%s", created.Namespace, created.Name)
		err := upstreams.Delete(context.Background(), created.Name, metav1.DeleteOptions{})
		notFound := apierrors.IsNotFound(err)
		// It's okay if it is not found, because it might have been deleted by another part of this test.
		if !notFound {
			require.NoErrorf(t, err, "could not cleanup test OIDCIdentityProvider %s/%s", created.Namespace, created.Name)
		}
	})
	t.Logf("created test OIDCIdentityProvider %s", created.Name)

	// Wait for the OIDCIdentityProvider to enter the expected phase (or time out).
	var result *idpv1alpha1.OIDCIdentityProvider
	RequireEventuallyf(t, func(requireEventually *require.Assertions) {
		var err error
		result, err = upstreams.Get(ctx, created.Name, metav1.GetOptions{})
		requireEventually.NoErrorf(err, "error while getting OIDCIdentityProvider %s/%s", created.Namespace, created.Name)
		requireEventually.Equal(expectedPhase, result.Status.Phase)
	}, 60*time.Second, 1*time.Second, "expected the OIDCIdentityProvider to go into phase %s, OIDCIdentityProvider was: %s", expectedPhase, Sdump(result))
	return result
}

func CreateTestLDAPIdentityProvider(t *testing.T, spec idpv1alpha1.LDAPIdentityProviderSpec, expectedPhase idpv1alpha1.LDAPIdentityProviderPhase) *idpv1alpha1.LDAPIdentityProvider {
	t.Helper()
	env := IntegrationEnv(t)
	client := NewSupervisorClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	upstreams := client.IDPV1alpha1().LDAPIdentityProviders(env.SupervisorNamespace)

	// Create the LDAPIdentityProvider using GenerateName to get a random name.
	created, err := upstreams.Create(ctx, &idpv1alpha1.LDAPIdentityProvider{
		ObjectMeta: TestObjectMeta(t, "upstream-ldap-idp"),
		Spec:       spec,
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	// Always clean this up after this point.
	t.Cleanup(func() {
		t.Logf("cleaning up test LDAPIdentityProvider %s/%s", created.Namespace, created.Name)
		err := upstreams.Delete(context.Background(), created.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})
	t.Logf("created test LDAPIdentityProvider %s", created.Name)

	// Wait for the LDAPIdentityProvider to enter the expected phase (or time out).
	var result *idpv1alpha1.LDAPIdentityProvider
	RequireEventuallyf(t,
		func(requireEventually *require.Assertions) {
			var err error
			result, err = upstreams.Get(ctx, created.Name, metav1.GetOptions{})
			requireEventually.NoErrorf(err, "error while getting LDAPIdentityProvider %s/%s", created.Namespace, created.Name)
			requireEventually.Equalf(expectedPhase, result.Status.Phase, "LDAPIdentityProvider is not in phase %s: %v", expectedPhase, Sdump(result))
		},
		2*time.Minute, // it takes 1 minute for a failed LDAP TLS connection test to timeout before it tries using StartTLS, so wait longer than that
		1*time.Second,
		"expected the LDAPIdentityProvider to go into phase %s",
		expectedPhase,
	)
	return result
}

func CreateTestActiveDirectoryIdentityProvider(t *testing.T, spec idpv1alpha1.ActiveDirectoryIdentityProviderSpec, expectedPhase idpv1alpha1.ActiveDirectoryIdentityProviderPhase) *idpv1alpha1.ActiveDirectoryIdentityProvider {
	t.Helper()
	env := IntegrationEnv(t)
	client := NewSupervisorClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	upstreams := client.IDPV1alpha1().ActiveDirectoryIdentityProviders(env.SupervisorNamespace)

	// Create the ActiveDirectoryIdentityProvider using GenerateName to get a random name.
	created, err := upstreams.Create(ctx, &idpv1alpha1.ActiveDirectoryIdentityProvider{
		ObjectMeta: TestObjectMeta(t, "upstream-ad-idp"),
		Spec:       spec,
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	// Always clean this up after this point.
	t.Cleanup(func() {
		t.Logf("cleaning up test ActiveDirectoryIdentityProvider %s/%s", created.Namespace, created.Name)
		err := upstreams.Delete(context.Background(), created.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})
	t.Logf("created test ActiveDirectoryIdentityProvider %s", created.Name)

	// Wait for the ActiveDirectoryIdentityProvider to enter the expected phase (or time out).
	var result *idpv1alpha1.ActiveDirectoryIdentityProvider
	RequireEventuallyf(t,
		func(requireEventually *require.Assertions) {
			var err error
			result, err = upstreams.Get(ctx, created.Name, metav1.GetOptions{})
			requireEventually.NoErrorf(err, "error while getting ActiveDirectoryIdentityProvider %s/%s", created.Namespace, created.Name)
			requireEventually.Equalf(expectedPhase, result.Status.Phase, "ActiveDirectoryIdentityProvider is not in phase %s: %v", expectedPhase, Sdump(result))
		},
		2*time.Minute, // it takes 1 minute for a failed LDAP TLS connection test to timeout before it tries using StartTLS, so wait longer than that
		1*time.Second,
		"expected the ActiveDirectoryIdentityProvider to go into phase %s",
		expectedPhase,
	)
	return result
}

func CreateGitHubIdentityProvider(t *testing.T, spec idpv1alpha1.GitHubIdentityProviderSpec, expectedPhase idpv1alpha1.GitHubIdentityProviderPhase) *idpv1alpha1.GitHubIdentityProvider {
	t.Helper()
	env := IntegrationEnv(t)
	client := NewSupervisorClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	upstreams := client.IDPV1alpha1().GitHubIdentityProviders(env.SupervisorNamespace)

	// Create the GitHubIdentityProvider using GenerateName to get a random name.
	created, err := upstreams.Create(ctx, &idpv1alpha1.GitHubIdentityProvider{
		ObjectMeta: TestObjectMeta(t, "upstream-github-idp"),
		Spec:       spec,
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	// Always clean this up after this point.
	t.Cleanup(func() {
		t.Logf("cleaning up test GitHubIdentityProvider %s/%s", created.Namespace, created.Name)
		err := upstreams.Delete(context.Background(), created.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})
	t.Logf("created test GitHubIdentityProvider %s", created.Name)

	// Wait for the GitHubIdentityProvider to enter the expected phase (or time out).
	var result *idpv1alpha1.GitHubIdentityProvider
	RequireEventuallyf(t, func(requireEventually *require.Assertions) {
		var err error
		result, err = upstreams.Get(ctx, created.Name, metav1.GetOptions{})
		requireEventually.NoErrorf(err, "error while getting GitHubIdentityProvider %s/%s", created.Namespace, created.Name)
		requireEventually.Equal(expectedPhase, result.Status.Phase)
	}, 60*time.Second, 1*time.Second, "expected the GitHubIdentityProvider to go into phase %s, GitHubIdentityProvider was: %s", expectedPhase, Sdump(result))
	return result
}

func CreateTestClusterRoleBinding(t *testing.T, subject rbacv1.Subject, roleRef rbacv1.RoleRef) *rbacv1.ClusterRoleBinding {
	t.Helper()
	client := NewKubernetesClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	clusterRoles := client.RbacV1().ClusterRoleBindings()

	// Create the ClusterRoleBinding using GenerateName to get a random name.
	created, err := clusterRoles.Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: TestObjectMeta(t, "cluster-role"),
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

func CreateTokenCredentialRequest(ctx context.Context, t *testing.T, spec v1alpha1.TokenCredentialRequestSpec) (*v1alpha1.TokenCredentialRequest, error) {
	t.Helper()

	client := NewAnonymousConciergeClientset(t)

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	return client.LoginV1alpha1().TokenCredentialRequests().Create(ctx,
		&v1alpha1.TokenCredentialRequest{Spec: spec}, metav1.CreateOptions{},
	)
}

// RestrictiveSecurityContext returns a container SecurityContext which will be allowed by the most
// restrictive level of Pod Security Admission policy (as of Kube v1.25's policies).
func RestrictiveSecurityContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
		RunAsNonRoot:             ptr.To(true),
		AllowPrivilegeEscalation: ptr.To(false),
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

func CreatePod(ctx context.Context, t *testing.T, name, namespace string, spec corev1.PodSpec) *corev1.Pod {
	t.Helper()

	client := NewKubernetesClientset(t)
	pods := client.CoreV1().Pods(namespace)

	const podCreateTimeout = 4 * time.Minute // it may take some time for the cluster to pull the container image
	ctx, cancel := context.WithTimeout(ctx, podCreateTimeout+time.Minute)
	defer cancel()

	created, err := pods.Create(ctx, &corev1.Pod{ObjectMeta: TestObjectMeta(t, name), Spec: spec}, metav1.CreateOptions{})
	require.NoError(t, err)
	t.Logf("created test Pod %s", created.Name)

	t.Cleanup(func() {
		t.Logf("cleaning up test Pod %s", created.Name)
		err := pods.Delete(context.Background(), created.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})

	var result *corev1.Pod
	RequireEventuallyf(t, func(requireEventually *require.Assertions) {
		var err error
		result, err = pods.Get(ctx, created.Name, metav1.GetOptions{})
		requireEventually.NoError(err)
		requireEventually.Equal(corev1.PodRunning, result.Status.Phase)
	}, podCreateTimeout, 1*time.Second, "expected the Pod to go into phase %s", corev1.PodRunning)
	return result
}

func CreateNamespace(ctx context.Context, t *testing.T, name string) *corev1.Namespace {
	t.Helper()

	adminClient := NewKubernetesClientset(t)

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	namespace, err := adminClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: name + "-integration-test-"},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		t.Logf("cleaning up test namespace %s", namespace.Name)
		require.NoError(t, adminClient.CoreV1().Namespaces().Delete(ctx, namespace.Name, metav1.DeleteOptions{}))
	})

	return namespace
}

func WaitForUserToHaveAccess(t *testing.T, user string, groups []string, shouldHaveAccessTo *authorizationv1.ResourceAttributes) {
	t.Helper()
	client := NewKubernetesClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	RequireEventuallyWithoutError(t, func() (bool, error) {
		subjectAccessReview, err := client.AuthorizationV1().SubjectAccessReviews().Create(ctx,
			&authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					ResourceAttributes: shouldHaveAccessTo,
					User:               user,
					Groups:             groups,
				}}, metav1.CreateOptions{})
		if err != nil {
			return false, err
		}
		return subjectAccessReview.Status.Allowed, nil
	}, time.Minute, 500*time.Millisecond)
}

func WaitForGitHubIDPPhase(
	ctx context.Context,
	t *testing.T,
	client alpha1.GitHubIdentityProviderInterface,
	gitHubIDPName string,
	expectPhase idpv1alpha1.GitHubIdentityProviderPhase,
) {
	t.Helper()

	RequireEventuallyf(t, func(requireEventually *require.Assertions) {
		idp, err := client.Get(ctx, gitHubIDPName, metav1.GetOptions{})
		requireEventually.NoError(err)
		requireEventually.Equalf(expectPhase, idp.Status.Phase, "actual status conditions were: %#v", idp.Status.Conditions)
	}, 60*time.Second, 1*time.Second, "expected the GitHubIDP to have status %q", expectPhase)
}

func WaitForGitHubIdentityProviderStatusConditions(
	ctx context.Context,
	t *testing.T,
	client alpha1.GitHubIdentityProviderInterface,
	gitHubIDPName string,
	expectConditions []*metav1.Condition,
) {
	t.Helper()

	RequireEventuallyf(t, func(requireEventually *require.Assertions) {
		idp, err := client.Get(ctx, gitHubIDPName, metav1.GetOptions{})
		requireEventually.NoError(err)

		actualConditions := make([]*metav1.Condition, len(idp.Status.Conditions))
		for i, c := range idp.Status.Conditions {
			actualConditions[i] = c.DeepCopy()
		}

		requireEventually.Lenf(actualConditions, len(expectConditions),
			"wanted status conditions: %#v", expectConditions)

		for i, wantCond := range expectConditions {
			actualCond := actualConditions[i]

			// This is a cheat to avoid needing to make equality assertions on these fields.
			requireEventually.NotZero(actualCond.LastTransitionTime)
			wantCond.LastTransitionTime = actualCond.LastTransitionTime
			requireEventually.NotZero(actualCond.ObservedGeneration)
			wantCond.ObservedGeneration = actualCond.ObservedGeneration

			requireEventually.Equalf(wantCond, actualCond,
				"wanted status conditions: %#v\nactual status conditions were: %#v\nnot equal at index %d",
				expectConditions, &actualConditions, i)
		}
	}, 60*time.Second, 1*time.Second, "wanted conditions for GitHubIdentityProvider %q", gitHubIDPName)
}

func WaitForLDAPIdentityProviderStatusConditions(
	ctx context.Context,
	t *testing.T,
	client alpha1.LDAPIdentityProviderInterface,
	ldapIDPName string,
	expectConditions []*metav1.Condition,
) {
	t.Helper()

	RequireEventuallyf(t, func(requireEventually *require.Assertions) {
		idp, err := client.Get(ctx, ldapIDPName, metav1.GetOptions{})
		requireEventually.NoError(err)

		actualConditions := make([]*metav1.Condition, len(idp.Status.Conditions))
		for i, c := range idp.Status.Conditions {
			actualConditions[i] = c.DeepCopy()
		}

		requireEventually.Lenf(actualConditions, len(expectConditions),
			"wanted status conditions: %#v", expectConditions)

		for i, wantCond := range expectConditions {
			actualCond := actualConditions[i]

			// This is a cheat to avoid needing to make equality assertions on these fields.
			requireEventually.NotZero(actualCond.LastTransitionTime)
			wantCond.LastTransitionTime = actualCond.LastTransitionTime
			requireEventually.NotZero(actualCond.ObservedGeneration)
			wantCond.ObservedGeneration = actualCond.ObservedGeneration

			requireEventually.Equalf(wantCond, actualCond,
				"wanted status conditions: %#v\nactual status conditions were: %#v\nnot equal at index %d",
				expectConditions, &actualConditions, i)
		}
	}, 60*time.Second, 1*time.Second, "wanted conditions for LDAPIdentityProvider %q", ldapIDPName)
}

func WaitForActiveDirectoryIdentityProviderStatusConditions(
	ctx context.Context,
	t *testing.T,
	client alpha1.ActiveDirectoryIdentityProviderInterface,
	activeDirectoryIDPName string,
	expectConditions []*metav1.Condition,
) {
	t.Helper()

	RequireEventuallyf(t, func(requireEventually *require.Assertions) {
		idp, err := client.Get(ctx, activeDirectoryIDPName, metav1.GetOptions{})
		requireEventually.NoError(err)

		actualConditions := make([]*metav1.Condition, len(idp.Status.Conditions))
		for i, c := range idp.Status.Conditions {
			actualConditions[i] = c.DeepCopy()
		}

		requireEventually.Lenf(actualConditions, len(expectConditions),
			"wanted status conditions: %#v", expectConditions)

		for i, wantCond := range expectConditions {
			actualCond := actualConditions[i]

			// This is a cheat to avoid needing to make equality assertions on these fields.
			requireEventually.NotZero(actualCond.LastTransitionTime)
			wantCond.LastTransitionTime = actualCond.LastTransitionTime
			requireEventually.NotZero(actualCond.ObservedGeneration)
			wantCond.ObservedGeneration = actualCond.ObservedGeneration

			requireEventually.Equalf(wantCond, actualCond,
				"wanted status conditions: %#v\nactual status conditions were: %#v\nnot equal at index %d",
				expectConditions, &actualConditions, i)
		}
	}, 60*time.Second, 1*time.Second, "wanted conditions for ActiveDirectoryIdentityProvider %q", activeDirectoryIDPName)
}

func TestObjectMeta(t *testing.T, baseName string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		GenerateName: fmt.Sprintf("test-%s-", baseName),
		Labels:       map[string]string{"pinniped.dev/test": ""},
		Annotations:  map[string]string{"pinniped.dev/testName": t.Name()},
	}
}

func ObjectMetaWithRandomName(t *testing.T, baseName string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:        fmt.Sprintf("test-%s-%s", baseName, RandHex(t, 8)),
		Labels:      map[string]string{"pinniped.dev/test": ""},
		Annotations: map[string]string{"pinniped.dev/testName": t.Name()},
	}
}
