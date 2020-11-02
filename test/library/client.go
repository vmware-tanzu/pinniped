// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package library

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	auth1alpha1 "go.pinniped.dev/generated/1.19/apis/concierge/authentication/v1alpha1"
	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/supervisor/config/v1alpha1"
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

	kubeConfigFile, err := ioutil.TempFile("", "pinniped-cli-test-*")
	require.NoError(t, err)
	defer os.Remove(kubeConfigFile.Name())

	_, err = kubeConfigFile.Write([]byte(kubeConfig))
	require.NoError(t, err)

	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile.Name())
	require.NoError(t, err)

	return newClientsetWithConfig(t, restConfig)
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
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-webhook-",
			Labels:       map[string]string{"pinniped.dev/test": ""},
			Annotations:  map[string]string{"pinniped.dev/testName": t.Name()},
		},
		Spec: testEnv.TestWebhook,
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

// CreateTestOIDCProvider creates and returns a test OIDCProvider in
// $PINNIPED_TEST_SUPERVISOR_NAMESPACE, which will be automatically deleted at the end of the
// current test's lifetime. It generates a random, valid, issuer for the OIDCProvider.
//
// If the provided issuer is not the empty string, then it will be used for the
// OIDCProvider.Spec.Issuer field. Else, a random issuer will be generated.
func CreateTestOIDCProvider(ctx context.Context, t *testing.T, issuer, certSecretName string) *configv1alpha1.OIDCProvider {
	t.Helper()
	testEnv := IntegrationEnv(t)

	createContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if issuer == "" {
		var err error
		issuer, err = randomIssuer()
		require.NoError(t, err)
	}

	opcs := NewSupervisorClientset(t).ConfigV1alpha1().OIDCProviders(testEnv.SupervisorNamespace)
	opc, err := opcs.Create(createContext, &configv1alpha1.OIDCProvider{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-oidc-provider-",
			Labels:       map[string]string{"pinniped.dev/test": ""},
			Annotations:  map[string]string{"pinniped.dev/testName": t.Name()},
		},
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

	return opc
}

func randomIssuer() (string, error) {
	var buf [8]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return "", fmt.Errorf("could not generate random state: %w", err)
	}
	return fmt.Sprintf("http://test-issuer-%s.pinniped.dev", hex.EncodeToString(buf[:])), nil
}
