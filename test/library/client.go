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
	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.19/client/clientset/versioned"

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

func NewPinnipedClientset(t *testing.T) pinnipedclientset.Interface {
	t.Helper()

	return pinnipedclientset.NewForConfigOrDie(NewClientConfig(t))
}

func NewAnonymousPinnipedClientset(t *testing.T) pinnipedclientset.Interface {
	t.Helper()

	return pinnipedclientset.NewForConfigOrDie(newAnonymousClientRestConfig(t))
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

// CreateTestWebhookIDP creates and returns a test WebhookIdentityProvider in $PINNIPED_TEST_CONCIERGE_NAMESPACE, which will be
// automatically deleted at the end of the current test's lifetime. It returns a corev1.TypedLocalObjectReference which
// descibes the test IDP within the test namespace.
func CreateTestWebhookIDP(ctx context.Context, t *testing.T) corev1.TypedLocalObjectReference {
	t.Helper()
	testEnv := IntegrationEnv(t)

	client := NewPinnipedClientset(t)
	webhooks := client.AuthenticationV1alpha1().WebhookIdentityProviders(testEnv.ConciergeNamespace)

	createContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	idp, err := webhooks.Create(createContext, &auth1alpha1.WebhookIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-webhook-",
			Labels:       map[string]string{"pinniped.dev/test": ""},
			Annotations:  map[string]string{"pinniped.dev/testName": t.Name()},
		},
		Spec: testEnv.TestWebhook,
	}, metav1.CreateOptions{})
	require.NoError(t, err, "could not create test WebhookIdentityProvider")
	t.Logf("created test WebhookIdentityProvider %s/%s", idp.Namespace, idp.Name)

	t.Cleanup(func() {
		t.Helper()
		t.Logf("cleaning up test WebhookIdentityProvider %s/%s", idp.Namespace, idp.Name)
		deleteCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := webhooks.Delete(deleteCtx, idp.Name, metav1.DeleteOptions{})
		require.NoErrorf(t, err, "could not cleanup test WebhookIdentityProvider %s/%s", idp.Namespace, idp.Name)
	})

	return corev1.TypedLocalObjectReference{
		APIGroup: &auth1alpha1.SchemeGroupVersion.Group,
		Kind:     "WebhookIdentityProvider",
		Name:     idp.Name,
	}
}

// CreateTestOIDCProvider creates and returns a test OIDCProviderConfig in
// $PINNIPED_TEST_SUPERVISOR_NAMESPACE, which will be automatically deleted at the end of the
// current test's lifetime. It generates a random, valid, issuer for the OIDCProviderConfig.
//
// If the provided issuer is not the empty string, then it will be used for the
// OIDCProviderConfig.Spec.Issuer field. Else, a random issuer will be generated.
func CreateTestOIDCProvider(ctx context.Context, t *testing.T, issuer, sniCertificateSecretName string) *configv1alpha1.OIDCProviderConfig {
	t.Helper()
	testEnv := IntegrationEnv(t)

	createContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if issuer == "" {
		var err error
		issuer, err = randomIssuer()
		require.NoError(t, err)
	}

	opcs := NewPinnipedClientset(t).ConfigV1alpha1().OIDCProviderConfigs(testEnv.SupervisorNamespace)
	opc, err := opcs.Create(createContext, &configv1alpha1.OIDCProviderConfig{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-oidc-provider-",
			Labels:       map[string]string{"pinniped.dev/test": ""},
			Annotations:  map[string]string{"pinniped.dev/testName": t.Name()},
		},
		Spec: configv1alpha1.OIDCProviderConfigSpec{
			Issuer:                   issuer,
			SNICertificateSecretName: sniCertificateSecretName,
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err, "could not create test OIDCProviderConfig")
	t.Logf("created test OIDCProviderConfig %s/%s", opc.Namespace, opc.Name)

	t.Cleanup(func() {
		t.Helper()
		t.Logf("cleaning up test OIDCProviderConfig %s/%s", opc.Namespace, opc.Name)
		deleteCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := opcs.Delete(deleteCtx, opc.Name, metav1.DeleteOptions{})
		notFound := k8serrors.IsNotFound(err)
		// It's okay if it is not found, because it might have been deleted by another part of this test.
		if !notFound {
			require.NoErrorf(t, err, "could not cleanup test OIDCProviderConfig %s/%s", opc.Namespace, opc.Name)
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
