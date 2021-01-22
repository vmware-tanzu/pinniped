// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

	loginv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/test/library"
)

// Smoke test to see if the kubeconfig works and the cluster is reachable.
func TestImpersonationProxy(t *testing.T) {
	env := library.IntegrationEnv(t)
	if env.Proxy == "" {
		t.Skip("this test can only run in environments with the in-cluster proxy right now")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	// Create a client using the admin kubeconfig.
	adminClient := library.NewClientset(t)

	// Create a WebhookAuthenticator.
	authenticator := library.CreateTestWebhookAuthenticator(ctx, t)

	// Find the address of the ClusterIP service.
	proxyServiceURL := fmt.Sprintf("https://%s-proxy.%s.svc.cluster.local", env.ConciergeAppName, env.ConciergeNamespace)
	t.Logf("making kubeconfig that points to %q", proxyServiceURL)

	kubeconfig := &rest.Config{
		Host:            proxyServiceURL,
		TLSClientConfig: rest.TLSClientConfig{Insecure: true},
		BearerToken:     makeImpersonationTestToken(t, authenticator),
		Proxy: func(req *http.Request) (*url.URL, error) {
			proxyURL, err := url.Parse(env.Proxy)
			require.NoError(t, err)
			t.Logf("passing request for %s through proxy %s", req.URL, proxyURL.String())
			return proxyURL, nil
		},
	}

	clientset, err := kubernetes.NewForConfig(kubeconfig)
	require.NoError(t, err, "unexpected failure from kubernetes.NewForConfig()")

	t.Run(
		"access as user",
		library.AccessAsUserTest(ctx, adminClient, env.TestUser.ExpectedUsername, clientset),
	)
	for _, group := range env.TestUser.ExpectedGroups {
		group := group
		t.Run(
			"access as group "+group,
			library.AccessAsGroupTest(ctx, adminClient, group, clientset),
		)
	}
}

func makeImpersonationTestToken(t *testing.T, authenticator corev1.TypedLocalObjectReference) string {
	t.Helper()

	env := library.IntegrationEnv(t)
	reqJSON, err := json.Marshal(&loginv1alpha1.TokenCredentialRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: env.ConciergeNamespace,
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "TokenCredentialRequest",
			APIVersion: loginv1alpha1.GroupName + "/v1alpha1",
		},
		Spec: loginv1alpha1.TokenCredentialRequestSpec{
			Token:         env.TestUser.Token,
			Authenticator: authenticator,
		},
	})
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(reqJSON)
}
