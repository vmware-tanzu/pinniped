// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/generated/1.19/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/test/library"
)

func TestSupervisorUpstreamOIDCDiscovery(t *testing.T) {
	env := library.IntegrationEnv(t)

	t.Run("invalid missing secret and bad issuer", func(t *testing.T) {
		t.Parallel()
		spec := v1alpha1.UpstreamOIDCProviderSpec{
			Issuer: "https://127.0.0.1:444444/issuer",
			Client: v1alpha1.OIDCClient{
				SecretName: "does-not-exist",
			},
		}
		upstream := makeTestUpstream(t, spec, v1alpha1.PhaseError)
		expectUpstreamConditions(t, upstream, []v1alpha1.Condition{
			{
				Type:    "ClientCredentialsValid",
				Status:  v1alpha1.ConditionFalse,
				Reason:  "SecretNotFound",
				Message: `secret "does-not-exist" not found`,
			},
			{
				Type:    "OIDCDiscoverySucceeded",
				Status:  v1alpha1.ConditionFalse,
				Reason:  "Unreachable",
				Message: `failed to perform OIDC discovery against "https://127.0.0.1:444444/issuer"`,
			},
		})
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		spec := v1alpha1.UpstreamOIDCProviderSpec{
			Issuer: env.OIDCUpstream.Issuer,
			TLS: &v1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.OIDCUpstream.CABundle)),
			},
			AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{
				AdditionalScopes: []string{"email", "profile"},
			},
			Client: v1alpha1.OIDCClient{
				SecretName: makeTestClientCredsSecret(t, "test-client-id", "test-client-secret").Name,
			},
		}
		upstream := makeTestUpstream(t, spec, v1alpha1.PhaseReady)
		expectUpstreamConditions(t, upstream, []v1alpha1.Condition{
			{
				Type:    "ClientCredentialsValid",
				Status:  v1alpha1.ConditionTrue,
				Reason:  "Success",
				Message: "loaded client credentials",
			},
			{
				Type:    "OIDCDiscoverySucceeded",
				Status:  v1alpha1.ConditionTrue,
				Reason:  "Success",
				Message: "discovered issuer configuration",
			},
		})
	})
}

func expectUpstreamConditions(t *testing.T, upstream *v1alpha1.UpstreamOIDCProvider, expected []v1alpha1.Condition) {
	t.Helper()
	normalized := make([]v1alpha1.Condition, 0, len(upstream.Status.Conditions))
	for _, c := range upstream.Status.Conditions {
		c.ObservedGeneration = 0
		c.LastTransitionTime = metav1.Time{}
		normalized = append(normalized, c)
	}
	require.ElementsMatch(t, expected, normalized)
}

func makeTestClientCredsSecret(t *testing.T, clientID string, clientSecret string) *corev1.Secret {
	t.Helper()
	env := library.IntegrationEnv(t)
	client := library.NewClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	created, err := client.CoreV1().Secrets(env.SupervisorNamespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    env.SupervisorNamespace,
			GenerateName: "test-client-creds-",
			Labels:       map[string]string{"pinniped.dev/test": ""},
			Annotations:  map[string]string{"pinniped.dev/testName": t.Name()},
		},
		Type: "secrets.pinniped.dev/oidc-client",
		StringData: map[string]string{
			"clientID":     clientID,
			"clientSecret": clientSecret,
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		err := client.CoreV1().Secrets(env.SupervisorNamespace).Delete(context.Background(), created.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})
	t.Logf("created test client credentials Secret %s", created.Name)
	return created
}

func makeTestUpstream(t *testing.T, spec v1alpha1.UpstreamOIDCProviderSpec, expectedPhase v1alpha1.UpstreamOIDCProviderPhase) *v1alpha1.UpstreamOIDCProvider {
	t.Helper()
	env := library.IntegrationEnv(t)
	client := library.NewSupervisorClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create the UpstreamOIDCProvider using GenerateName to get a random name.
	created, err := client.IDPV1alpha1().
		UpstreamOIDCProviders(env.SupervisorNamespace).
		Create(ctx, &v1alpha1.UpstreamOIDCProvider{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:    env.SupervisorNamespace,
				GenerateName: "test-upstream-",
				Labels:       map[string]string{"pinniped.dev/test": ""},
				Annotations:  map[string]string{"pinniped.dev/testName": t.Name()},
			},
			Spec: spec,
		}, metav1.CreateOptions{})
	require.NoError(t, err)

	// Always clean this up after this point.
	t.Cleanup(func() {
		err := client.IDPV1alpha1().
			UpstreamOIDCProviders(env.SupervisorNamespace).
			Delete(context.Background(), created.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})
	t.Logf("created test UpstreamOIDCProvider %s", created.Name)

	// Wait for the UpstreamOIDCProvider to enter the expected phase (or time out).
	var result *v1alpha1.UpstreamOIDCProvider
	require.Eventuallyf(t, func() bool {
		var err error
		result, err = client.IDPV1alpha1().
			UpstreamOIDCProviders(created.Namespace).Get(ctx, created.Name, metav1.GetOptions{})
		require.NoError(t, err)
		return result.Status.Phase == expectedPhase
	}, 60*time.Second, 1*time.Second, "expected the UpstreamOIDCProvider to go into phase %s", expectedPhase)
	return result
}
