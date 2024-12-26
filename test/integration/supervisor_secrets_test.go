// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	"go.pinniped.dev/test/testlib"
)

// safe to run in parallel with serial tests since it only interacts with a test local federation domain, see main_test.go.
func TestSupervisorSecrets_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	kubeClient := testlib.NewKubernetesClientset(t)
	supervisorClient := testlib.NewSupervisorClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	// Create our FederationDomain under test.
	federationDomain := testlib.CreateTestFederationDomain(ctx, t,
		supervisorconfigv1alpha1.FederationDomainSpec{
			Issuer: fmt.Sprintf("https://test-issuer-%s.pinniped.dev", testlib.RandHex(t, 8)),
		},
		supervisorconfigv1alpha1.FederationDomainPhaseError, // in phase error until there is an IDP created, but this test does not care
	)

	tests := []struct {
		name        string
		secretName  func(federationDomain *supervisorconfigv1alpha1.FederationDomain) string
		ensureValid func(t *testing.T, secret *corev1.Secret)
	}{
		{
			name: "csrf cookie signing key",
			secretName: func(federationDomain *supervisorconfigv1alpha1.FederationDomain) string {
				return env.SupervisorAppName + "-key"
			},
			ensureValid: ensureValidSymmetricSecretOfTypeFunc("secrets.pinniped.dev/supervisor-csrf-signing-key"),
		},
		{
			name: "jwks",
			secretName: func(federationDomain *supervisorconfigv1alpha1.FederationDomain) string {
				return federationDomain.Status.Secrets.JWKS.Name
			},
			ensureValid: ensureValidJWKS,
		},
		{
			name: "hmac signing secret",
			secretName: func(federationDomain *supervisorconfigv1alpha1.FederationDomain) string {
				return federationDomain.Status.Secrets.TokenSigningKey.Name
			},
			ensureValid: ensureValidSymmetricSecretOfTypeFunc("secrets.pinniped.dev/federation-domain-token-signing-key"),
		},
		{
			name: "state signature secret",
			secretName: func(federationDomain *supervisorconfigv1alpha1.FederationDomain) string {
				return federationDomain.Status.Secrets.StateSigningKey.Name
			},
			ensureValid: ensureValidSymmetricSecretOfTypeFunc("secrets.pinniped.dev/federation-domain-state-signing-key"),
		},
		{
			name: "state encryption secret",
			secretName: func(federationDomain *supervisorconfigv1alpha1.FederationDomain) string {
				return federationDomain.Status.Secrets.StateEncryptionKey.Name
			},
			ensureValid: ensureValidSymmetricSecretOfTypeFunc("secrets.pinniped.dev/federation-domain-state-encryption-key"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Ensure a secret is created with the FederationDomain's JWKS.
			var updatedFederationDomain *supervisorconfigv1alpha1.FederationDomain
			testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
				resp, err := supervisorClient.
					ConfigV1alpha1().
					FederationDomains(env.SupervisorNamespace).
					Get(ctx, federationDomain.Name, metav1.GetOptions{})
				requireEventually.NoError(err)
				requireEventually.NotEmpty(test.secretName(resp))
				updatedFederationDomain = resp
			}, time.Minute, time.Millisecond*500)

			// Ensure the secret actually exists.
			secret, err := kubeClient.
				CoreV1().
				Secrets(env.SupervisorNamespace).
				Get(ctx, test.secretName(updatedFederationDomain), metav1.GetOptions{})
			require.NoError(t, err)

			// Ensure that the secret was labelled.
			for k, v := range env.SupervisorCustomLabels {
				require.Equalf(t, v, secret.Labels[k], "expected secret to have label `%s: %s`", k, v)
			}
			require.Equal(t, env.SupervisorAppName, secret.Labels["app"])

			// Ensure that the secret is valid.
			test.ensureValid(t, secret)

			// Ensure upon deleting the secret, it is eventually brought back.
			err = kubeClient.
				CoreV1().
				Secrets(env.SupervisorNamespace).
				Delete(ctx, test.secretName(updatedFederationDomain), metav1.DeleteOptions{})
			require.NoError(t, err)
			testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
				var err error
				secret, err = kubeClient.
					CoreV1().
					Secrets(env.SupervisorNamespace).
					Get(ctx, test.secretName(updatedFederationDomain), metav1.GetOptions{})
				requireEventually.NoError(err)
			}, time.Minute, time.Millisecond*500)

			// Ensure that the new secret is valid.
			test.ensureValid(t, secret)
		})
	}

	// Upon deleting the FederationDomain, the secret is deleted (we test this behavior in our uninstall tests).
}

func ensureValidJWKS(t *testing.T, secret *corev1.Secret) {
	t.Helper()

	// Ensure the secret has the right type.
	require.Equal(t, corev1.SecretType("secrets.pinniped.dev/federation-domain-jwks"), secret.Type)

	// Ensure the secret has an active key.
	jwkData, ok := secret.Data["activeJWK"]
	require.True(t, ok, "secret is missing active jwk")

	// Ensure the secret's active key is valid.
	var activeJWK jose.JSONWebKey
	require.NoError(t, json.Unmarshal(jwkData, &activeJWK))
	require.True(t, activeJWK.Valid(), "active jwk is invalid")
	require.False(t, activeJWK.IsPublic(), "active jwk is public")

	// Ensure the secret has a JWKS.
	jwksData, ok := secret.Data["jwks"]
	require.True(t, ok, "secret is missing jwks")

	// Ensure the secret's JWKS is valid, public, and contains the singing key.
	var jwks jose.JSONWebKeySet
	require.NoError(t, json.Unmarshal(jwksData, &jwks))
	foundActiveJWK := false
	for _, jwk := range jwks.Keys {
		require.Truef(t, jwk.Valid(), "jwk %s is invalid", jwk.KeyID)
		require.Truef(t, jwk.IsPublic(), "jwk %s is not public", jwk.KeyID)
		if jwk.KeyID == activeJWK.KeyID {
			foundActiveJWK = true
		}
	}
	require.True(t, foundActiveJWK, "could not find active JWK in JWKS: %s", jwks)
}

func ensureValidSymmetricSecretOfTypeFunc(secretTypeValue string) func(*testing.T, *corev1.Secret) {
	return func(t *testing.T, secret *corev1.Secret) {
		t.Helper()
		require.Equal(t, corev1.SecretType(secretTypeValue), secret.Type)
		key, ok := secret.Data["key"]
		require.Truef(t, ok, "secret data does not contain 'key': %s", secret.Data)
		require.Equal(t, 32, len(key))
	}
}
