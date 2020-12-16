// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/supervisor/config/v1alpha1"
	"go.pinniped.dev/test/library"
)

func TestSupervisorSecrets(t *testing.T) {
	env := library.IntegrationEnv(t)
	kubeClient := library.NewClientset(t)
	supervisorClient := library.NewSupervisorClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create our OP under test.
	op := library.CreateTestOIDCProvider(ctx, t, "", "", "")

	tests := []struct {
		name        string
		secretName  func(op *configv1alpha1.OIDCProvider) string
		ensureValid func(t *testing.T, secret *corev1.Secret)
	}{
		{
			name: "csrf cookie signing key",
			secretName: func(op *configv1alpha1.OIDCProvider) string {
				return env.SupervisorAppName + "-key"
			},
			ensureValid: ensureValidSymmetricKey,
		},
		{
			name: "jwks",
			secretName: func(op *configv1alpha1.OIDCProvider) string {
				return op.Status.Secrets.JWKS.Name
			},
			ensureValid: ensureValidJWKS,
		},
		{
			name: "hmac signing secret",
			secretName: func(op *configv1alpha1.OIDCProvider) string {
				return op.Status.Secrets.TokenSigningKey.Name
			},
			ensureValid: ensureValidSymmetricKey,
		},
		{
			name: "state signature secret",
			secretName: func(op *configv1alpha1.OIDCProvider) string {
				return op.Status.Secrets.StateSigningKey.Name
			},
			ensureValid: ensureValidSymmetricKey,
		},
		{
			name: "state encryption secret",
			secretName: func(op *configv1alpha1.OIDCProvider) string {
				return op.Status.Secrets.StateEncryptionKey.Name
			},
			ensureValid: ensureValidSymmetricKey,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Ensure a secret is created with the OP's JWKS.
			var updatedOP *configv1alpha1.OIDCProvider
			var err error
			assert.Eventually(t, func() bool {
				updatedOP, err = supervisorClient.
					ConfigV1alpha1().
					OIDCProviders(env.SupervisorNamespace).
					Get(ctx, op.Name, metav1.GetOptions{})
				return err == nil && test.secretName(updatedOP) != ""
			}, time.Second*10, time.Millisecond*500)
			require.NoError(t, err)
			require.NotEmpty(t, test.secretName(updatedOP))

			// Ensure the secret actually exists.
			secret, err := kubeClient.
				CoreV1().
				Secrets(env.SupervisorNamespace).
				Get(ctx, test.secretName(updatedOP), metav1.GetOptions{})
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
				Delete(ctx, test.secretName(updatedOP), metav1.DeleteOptions{})
			require.NoError(t, err)
			assert.Eventually(t, func() bool {
				secret, err = kubeClient.
					CoreV1().
					Secrets(env.SupervisorNamespace).
					Get(ctx, test.secretName(updatedOP), metav1.GetOptions{})
				return err == nil
			}, time.Second*10, time.Millisecond*500)
			require.NoError(t, err)

			// Ensure that the new secret is valid.
			test.ensureValid(t, secret)
		})
	}

	// Upon deleting the OP, the secret is deleted (we test this behavior in our uninstall tests).
}

func ensureValidJWKS(t *testing.T, secret *corev1.Secret) {
	t.Helper()

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

func ensureValidSymmetricKey(t *testing.T, secret *corev1.Secret) {
	t.Helper()
	require.Equal(t, corev1.SecretType("secrets.pinniped.dev/symmetric"), secret.Type)
	key, ok := secret.Data["key"]
	require.Truef(t, ok, "secret data does not contain 'key': %s", secret.Data)
	require.Equal(t, 32, len(key))
}
