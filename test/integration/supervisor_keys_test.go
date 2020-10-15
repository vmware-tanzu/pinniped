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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	"go.pinniped.dev/test/library"
)

func TestSupervisorOIDCKeys(t *testing.T) {
	env := library.IntegrationEnv(t)
	kubeClient := library.NewClientset(t)
	pinnipedClient := library.NewPinnipedClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create our OPC under test.
	opc := library.CreateTestOIDCProvider(ctx, t, "")

	// Ensure a secret is created with the OPC's JWKS.
	var updatedOPC *configv1alpha1.OIDCProviderConfig
	var err error
	assert.Eventually(t, func() bool {
		updatedOPC, err = pinnipedClient.
			ConfigV1alpha1().
			OIDCProviderConfigs(env.SupervisorNamespace).
			Get(ctx, opc.Name, metav1.GetOptions{})
		return err == nil && updatedOPC.Status.JWKSSecret.Name != ""
	}, time.Second*10, time.Millisecond*500)
	require.NoError(t, err)
	require.NotEmpty(t, updatedOPC.Status.JWKSSecret.Name)

	// Ensure the secret actually exists.
	secret, err := kubeClient.
		CoreV1().
		Secrets(env.SupervisorNamespace).
		Get(ctx, updatedOPC.Status.JWKSSecret.Name, metav1.GetOptions{})
	require.NoError(t, err)

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

	// Ensure upon deleting the secret, it is eventually brought back.
	err = kubeClient.
		CoreV1().
		Secrets(env.SupervisorNamespace).
		Delete(ctx, updatedOPC.Status.JWKSSecret.Name, metav1.DeleteOptions{})
	require.NoError(t, err)
	assert.Eventually(t, func() bool {
		secret, err = kubeClient.
			CoreV1().
			Secrets(env.SupervisorNamespace).
			Get(ctx, updatedOPC.Status.JWKSSecret.Name, metav1.GetOptions{})
		return err == nil
	}, time.Second*10, time.Millisecond*500)
	require.NoError(t, err)

	// Upon deleting the OPC, the secret is deleted (we test this behavior in our uninstall tests).
}
