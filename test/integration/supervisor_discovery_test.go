// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/test/library"
)

func TestSupervisorOIDCDiscovery(t *testing.T) {
	env := library.IntegrationEnv(t)
	client := library.NewPinnipedClientset(t)

	httpClient := &http.Client{}
	ns := env.SupervisorNamespace
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Temporarily remove any existing OIDCProviderConfigs from the cluster so we can test from a clean slate.
	originalConfigList, err := client.ConfigV1alpha1().OIDCProviderConfigs(ns).List(ctx, metav1.ListOptions{})
	require.NoError(t, err)

	for _, config := range originalConfigList.Items {
		err := client.ConfigV1alpha1().OIDCProviderConfigs(ns).Delete(ctx, config.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	}

	// When this test has finished, recreate any OIDCProviderConfigs that had existed on the cluster before this test.
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		for _, config := range originalConfigList.Items {
			thisConfig := config
			thisConfig.ResourceVersion = "" // Get rid of resource version since we can't create an object with one.
			_, err := client.ConfigV1alpha1().OIDCProviderConfigs(ns).Create(cleanupCtx, &thisConfig, metav1.CreateOptions{})
			require.NoError(t, err)
		}
	})

	// Test that there is no default discovery endpoint available when there are no OIDCProviderConfigs.
	requestNonExistentPath, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("http://%s/.well-known/openid-configuration", env.SupervisorAddress),
		nil,
	)
	require.NoError(t, err)
	notFoundResponse, err := httpClient.Do(requestNonExistentPath)
	require.NoError(t, err)
	require.Equal(t, 404, notFoundResponse.StatusCode)
	err = notFoundResponse.Body.Close()
	require.NoError(t, err)

	// Create a new OIDCProviderConfig with a known issuer.
	issuer := fmt.Sprintf("http://%s/nested/issuer", env.SupervisorAddress)
	newOIDCProviderConfig := v1alpha1.OIDCProviderConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       "OIDCProviderConfig",
			APIVersion: v1alpha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nested-issuser-config-from-integration-test",
			Namespace: ns,
		},
		Spec: v1alpha1.OIDCProviderConfigSpec{
			Issuer: issuer,
		},
	}
	_, err = client.ConfigV1alpha1().OIDCProviderConfigs(ns).Create(ctx, &newOIDCProviderConfig, metav1.CreateOptions{})
	require.NoError(t, err)

	// When this test has finished, clean up the new OIDCProviderConfig.
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		err = client.ConfigV1alpha1().OIDCProviderConfigs(ns).Delete(cleanupCtx, newOIDCProviderConfig.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	})

	// Define a request to the new discovery endpoint which should have been created for the above OIDCProviderConfig.
	requestDiscoveryEndpoint, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("http://%s/nested/issuer/.well-known/openid-configuration", env.SupervisorAddress),
		nil,
	)
	require.NoError(t, err)

	// Fetch that discovery endpoint. Give it some time for the endpoint to come into existence.
	var response *http.Response
	assert.Eventually(t, func() bool {
		response, err = httpClient.Do(requestDiscoveryEndpoint) //nolint:bodyclose // the body is closed below after it is read
		return err == nil && response.StatusCode == http.StatusOK
	}, 10*time.Second, 200*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)

	responseBody, err := ioutil.ReadAll(response.Body)
	require.NoError(t, err)
	err = response.Body.Close()
	require.NoError(t, err)

	// Check that the response matches our expectations.
	expectedResultTemplate := here.Doc(`{
      "issuer": "%s",
      "authorization_endpoint": "%s/connect/authorize",
      "token_endpoint": "%s/connect/token",
      "token_endpoint_auth_methods_supported": ["client_secret_basic"],
      "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
      "jwks_uri": "%s/jwks.json",
      "scopes_supported": ["openid", "offline"],
      "response_types_supported": ["code"],
      "claims_supported": ["groups"],
    }`)
	expectedJSON := fmt.Sprintf(expectedResultTemplate, issuer, issuer, issuer, issuer)

	require.Equal(t, "application/json", response.Header.Get("content-type"))
	require.JSONEq(t, expectedJSON, string(responseBody))
}
