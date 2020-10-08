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
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.19/client/clientset/versioned"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/test/library"
)

func TestSupervisorOIDCDiscovery(t *testing.T) {
	env := library.IntegrationEnv(t)
	client := library.NewPinnipedClientset(t)

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
	requireDiscoveryEndpointIsNotFound(t, fmt.Sprintf("http://%s", env.SupervisorAddress))

	// Define several unique issuer strings.
	issuer1 := fmt.Sprintf("http://%s/nested/issuer1", env.SupervisorAddress)
	issuer2 := fmt.Sprintf("http://%s/nested/issuer2", env.SupervisorAddress)
	issuer3 := fmt.Sprintf("http://%s/issuer3", env.SupervisorAddress)
	issuer4 := fmt.Sprintf("http://%s/issuer4", env.SupervisorAddress)

	// When OIDCProviderConfig are created in sequence they each cause a discovery endpoint to appear only for as long as the OIDCProviderConfig exists.
	createdOIDCProviderConfig1 := requireCreatingOIDCProviderConfigCausesWellKnownEndpointToAppear(t, client, ns, issuer1, "from-integration-test1")
	requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(t, createdOIDCProviderConfig1, client, ns, issuer1)
	createdOIDCProviderConfig2 := requireCreatingOIDCProviderConfigCausesWellKnownEndpointToAppear(t, client, ns, issuer2, "from-integration-test2")
	requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(t, createdOIDCProviderConfig2, client, ns, issuer2)

	// When multiple OIDCProviderConfigs exist at the same time they each serve a unique discovery endpoint.
	createdOIDCProviderConfig3 := requireCreatingOIDCProviderConfigCausesWellKnownEndpointToAppear(t, client, ns, issuer3, "from-integration-test3")
	createdOIDCProviderConfig4 := requireCreatingOIDCProviderConfigCausesWellKnownEndpointToAppear(t, client, ns, issuer4, "from-integration-test4")
	requireWellKnownEndpointIsWorking(t, issuer3) // discovery for issuer3 is still working after issuer4 started working

	// When they are deleted they stop serving discovery endpoints.
	requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(t, createdOIDCProviderConfig3, client, ns, issuer2)
	requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(t, createdOIDCProviderConfig4, client, ns, issuer2)
}

func requireDiscoveryEndpointIsNotFound(t *testing.T, issuerName string) {
	t.Helper()
	httpClient := &http.Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	requestNonExistentPath, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("%s/.well-known/openid-configuration", issuerName),
		nil,
	)

	var response *http.Response
	assert.Eventually(t, func() bool {
		response, err = httpClient.Do(requestNonExistentPath) //nolint:bodyclose
		return err == nil && response.StatusCode == http.StatusNotFound
	}, 10*time.Second, 200*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, response.StatusCode)
	err = response.Body.Close()
	require.NoError(t, err)
}

func requireCreatingOIDCProviderConfigCausesWellKnownEndpointToAppear(t *testing.T, client pinnipedclientset.Interface, ns string, issuerName string, oidcProviderConfigName string) *v1alpha1.OIDCProviderConfig {
	t.Helper()
	newOIDCProviderConfig := createOIDCProviderConfig(t, oidcProviderConfigName, client, ns, issuerName)
	requireWellKnownEndpointIsWorking(t, issuerName)
	return newOIDCProviderConfig
}

func requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(t *testing.T, existingOIDCProviderConfig *v1alpha1.OIDCProviderConfig, client pinnipedclientset.Interface, ns string, issuerName string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Delete the OIDCProviderConfig.
	err := client.ConfigV1alpha1().OIDCProviderConfigs(ns).Delete(ctx, existingOIDCProviderConfig.Name, metav1.DeleteOptions{})
	require.NoError(t, err)

	// Fetch that same discovery endpoint as before, but now it should not exist anymore. Give it some time for the endpoint to go away.
	requireDiscoveryEndpointIsNotFound(t, issuerName)
}

func requireWellKnownEndpointIsWorking(t *testing.T, issuerName string) {
	t.Helper()
	httpClient := &http.Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Define a request to the new discovery endpoint which should have been created by an OIDCProviderConfig.
	requestDiscoveryEndpoint, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("%s/.well-known/openid-configuration", issuerName),
		nil,
	)
	require.NoError(t, err)

	// Fetch that discovery endpoint. Give it some time for the endpoint to come into existence.
	var response *http.Response
	assert.Eventually(t, func() bool {
		response, err = httpClient.Do(requestDiscoveryEndpoint) //nolint:bodyclose
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
      "authorization_endpoint": "%s/oauth2/v0/auth",
      "token_endpoint": "%s/oauth2/v0/token",
      "token_endpoint_auth_methods_supported": ["client_secret_basic"],
      "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
      "jwks_uri": "%s/jwks.json",
      "scopes_supported": ["openid", "offline"],
      "response_types_supported": ["code"],
      "claims_supported": ["groups"],
      "subject_types_supported": ["public"],
      "id_token_signing_alg_values_supported": ["RS256"]
    }`)
	expectedJSON := fmt.Sprintf(expectedResultTemplate, issuerName, issuerName, issuerName, issuerName)

	require.Equal(t, "application/json", response.Header.Get("content-type"))
	require.JSONEq(t, expectedJSON, string(responseBody))
}

func createOIDCProviderConfig(t *testing.T, oidcProviderConfigName string, client pinnipedclientset.Interface, ns string, issuerName string) *v1alpha1.OIDCProviderConfig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	newOIDCProviderConfig := v1alpha1.OIDCProviderConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       "OIDCProviderConfig",
			APIVersion: v1alpha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      oidcProviderConfigName,
			Namespace: ns,
		},
		Spec: v1alpha1.OIDCProviderConfigSpec{
			Issuer: issuerName,
		},
	}
	createdOIDCProviderConfig, err := client.ConfigV1alpha1().OIDCProviderConfigs(ns).Create(ctx, &newOIDCProviderConfig, metav1.CreateOptions{})
	require.NoError(t, err)

	// When this test has finished, be sure to clean up the new OIDCProviderConfig.
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		err = client.ConfigV1alpha1().OIDCProviderConfigs(ns).Delete(cleanupCtx, newOIDCProviderConfig.Name, metav1.DeleteOptions{})
		notFound := k8serrors.IsNotFound(err)
		// It's okay if it is not found, because it might have been deleted by another part of this test.
		if !notFound {
			require.NoError(t, err)
		}
	})

	return createdOIDCProviderConfig
}
