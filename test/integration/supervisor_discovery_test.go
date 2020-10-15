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
	issuer5 := fmt.Sprintf("http://%s/issuer5", env.SupervisorAddress)
	badIssuer := fmt.Sprintf("http://%s/badIssuer?cannot-use=queries", env.SupervisorAddress)

	// When OIDCProviderConfig are created in sequence they each cause a discovery endpoint to appear only for as long as the OIDCProviderConfig exists.
	config1 := requireCreatingOIDCProviderConfigCausesWellKnownEndpointToAppear(ctx, t, issuer1, client)
	requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(t, config1, client, ns, issuer1)
	config2 := requireCreatingOIDCProviderConfigCausesWellKnownEndpointToAppear(ctx, t, issuer2, client)
	requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(t, config2, client, ns, issuer2)

	// When multiple OIDCProviderConfigs exist at the same time they each serve a unique discovery endpoint.
	config3 := requireCreatingOIDCProviderConfigCausesWellKnownEndpointToAppear(ctx, t, issuer3, client)
	config4 := requireCreatingOIDCProviderConfigCausesWellKnownEndpointToAppear(ctx, t, issuer4, client)
	requireWellKnownEndpointIsWorking(t, issuer3) // discovery for issuer3 is still working after issuer4 started working

	// When they are deleted they stop serving discovery endpoints.
	requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(t, config3, client, ns, issuer3)
	requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(t, config4, client, ns, issuer4)

	// When the same issuer is added twice, both issuers are marked as duplicates, and neither provider is serving.
	config5Duplicate1 := requireCreatingOIDCProviderConfigCausesWellKnownEndpointToAppear(ctx, t, issuer5, client)
	config5Duplicate2 := library.CreateTestOIDCProvider(ctx, t, issuer5)
	requireStatus(t, client, ns, config5Duplicate1.Name, v1alpha1.DuplicateOIDCProviderStatus)
	requireStatus(t, client, ns, config5Duplicate2.Name, v1alpha1.DuplicateOIDCProviderStatus)
	requireDiscoveryEndpointIsNotFound(t, issuer5)

	// If we delete the first duplicate issuer, the second duplicate issuer starts serving.
	requireDelete(t, client, ns, config5Duplicate1.Name)
	requireWellKnownEndpointIsWorking(t, issuer5)
	requireStatus(t, client, ns, config5Duplicate2.Name, v1alpha1.SuccessOIDCProviderStatus)

	// When we finally delete all issuers, the endpoint should be down.
	requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(t, config5Duplicate2, client, ns, issuer5)

	// When we create a provider with an invalid issuer, the status is set to invalid.
	badConfig := library.CreateTestOIDCProvider(ctx, t, badIssuer)
	requireStatus(t, client, ns, badConfig.Name, v1alpha1.InvalidOIDCProviderStatus)
	requireDiscoveryEndpointIsNotFound(t, badIssuer)
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

func requireCreatingOIDCProviderConfigCausesWellKnownEndpointToAppear(
	ctx context.Context,
	t *testing.T,
	issuerName string,
	client pinnipedclientset.Interface,
) *v1alpha1.OIDCProviderConfig {
	t.Helper()
	newOIDCProviderConfig := library.CreateTestOIDCProvider(ctx, t, issuerName)
	requireWellKnownEndpointIsWorking(t, issuerName)
	requireStatus(t, client, newOIDCProviderConfig.Namespace, newOIDCProviderConfig.Name, v1alpha1.SuccessOIDCProviderStatus)
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
      "authorization_endpoint": "%s/oauth2/authorize",
      "token_endpoint": "%s/oauth2/token",
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

func requireDelete(t *testing.T, client pinnipedclientset.Interface, ns, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.ConfigV1alpha1().OIDCProviderConfigs(ns).Delete(ctx, name, metav1.DeleteOptions{})
	require.NoError(t, err)
}

func requireStatus(t *testing.T, client pinnipedclientset.Interface, ns, name string, status v1alpha1.OIDCProviderStatus) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var opc *v1alpha1.OIDCProviderConfig
	var err error
	assert.Eventually(t, func() bool {
		opc, err = client.ConfigV1alpha1().OIDCProviderConfigs(ns).Get(ctx, name, metav1.GetOptions{})
		return err == nil && opc.Status.Status == status
	}, 10*time.Second, 200*time.Millisecond)
	require.NoError(t, err)
	require.Equalf(t, status, opc.Status.Status, "unexpected status (message = '%s')", opc.Status.Message)
}
