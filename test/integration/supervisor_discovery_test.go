// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	requireDiscoveryEndpointsAreNotFound(t, fmt.Sprintf("http://%s", env.SupervisorAddress))

	// Define several unique issuer strings.
	issuer1 := fmt.Sprintf("http://%s/nested/issuer1", env.SupervisorAddress)
	issuer2 := fmt.Sprintf("http://%s/nested/issuer2", env.SupervisorAddress)
	issuer3 := fmt.Sprintf("http://%s/issuer3", env.SupervisorAddress)
	issuer4 := fmt.Sprintf("http://%s/issuer4", env.SupervisorAddress)
	issuer5 := fmt.Sprintf("http://%s/issuer5", env.SupervisorAddress)
	issuer6 := fmt.Sprintf("http://%s/issuer6", env.SupervisorAddress)
	badIssuer := fmt.Sprintf("http://%s/badIssuer?cannot-use=queries", env.SupervisorAddress)

	// When OIDCProviderConfig are created in sequence they each cause a discovery endpoint to appear only for as long as the OIDCProviderConfig exists.
	config1, jwks1 := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, issuer1, client)
	requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(t, config1, client, ns, issuer1)
	config2, jwks2 := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, issuer2, client)
	requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(t, config2, client, ns, issuer2)
	// The auto-created JWK's were different from each other.
	require.NotEqual(t, jwks1.Keys[0]["x"], jwks2.Keys[0]["x"])
	require.NotEqual(t, jwks1.Keys[0]["y"], jwks2.Keys[0]["y"])

	// When multiple OIDCProviderConfigs exist at the same time they each serve a unique discovery endpoint.
	config3, jwks3 := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, issuer3, client)
	config4, jwks4 := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, issuer4, client)
	requireDiscoveryEndpointsAreWorking(t, issuer3) // discovery for issuer3 is still working after issuer4 started working
	// The auto-created JWK's were different from each other.
	require.NotEqual(t, jwks3.Keys[0]["x"], jwks4.Keys[0]["x"])
	require.NotEqual(t, jwks3.Keys[0]["y"], jwks4.Keys[0]["y"])

	// Editing a provider to change the issuer name updates the endpoints that are being served.
	updatedConfig4 := editOIDCProviderConfigIssuerName(t, config4, client, ns, issuer5)
	requireDiscoveryEndpointsAreNotFound(t, issuer4)
	jwks5 := requireDiscoveryEndpointsAreWorking(t, issuer5)
	// The JWK did not change when the issuer name was updated.
	require.Equal(t, jwks4.Keys[0], jwks5.Keys[0])

	// When they are deleted they stop serving discovery endpoints.
	requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(t, config3, client, ns, issuer3)
	requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(t, updatedConfig4, client, ns, issuer5)

	// When the same issuer is added twice, both issuers are marked as duplicates, and neither provider is serving.
	config5Duplicate1, _ := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, issuer6, client)
	config5Duplicate2 := library.CreateTestOIDCProvider(ctx, t, issuer6)
	requireStatus(t, client, ns, config5Duplicate1.Name, v1alpha1.DuplicateOIDCProviderStatus)
	requireStatus(t, client, ns, config5Duplicate2.Name, v1alpha1.DuplicateOIDCProviderStatus)
	requireDiscoveryEndpointsAreNotFound(t, issuer6)

	// If we delete the first duplicate issuer, the second duplicate issuer starts serving.
	requireDelete(t, client, ns, config5Duplicate1.Name)
	requireWellKnownEndpointIsWorking(t, issuer6)
	requireStatus(t, client, ns, config5Duplicate2.Name, v1alpha1.SuccessOIDCProviderStatus)

	// When we finally delete all issuers, the endpoint should be down.
	requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(t, config5Duplicate2, client, ns, issuer6)

	// When we create a provider with an invalid issuer, the status is set to invalid.
	badConfig := library.CreateTestOIDCProvider(ctx, t, badIssuer)
	requireStatus(t, client, ns, badConfig.Name, v1alpha1.InvalidOIDCProviderStatus)
	requireDiscoveryEndpointsAreNotFound(t, badIssuer)
}

func jwksURLForIssuer(issuerName string) string {
	return fmt.Sprintf("%s/jwks.json", issuerName)
}

func wellKnownURLForIssuer(issuerName string) string {
	return fmt.Sprintf("%s/.well-known/openid-configuration", issuerName)
}

func requireDiscoveryEndpointsAreNotFound(t *testing.T, issuerName string) {
	t.Helper()
	requireEndpointNotFound(t, wellKnownURLForIssuer(issuerName))
	requireEndpointNotFound(t, jwksURLForIssuer(issuerName))
}

func requireEndpointNotFound(t *testing.T, url string) {
	t.Helper()
	httpClient := &http.Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	requestNonExistentPath, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

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

func requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(
	ctx context.Context,
	t *testing.T,
	issuerName string,
	client pinnipedclientset.Interface,
) (*v1alpha1.OIDCProviderConfig, *ExpectedJWKSResponseFormat) {
	t.Helper()

	newOIDCProviderConfig := library.CreateTestOIDCProvider(ctx, t, issuerName)

	jwksResult := requireDiscoveryEndpointsAreWorking(t, issuerName)

	requireStatus(t, client, newOIDCProviderConfig.Namespace, newOIDCProviderConfig.Name, v1alpha1.SuccessOIDCProviderStatus)

	return newOIDCProviderConfig, jwksResult
}

func requireDiscoveryEndpointsAreWorking(t *testing.T, issuerName string) *ExpectedJWKSResponseFormat {
	requireWellKnownEndpointIsWorking(t, issuerName)
	jwksResult := requireJWKSEndpointIsWorking(t, issuerName)
	return jwksResult
}

func requireDeletingOIDCProviderConfigCausesWellKnownEndpointToDisappear(
	t *testing.T,
	existingOIDCProviderConfig *v1alpha1.OIDCProviderConfig,
	client pinnipedclientset.Interface,
	ns string,
	issuerName string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Delete the OIDCProviderConfig.
	err := client.ConfigV1alpha1().OIDCProviderConfigs(ns).Delete(ctx, existingOIDCProviderConfig.Name, metav1.DeleteOptions{})
	require.NoError(t, err)

	// Fetch that same discovery endpoint as before, but now it should not exist anymore. Give it some time for the endpoint to go away.
	requireDiscoveryEndpointsAreNotFound(t, issuerName)
}

func requireWellKnownEndpointIsWorking(t *testing.T, issuerName string) {
	t.Helper()

	response, responseBody := requireSuccessEndpointResponse(t, wellKnownURLForIssuer(issuerName)) //nolint:bodyclose

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
	require.JSONEq(t, expectedJSON, responseBody)
}

type ExpectedJWKSResponseFormat struct {
	Keys []map[string]string
}

func requireJWKSEndpointIsWorking(t *testing.T, issuerName string) *ExpectedJWKSResponseFormat {
	t.Helper()

	response, responseBody := requireSuccessEndpointResponse(t, jwksURLForIssuer(issuerName)) //nolint:bodyclose

	var result ExpectedJWKSResponseFormat
	err := json.Unmarshal([]byte(responseBody), &result)
	require.NoError(t, err)

	require.Len(t, result.Keys, 1)
	jwk := result.Keys[0]
	require.Len(t, jwk, 7) // make sure there are no extra values, i.e. does not include private key
	require.NotEmpty(t, jwk["kid"])
	require.Equal(t, "sig", jwk["use"])
	require.Equal(t, "EC", jwk["kty"])
	require.Equal(t, "P-256", jwk["crv"])
	require.Equal(t, "ES256", jwk["alg"])
	require.NotEmpty(t, jwk["x"])
	require.NotEmpty(t, jwk["y"])

	require.Equal(t, "application/json", response.Header.Get("content-type"))

	return &result
}

func requireSuccessEndpointResponse(t *testing.T, wellKnownURL string) (*http.Response, string) {
	httpClient := &http.Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Define a request to the new discovery endpoint which should have been created by an OIDCProviderConfig.
	requestDiscoveryEndpoint, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		wellKnownURL,
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
	return response, string(responseBody)
}

func editOIDCProviderConfigIssuerName(
	t *testing.T,
	existingOIDCProviderConfig *v1alpha1.OIDCProviderConfig,
	client pinnipedclientset.Interface,
	ns string,
	newIssuerName string,
) *v1alpha1.OIDCProviderConfig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	mostRecentVersion, err := client.ConfigV1alpha1().OIDCProviderConfigs(ns).Get(ctx, existingOIDCProviderConfig.Name, metav1.GetOptions{})
	require.NoError(t, err)

	mostRecentVersion.Spec.Issuer = newIssuerName
	updated, err := client.ConfigV1alpha1().OIDCProviderConfigs(ns).Update(ctx, mostRecentVersion, metav1.UpdateOptions{})
	require.NoError(t, err)

	return updated
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
