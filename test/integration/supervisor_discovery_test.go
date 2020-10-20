// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
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

	tests := []struct {
		Scheme  string
		Address string
	}{
		{Scheme: "http", Address: env.SupervisorHTTPAddress},
		{Scheme: "https", Address: env.SupervisorHTTPSAddress},
	}

	for _, test := range tests {
		supervisorScheme := test.Scheme
		supervisorAddress := test.Address

		if supervisorAddress == "" {
			// Both cases are not required, so when one is empty skip it.
			continue
		}

		// Test that there is no default discovery endpoint available when there are no OIDCProviderConfigs.
		requireDiscoveryEndpointsAreNotFound(t, supervisorScheme, supervisorAddress, fmt.Sprintf("%s://%s", supervisorScheme, supervisorAddress))

		// Define several unique issuer strings.
		issuer1 := fmt.Sprintf("%s://%s/nested/issuer1", supervisorScheme, supervisorAddress)
		issuer2 := fmt.Sprintf("%s://%s/nested/issuer2", supervisorScheme, supervisorAddress)
		issuer3 := fmt.Sprintf("%s://%s/issuer3", supervisorScheme, supervisorAddress)
		issuer4 := fmt.Sprintf("%s://%s/issuer4", supervisorScheme, supervisorAddress)
		issuer5 := fmt.Sprintf("%s://%s/issuer5", supervisorScheme, supervisorAddress)
		issuer6 := fmt.Sprintf("%s://%s/issuer6", supervisorScheme, supervisorAddress)
		badIssuer := fmt.Sprintf("%s://%s/badIssuer?cannot-use=queries", supervisorScheme, supervisorAddress)

		// When OIDCProviderConfig are created in sequence they each cause a discovery endpoint to appear only for as long as the OIDCProviderConfig exists.
		config1, jwks1 := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, supervisorScheme, supervisorAddress, issuer1, client)
		requireDeletingOIDCProviderConfigCausesDiscoveryEndpointsToDisappear(t, config1, client, ns, supervisorScheme, supervisorAddress, issuer1)
		config2, jwks2 := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, supervisorScheme, supervisorAddress, issuer2, client)
		requireDeletingOIDCProviderConfigCausesDiscoveryEndpointsToDisappear(t, config2, client, ns, supervisorScheme, supervisorAddress, issuer2)
		// The auto-created JWK's were different from each other.
		require.NotEqual(t, jwks1.Keys[0]["x"], jwks2.Keys[0]["x"])
		require.NotEqual(t, jwks1.Keys[0]["y"], jwks2.Keys[0]["y"])

		// When multiple OIDCProviderConfigs exist at the same time they each serve a unique discovery endpoint.
		config3, jwks3 := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, supervisorScheme, supervisorAddress, issuer3, client)
		config4, jwks4 := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, supervisorScheme, supervisorAddress, issuer4, client)
		requireDiscoveryEndpointsAreWorking(t, supervisorScheme, supervisorAddress, issuer3) // discovery for issuer3 is still working after issuer4 started working
		// The auto-created JWK's were different from each other.
		require.NotEqual(t, jwks3.Keys[0]["x"], jwks4.Keys[0]["x"])
		require.NotEqual(t, jwks3.Keys[0]["y"], jwks4.Keys[0]["y"])

		// Editing a provider to change the issuer name updates the endpoints that are being served.
		updatedConfig4 := editOIDCProviderConfigIssuerName(t, config4, client, ns, issuer5)
		requireDiscoveryEndpointsAreNotFound(t, supervisorScheme, supervisorAddress, issuer4)
		jwks5 := requireDiscoveryEndpointsAreWorking(t, supervisorScheme, supervisorAddress, issuer5)
		// The JWK did not change when the issuer name was updated.
		require.Equal(t, jwks4.Keys[0], jwks5.Keys[0])

		// When they are deleted they stop serving discovery endpoints.
		requireDeletingOIDCProviderConfigCausesDiscoveryEndpointsToDisappear(t, config3, client, ns, supervisorScheme, supervisorAddress, issuer3)
		requireDeletingOIDCProviderConfigCausesDiscoveryEndpointsToDisappear(t, updatedConfig4, client, ns, supervisorScheme, supervisorAddress, issuer5)

		// When the same issuer is added twice, both issuers are marked as duplicates, and neither provider is serving.
		config6Duplicate1, _ := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, supervisorScheme, supervisorAddress, issuer6, client)
		config6Duplicate2 := library.CreateTestOIDCProvider(ctx, t, issuer6)
		requireStatus(t, client, ns, config6Duplicate1.Name, v1alpha1.DuplicateOIDCProviderStatus)
		requireStatus(t, client, ns, config6Duplicate2.Name, v1alpha1.DuplicateOIDCProviderStatus)
		requireDiscoveryEndpointsAreNotFound(t, supervisorScheme, supervisorAddress, issuer6)

		// If we delete the first duplicate issuer, the second duplicate issuer starts serving.
		requireDelete(t, client, ns, config6Duplicate1.Name)
		requireWellKnownEndpointIsWorking(t, supervisorScheme, supervisorAddress, issuer6)
		requireStatus(t, client, ns, config6Duplicate2.Name, v1alpha1.SuccessOIDCProviderStatus)

		// When we finally delete all issuers, the endpoint should be down.
		requireDeletingOIDCProviderConfigCausesDiscoveryEndpointsToDisappear(t, config6Duplicate2, client, ns, supervisorScheme, supervisorAddress, issuer6)

		// "Host" headers can be used to send requests to discovery endpoints when the public address is different from the issuer name.
		issuer7 := fmt.Sprintf("%s://some-issuer-host-and-port-that-doesnt-match-public-supervisor-address.com:2684/issuer7", supervisorScheme)
		config7, _ := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, supervisorScheme, supervisorAddress, issuer7, client)
		requireDeletingOIDCProviderConfigCausesDiscoveryEndpointsToDisappear(t, config7, client, ns, supervisorScheme, supervisorAddress, issuer7)

		// When we create a provider with an invalid issuer, the status is set to invalid.
		badConfig := library.CreateTestOIDCProvider(ctx, t, badIssuer)
		requireStatus(t, client, ns, badConfig.Name, v1alpha1.InvalidOIDCProviderStatus)
		requireDiscoveryEndpointsAreNotFound(t, supervisorScheme, supervisorAddress, badIssuer)
	}
}

func jwksURLForIssuer(scheme, host, path string) string {
	return fmt.Sprintf("%s://%s/%s/jwks.json", scheme, host, strings.TrimPrefix(path, "/"))
}

func wellKnownURLForIssuer(scheme, host, path string) string {
	return fmt.Sprintf("%s://%s/%s/.well-known/openid-configuration", scheme, host, strings.TrimPrefix(path, "/"))
}

func requireDiscoveryEndpointsAreNotFound(t *testing.T, supervisorScheme, supervisorAddress, issuerName string) {
	t.Helper()
	issuerURL, err := url.Parse(issuerName)
	require.NoError(t, err)
	requireEndpointNotFound(t, wellKnownURLForIssuer(supervisorScheme, supervisorAddress, issuerURL.Path), issuerURL.Host)
	requireEndpointNotFound(t, jwksURLForIssuer(supervisorScheme, supervisorAddress, issuerURL.Path), issuerURL.Host)
}

func requireEndpointNotFound(t *testing.T, url, host string) {
	t.Helper()
	httpClient := &http.Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	requestNonExistentPath, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)

	requestNonExistentPath.Header.Add("Host", host)

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
	supervisorScheme, supervisorAddress string,
	issuerName string,
	client pinnipedclientset.Interface,
) (*v1alpha1.OIDCProviderConfig, *ExpectedJWKSResponseFormat) {
	t.Helper()

	newOIDCProviderConfig := library.CreateTestOIDCProvider(ctx, t, issuerName)

	jwksResult := requireDiscoveryEndpointsAreWorking(t, supervisorScheme, supervisorAddress, issuerName)

	requireStatus(t, client, newOIDCProviderConfig.Namespace, newOIDCProviderConfig.Name, v1alpha1.SuccessOIDCProviderStatus)

	return newOIDCProviderConfig, jwksResult
}

func requireDiscoveryEndpointsAreWorking(t *testing.T, supervisorScheme, supervisorAddress, issuerName string) *ExpectedJWKSResponseFormat {
	requireWellKnownEndpointIsWorking(t, supervisorScheme, supervisorAddress, issuerName)
	jwksResult := requireJWKSEndpointIsWorking(t, supervisorScheme, supervisorAddress, issuerName)
	return jwksResult
}

func requireDeletingOIDCProviderConfigCausesDiscoveryEndpointsToDisappear(
	t *testing.T,
	existingOIDCProviderConfig *v1alpha1.OIDCProviderConfig,
	client pinnipedclientset.Interface,
	ns string,
	supervisorScheme, supervisorAddress string,
	issuerName string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Delete the OIDCProviderConfig.
	err := client.ConfigV1alpha1().OIDCProviderConfigs(ns).Delete(ctx, existingOIDCProviderConfig.Name, metav1.DeleteOptions{})
	require.NoError(t, err)

	// Fetch that same discovery endpoint as before, but now it should not exist anymore. Give it some time for the endpoint to go away.
	requireDiscoveryEndpointsAreNotFound(t, supervisorScheme, supervisorAddress, issuerName)
}

func requireWellKnownEndpointIsWorking(t *testing.T, supervisorScheme, supervisorAddress, issuerName string) {
	t.Helper()

	issuerURL, err := url.Parse(issuerName)
	require.NoError(t, err)
	response, responseBody := requireSuccessEndpointResponse(t, wellKnownURLForIssuer(supervisorScheme, supervisorAddress, issuerURL.Path), issuerName) //nolint:bodyclose

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

func requireJWKSEndpointIsWorking(t *testing.T, supervisorScheme, supervisorAddress, issuerName string) *ExpectedJWKSResponseFormat {
	t.Helper()

	issuerURL, err := url.Parse(issuerName)
	require.NoError(t, err)
	response, responseBody := requireSuccessEndpointResponse(t, jwksURLForIssuer(supervisorScheme, supervisorAddress, issuerURL.Path), issuerName) //nolint:bodyclose

	var result ExpectedJWKSResponseFormat
	err = json.Unmarshal([]byte(responseBody), &result)
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

func requireSuccessEndpointResponse(t *testing.T, endpointURL, issuer string) (*http.Response, string) {
	httpClient := &http.Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Define a request to the new discovery endpoint which should have been created by an OIDCProviderConfig.
	requestDiscoveryEndpoint, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		endpointURL,
		nil,
	)
	require.NoError(t, err)

	issuerURL, err := url.Parse(issuer)
	require.NoError(t, err)
	// Set the host header on the request to match the issuer's hostname, which could potentially be different
	// from the public ingress address, e.g. when a load balancer is used, so we want to test here that the host
	// header is respected by the supervisor server.
	requestDiscoveryEndpoint.Host = issuerURL.Host

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
