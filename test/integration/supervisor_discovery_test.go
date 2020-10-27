// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.19/client/clientset/versioned"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/test/library"
)

func TestSupervisorTLSTerminationWithSNI(t *testing.T) {
	env := library.IntegrationEnv(t)
	pinnipedClient := library.NewPinnipedClientset(t)
	kubeClient := library.NewClientset(t)

	ns := env.SupervisorNamespace
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	temporarilyRemoveAllOIDCProviderConfigs(ctx, t, ns, pinnipedClient)

	scheme := "https"
	address := env.SupervisorHTTPSAddress // hostname and port for direct access to the supervisor's port 443

	hostname1 := strings.Split(address, ":")[0]
	issuer1 := fmt.Sprintf("%s://%s/issuer1", scheme, address)
	sniCertificateSecretName1 := "integration-test-sni-cert-1"

	// Create an OIDCProviderConfig with an sniCertificateSecretName.
	oidcProviderConfig1 := library.CreateTestOIDCProvider(ctx, t, issuer1, sniCertificateSecretName1)
	requireStatus(t, pinnipedClient, oidcProviderConfig1.Namespace, oidcProviderConfig1.Name, v1alpha1.SuccessOIDCProviderStatus)

	// The sniCertificateSecretName Secret does not exist, so the endpoints should fail with TLS errors.
	requireEndpointHasTLSErrorBecauseCertificatesAreNotReady(t, issuer1)

	// Create the Secret.
	ca1 := createSNICertificateSecret(ctx, t, ns, hostname1, sniCertificateSecretName1, kubeClient)

	// Now that the Secret exists, we should be able to access the endpoints by hostname using the CA.
	_ = requireDiscoveryEndpointsAreWorking(t, scheme, address, string(ca1.Bundle()), issuer1, nil)

	// Update the config to take away the sniCertificateSecretName.
	sniCertificateSecretName1update := "integration-test-sni-cert-1-update"
	oidcProviderConfig1LatestVersion, err := pinnipedClient.ConfigV1alpha1().OIDCProviderConfigs(ns).Get(ctx, oidcProviderConfig1.Name, metav1.GetOptions{})
	require.NoError(t, err)
	oidcProviderConfig1LatestVersion.Spec.SNICertificateSecretName = sniCertificateSecretName1update
	_, err = pinnipedClient.ConfigV1alpha1().OIDCProviderConfigs(ns).Update(ctx, oidcProviderConfig1LatestVersion, metav1.UpdateOptions{})
	require.NoError(t, err)

	// The the endpoints should fail with TLS errors again.
	requireEndpointHasTLSErrorBecauseCertificatesAreNotReady(t, issuer1)

	// Create a Secret at the updated name.
	ca1update := createSNICertificateSecret(ctx, t, ns, hostname1, sniCertificateSecretName1update, kubeClient)

	// Now that the Secret exists at the new name, we should be able to access the endpoints by hostname using the CA.
	_ = requireDiscoveryEndpointsAreWorking(t, scheme, address, string(ca1update.Bundle()), issuer1, nil)

	// To test SNI virtual hosting, send requests to discovery endpoints when the public address is different from the issuer name.
	hostname2 := "some-issuer-host-and-port-that-doesnt-match-public-supervisor-address.com"
	hostnamePort2 := "2684"
	issuer2 := fmt.Sprintf("%s://%s:%s/issuer2", scheme, hostname2, hostnamePort2)
	sniCertificateSecretName2 := "integration-test-sni-cert-2"

	// Create an OIDCProviderConfig with an sniCertificateSecretName.
	oidcProviderConfig2 := library.CreateTestOIDCProvider(ctx, t, issuer2, sniCertificateSecretName2)
	requireStatus(t, pinnipedClient, oidcProviderConfig2.Namespace, oidcProviderConfig2.Name, v1alpha1.SuccessOIDCProviderStatus)

	// Create the Secret.
	ca2 := createSNICertificateSecret(ctx, t, ns, hostname2, sniCertificateSecretName2, kubeClient)

	// Now that the Secret exists, we should be able to access the endpoints by hostname using the CA.
	_ = requireDiscoveryEndpointsAreWorking(t, scheme, hostname2+":"+hostnamePort2, string(ca2.Bundle()), issuer2, map[string]string{
		hostname2 + ":" + hostnamePort2: address,
	})
}

func TestSupervisorOIDCDiscovery(t *testing.T) {
	env := library.IntegrationEnv(t)
	client := library.NewPinnipedClientset(t)

	ns := env.SupervisorNamespace
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	temporarilyRemoveAllOIDCProviderConfigs(ctx, t, ns, client)

	tests := []struct {
		Scheme   string
		Address  string
		CABundle string
	}{
		{Scheme: "http", Address: env.SupervisorHTTPAddress},
		{Scheme: "https", Address: env.SupervisorHTTPSIngressAddress, CABundle: env.SupervisorHTTPSIngressCABundle},
	}

	for _, test := range tests {
		scheme := test.Scheme
		addr := test.Address
		caBundle := test.CABundle

		if addr == "" {
			// Both cases are not required, so when one is empty skip it.
			continue
		}

		// Test that there is no default discovery endpoint available when there are no OIDCProviderConfigs.
		requireDiscoveryEndpointsAreNotFound(t, scheme, addr, caBundle, fmt.Sprintf("%s://%s", scheme, addr))

		// Define several unique issuer strings.
		issuer1 := fmt.Sprintf("%s://%s/nested/issuer1", scheme, addr)
		issuer2 := fmt.Sprintf("%s://%s/nested/issuer2", scheme, addr)
		issuer3 := fmt.Sprintf("%s://%s/issuer3", scheme, addr)
		issuer4 := fmt.Sprintf("%s://%s/issuer4", scheme, addr)
		issuer5 := fmt.Sprintf("%s://%s/issuer5", scheme, addr)
		issuer6 := fmt.Sprintf("%s://%s/issuer6", scheme, addr)
		badIssuer := fmt.Sprintf("%s://%s/badIssuer?cannot-use=queries", scheme, addr)

		// When OIDCProviderConfig are created in sequence they each cause a discovery endpoint to appear only for as long as the OIDCProviderConfig exists.
		config1, jwks1 := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer1, client)
		requireDeletingOIDCProviderConfigCausesDiscoveryEndpointsToDisappear(t, config1, client, ns, scheme, addr, caBundle, issuer1)
		config2, jwks2 := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer2, client)
		requireDeletingOIDCProviderConfigCausesDiscoveryEndpointsToDisappear(t, config2, client, ns, scheme, addr, caBundle, issuer2)
		// The auto-created JWK's were different from each other.
		require.NotEqual(t, jwks1.Keys[0]["x"], jwks2.Keys[0]["x"])
		require.NotEqual(t, jwks1.Keys[0]["y"], jwks2.Keys[0]["y"])

		// When multiple OIDCProviderConfigs exist at the same time they each serve a unique discovery endpoint.
		config3, jwks3 := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer3, client)
		config4, jwks4 := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer4, client)
		requireDiscoveryEndpointsAreWorking(t, scheme, addr, caBundle, issuer3, nil) // discovery for issuer3 is still working after issuer4 started working
		// The auto-created JWK's were different from each other.
		require.NotEqual(t, jwks3.Keys[0]["x"], jwks4.Keys[0]["x"])
		require.NotEqual(t, jwks3.Keys[0]["y"], jwks4.Keys[0]["y"])

		// Editing a provider to change the issuer name updates the endpoints that are being served.
		updatedConfig4 := editOIDCProviderConfigIssuerName(t, config4, client, ns, issuer5)
		requireDiscoveryEndpointsAreNotFound(t, scheme, addr, caBundle, issuer4)
		jwks5 := requireDiscoveryEndpointsAreWorking(t, scheme, addr, caBundle, issuer5, nil)
		// The JWK did not change when the issuer name was updated.
		require.Equal(t, jwks4.Keys[0], jwks5.Keys[0])

		// When they are deleted they stop serving discovery endpoints.
		requireDeletingOIDCProviderConfigCausesDiscoveryEndpointsToDisappear(t, config3, client, ns, scheme, addr, caBundle, issuer3)
		requireDeletingOIDCProviderConfigCausesDiscoveryEndpointsToDisappear(t, updatedConfig4, client, ns, scheme, addr, caBundle, issuer5)

		// When the same issuer is added twice, both issuers are marked as duplicates, and neither provider is serving.
		config6Duplicate1, _ := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer6, client)
		config6Duplicate2 := library.CreateTestOIDCProvider(ctx, t, issuer6, "")
		requireStatus(t, client, ns, config6Duplicate1.Name, v1alpha1.DuplicateOIDCProviderStatus)
		requireStatus(t, client, ns, config6Duplicate2.Name, v1alpha1.DuplicateOIDCProviderStatus)
		requireDiscoveryEndpointsAreNotFound(t, scheme, addr, caBundle, issuer6)

		// If we delete the first duplicate issuer, the second duplicate issuer starts serving.
		requireDelete(t, client, ns, config6Duplicate1.Name)
		requireWellKnownEndpointIsWorking(t, scheme, addr, caBundle, issuer6, nil)
		requireStatus(t, client, ns, config6Duplicate2.Name, v1alpha1.SuccessOIDCProviderStatus)

		// When we finally delete all issuers, the endpoint should be down.
		requireDeletingOIDCProviderConfigCausesDiscoveryEndpointsToDisappear(t, config6Duplicate2, client, ns, scheme, addr, caBundle, issuer6)

		// "Host" headers can be used to send requests to discovery endpoints when the public address is different from the issuer name.
		issuer7 := fmt.Sprintf("%s://some-issuer-host-and-port-that-doesnt-match-public-supervisor-address.com:2684/issuer7", scheme)
		config7, _ := requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer7, client)
		requireDeletingOIDCProviderConfigCausesDiscoveryEndpointsToDisappear(t, config7, client, ns, scheme, addr, caBundle, issuer7)

		// When we create a provider with an invalid issuer, the status is set to invalid.
		badConfig := library.CreateTestOIDCProvider(ctx, t, badIssuer, "")
		requireStatus(t, client, ns, badConfig.Name, v1alpha1.InvalidOIDCProviderStatus)
		requireDiscoveryEndpointsAreNotFound(t, scheme, addr, caBundle, badIssuer)
		requireDeletingOIDCProviderConfigCausesDiscoveryEndpointsToDisappear(t, badConfig, client, ns, scheme, addr, caBundle, badIssuer)
	}
}

func createSNICertificateSecret(ctx context.Context, t *testing.T, ns string, hostname string, sniCertificateSecretName string, kubeClient kubernetes.Interface) *certauthority.CA {
	// Create a CA.
	ca, err := certauthority.New(pkix.Name{CommonName: "Acme Corp"}, 1000*time.Hour)
	require.NoError(t, err)

	// Using the CA, create a TLS server cert.
	tlsCert, err := ca.Issue(pkix.Name{CommonName: hostname}, []string{hostname}, 1000*time.Hour)
	require.NoError(t, err)

	// Write the serving cert to the SNI secret.
	tlsCertChainPEM, tlsPrivateKeyPEM, err := certauthority.ToPEM(tlsCert)
	require.NoError(t, err)
	secret := corev1.Secret{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      sniCertificateSecretName,
			Namespace: ns,
		},
		StringData: map[string]string{
			"tls.crt": string(tlsCertChainPEM),
			"tls.key": string(tlsPrivateKeyPEM),
		},
	}
	_, err = kubeClient.CoreV1().Secrets(ns).Create(ctx, &secret, metav1.CreateOptions{})
	require.NoError(t, err)

	// Delete the Secret when the test ends.
	t.Cleanup(func() {
		t.Helper()
		deleteCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := kubeClient.CoreV1().Secrets(ns).Delete(deleteCtx, sniCertificateSecretName, metav1.DeleteOptions{})
		require.NoError(t, err)
	})

	return ca
}

func temporarilyRemoveAllOIDCProviderConfigs(ctx context.Context, t *testing.T, ns string, client pinnipedclientset.Interface) {
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
}

func jwksURLForIssuer(scheme, host, path string) string {
	return fmt.Sprintf("%s://%s/%s/jwks.json", scheme, host, strings.TrimPrefix(path, "/"))
}

func wellKnownURLForIssuer(scheme, host, path string) string {
	return fmt.Sprintf("%s://%s/%s/.well-known/openid-configuration", scheme, host, strings.TrimPrefix(path, "/"))
}

func requireDiscoveryEndpointsAreNotFound(t *testing.T, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName string) {
	t.Helper()
	issuerURL, err := url.Parse(issuerName)
	require.NoError(t, err)
	requireEndpointNotFound(t, wellKnownURLForIssuer(supervisorScheme, supervisorAddress, issuerURL.Path), issuerURL.Host, supervisorCABundle)
	requireEndpointNotFound(t, jwksURLForIssuer(supervisorScheme, supervisorAddress, issuerURL.Path), issuerURL.Host, supervisorCABundle)
}

func requireEndpointNotFound(t *testing.T, url, host, caBundle string) {
	t.Helper()
	httpClient := newHTTPClient(t, caBundle, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	requestNonExistentPath, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)

	requestNonExistentPath.Host = host

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

func requireEndpointHasTLSErrorBecauseCertificatesAreNotReady(t *testing.T, url string) {
	t.Helper()
	httpClient := newHTTPClient(t, "", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		_, err = httpClient.Do(request) //nolint:bodyclose
		return err != nil && strings.Contains(err.Error(), "tls: unrecognized name")
	}, 10*time.Second, 200*time.Millisecond)
	require.Error(t, err)
	require.EqualError(t, err, `Get "https://localhost:12344/issuer1": remote error: tls: unrecognized name`)
}

func requireCreatingOIDCProviderConfigCausesDiscoveryEndpointsToAppear(
	ctx context.Context,
	t *testing.T,
	supervisorScheme, supervisorAddress, supervisorCABundle string,
	issuerName string,
	client pinnipedclientset.Interface,
) (*v1alpha1.OIDCProviderConfig, *ExpectedJWKSResponseFormat) {
	t.Helper()
	newOIDCProviderConfig := library.CreateTestOIDCProvider(ctx, t, issuerName, "")
	jwksResult := requireDiscoveryEndpointsAreWorking(t, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName, nil)
	requireStatus(t, client, newOIDCProviderConfig.Namespace, newOIDCProviderConfig.Name, v1alpha1.SuccessOIDCProviderStatus)
	return newOIDCProviderConfig, jwksResult
}

func requireDiscoveryEndpointsAreWorking(t *testing.T, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName string, dnsOverrides map[string]string) *ExpectedJWKSResponseFormat {
	requireWellKnownEndpointIsWorking(t, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName, dnsOverrides)
	jwksResult := requireJWKSEndpointIsWorking(t, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName, dnsOverrides)
	return jwksResult
}

func requireDeletingOIDCProviderConfigCausesDiscoveryEndpointsToDisappear(
	t *testing.T,
	existingOIDCProviderConfig *v1alpha1.OIDCProviderConfig,
	client pinnipedclientset.Interface,
	ns string,
	supervisorScheme, supervisorAddress, supervisorCABundle string,
	issuerName string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Delete the OIDCProviderConfig.
	err := client.ConfigV1alpha1().OIDCProviderConfigs(ns).Delete(ctx, existingOIDCProviderConfig.Name, metav1.DeleteOptions{})
	require.NoError(t, err)

	// Fetch that same discovery endpoint as before, but now it should not exist anymore. Give it some time for the endpoint to go away.
	requireDiscoveryEndpointsAreNotFound(t, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName)
}

func requireWellKnownEndpointIsWorking(t *testing.T, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName string, dnsOverrides map[string]string) {
	t.Helper()
	issuerURL, err := url.Parse(issuerName)
	require.NoError(t, err)
	response, responseBody := requireSuccessEndpointResponse(t, wellKnownURLForIssuer(supervisorScheme, supervisorAddress, issuerURL.Path), issuerName, supervisorCABundle, dnsOverrides) //nolint:bodyclose

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

func requireJWKSEndpointIsWorking(t *testing.T, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName string, dnsOverrides map[string]string) *ExpectedJWKSResponseFormat {
	t.Helper()

	issuerURL, err := url.Parse(issuerName)
	require.NoError(t, err)
	response, responseBody := requireSuccessEndpointResponse(t, //nolint:bodyclose
		jwksURLForIssuer(supervisorScheme, supervisorAddress, issuerURL.Path),
		issuerName,
		supervisorCABundle,
		dnsOverrides,
	)

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

func requireSuccessEndpointResponse(t *testing.T, endpointURL, issuer, caBundle string, dnsOverrides map[string]string) (*http.Response, string) {
	t.Helper()
	httpClient := newHTTPClient(t, caBundle, dnsOverrides)

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

func newHTTPClient(t *testing.T, caBundle string, dnsOverrides map[string]string) *http.Client {
	c := &http.Client{}

	realDialer := &net.Dialer{}
	overrideDialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		replacementAddr, hasKey := dnsOverrides[addr]
		if hasKey {
			t.Logf("DialContext replacing addr %s with %s", addr, replacementAddr)
			addr = replacementAddr
		} else if dnsOverrides != nil {
			t.Fatal("dnsOverrides was provided but not used, which was probably a mistake")
		}
		return realDialer.DialContext(ctx, network, addr)
	}

	if caBundle != "" { // CA bundle is optional
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM([]byte(caBundle))
		c.Transport = &http.Transport{
			DialContext:     overrideDialContext,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: caCertPool},
		}
	} else {
		c.Transport = &http.Transport{
			DialContext: overrideDialContext,
		}
	}

	return c
}
