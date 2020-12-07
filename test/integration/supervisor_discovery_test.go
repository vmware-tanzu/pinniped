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
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"go.pinniped.dev/generated/1.19/apis/supervisor/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.19/client/supervisor/clientset/versioned"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/test/library"
)

// This test is intended to exercise the supervisor's HTTP port 8080. It can either access it directly via
// the env.SupervisorHTTPAddress setting, or it can access it indirectly through a TLS-enabled Ingress which
// uses the supervisor's port 8080 as its backend via the env.SupervisorHTTPSIngressAddress and
// env.SupervisorHTTPSIngressCABundle settings, or it can exercise it both ways when all of those
// env settings are present.
//
// Testing talking to the supervisor's port 8443 where the supervisor is terminating TLS itself is
// handled by the others tests in this file.
func TestSupervisorOIDCDiscovery(t *testing.T) {
	env := library.IntegrationEnv(t)
	client := library.NewSupervisorClientset(t)

	ns := env.SupervisorNamespace
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	temporarilyRemoveAllOIDCProvidersAndDefaultTLSCertSecret(ctx, t, ns, defaultTLSCertSecretName(env), client, library.NewClientset(t))

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

		// Test that there is no default discovery endpoint available when there are no OIDCProviders.
		requireDiscoveryEndpointsAreNotFound(t, scheme, addr, caBundle, fmt.Sprintf("%s://%s", scheme, addr))

		// Define several unique issuer strings. Always use https in the issuer name even when we are accessing the http port.
		issuer1 := fmt.Sprintf("https://%s/nested/issuer1", addr)
		issuer2 := fmt.Sprintf("https://%s/nested/issuer2", addr)
		issuer3 := fmt.Sprintf("https://%s/issuer3", addr)
		issuer4 := fmt.Sprintf("https://%s/issuer4", addr)
		issuer5 := fmt.Sprintf("https://%s/issuer5", addr)
		issuer6 := fmt.Sprintf("https://%s/issuer6", addr)
		badIssuer := fmt.Sprintf("https://%s/badIssuer?cannot-use=queries", addr)

		// When OIDCProvider are created in sequence they each cause a discovery endpoint to appear only for as long as the OIDCProvider exists.
		config1, jwks1 := requireCreatingOIDCProviderCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer1, client)
		requireDeletingOIDCProviderCausesDiscoveryEndpointsToDisappear(t, config1, client, ns, scheme, addr, caBundle, issuer1)
		config2, jwks2 := requireCreatingOIDCProviderCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer2, client)
		requireDeletingOIDCProviderCausesDiscoveryEndpointsToDisappear(t, config2, client, ns, scheme, addr, caBundle, issuer2)
		// The auto-created JWK's were different from each other.
		require.NotEqual(t, jwks1.Keys[0]["x"], jwks2.Keys[0]["x"])
		require.NotEqual(t, jwks1.Keys[0]["y"], jwks2.Keys[0]["y"])

		// When multiple OIDCProviders exist at the same time they each serve a unique discovery endpoint.
		config3, jwks3 := requireCreatingOIDCProviderCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer3, client)
		config4, jwks4 := requireCreatingOIDCProviderCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer4, client)
		requireDiscoveryEndpointsAreWorking(t, scheme, addr, caBundle, issuer3, nil) // discovery for issuer3 is still working after issuer4 started working
		// The auto-created JWK's were different from each other.
		require.NotEqual(t, jwks3.Keys[0]["x"], jwks4.Keys[0]["x"])
		require.NotEqual(t, jwks3.Keys[0]["y"], jwks4.Keys[0]["y"])

		// Editing a provider to change the issuer name updates the endpoints that are being served.
		updatedConfig4 := editOIDCProviderIssuerName(t, config4, client, ns, issuer5)
		requireDiscoveryEndpointsAreNotFound(t, scheme, addr, caBundle, issuer4)
		jwks5 := requireDiscoveryEndpointsAreWorking(t, scheme, addr, caBundle, issuer5, nil)
		// The JWK did not change when the issuer name was updated.
		require.Equal(t, jwks4.Keys[0], jwks5.Keys[0])

		// When they are deleted they stop serving discovery endpoints.
		requireDeletingOIDCProviderCausesDiscoveryEndpointsToDisappear(t, config3, client, ns, scheme, addr, caBundle, issuer3)
		requireDeletingOIDCProviderCausesDiscoveryEndpointsToDisappear(t, updatedConfig4, client, ns, scheme, addr, caBundle, issuer5)

		// When the same issuer is added twice, both issuers are marked as duplicates, and neither provider is serving.
		config6Duplicate1, _ := requireCreatingOIDCProviderCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer6, client)
		config6Duplicate2 := library.CreateTestOIDCProvider(ctx, t, issuer6, "", "")
		requireStatus(t, client, ns, config6Duplicate1.Name, v1alpha1.DuplicateOIDCProviderStatusCondition)
		requireStatus(t, client, ns, config6Duplicate2.Name, v1alpha1.DuplicateOIDCProviderStatusCondition)
		requireDiscoveryEndpointsAreNotFound(t, scheme, addr, caBundle, issuer6)

		// If we delete the first duplicate issuer, the second duplicate issuer starts serving.
		requireDelete(t, client, ns, config6Duplicate1.Name)
		requireWellKnownEndpointIsWorking(t, scheme, addr, caBundle, issuer6, nil)
		requireStatus(t, client, ns, config6Duplicate2.Name, v1alpha1.SuccessOIDCProviderStatusCondition)

		// When we finally delete all issuers, the endpoint should be down.
		requireDeletingOIDCProviderCausesDiscoveryEndpointsToDisappear(t, config6Duplicate2, client, ns, scheme, addr, caBundle, issuer6)

		// Only test this for http endpoints because https endpoints are going through an Ingress,
		// and while it is possible to configure an Ingress to serve multiple hostnames with matching TLS certs
		// for each hostname, that it not something that we felt like doing on all of our clusters that we
		// run tests against.  :)
		if scheme == "http" {
			// "Host" headers can be used to send requests to discovery endpoints when the public address is different from the issuer name.
			issuer7 := "https://some-issuer-host-and-port-that-doesnt-match-public-supervisor-address.com:2684/issuer7"
			config7, _ := requireCreatingOIDCProviderCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer7, client)
			requireDeletingOIDCProviderCausesDiscoveryEndpointsToDisappear(t, config7, client, ns, scheme, addr, caBundle, issuer7)
		}

		// When we create a provider with an invalid issuer, the status is set to invalid.
		badConfig := library.CreateTestOIDCProvider(ctx, t, badIssuer, "", "")
		requireStatus(t, client, ns, badConfig.Name, v1alpha1.InvalidOIDCProviderStatusCondition)
		requireDiscoveryEndpointsAreNotFound(t, scheme, addr, caBundle, badIssuer)
		requireDeletingOIDCProviderCausesDiscoveryEndpointsToDisappear(t, badConfig, client, ns, scheme, addr, caBundle, badIssuer)
	}
}

func TestSupervisorTLSTerminationWithSNI(t *testing.T) {
	env := library.IntegrationEnv(t)
	pinnipedClient := library.NewSupervisorClientset(t)
	kubeClient := library.NewClientset(t)

	ns := env.SupervisorNamespace
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	temporarilyRemoveAllOIDCProvidersAndDefaultTLSCertSecret(ctx, t, ns, defaultTLSCertSecretName(env), pinnipedClient, kubeClient)

	scheme := "https"
	address := env.SupervisorHTTPSAddress // hostname and port for direct access to the supervisor's port 8443

	hostname1 := strings.Split(address, ":")[0]
	issuer1 := fmt.Sprintf("%s://%s/issuer1", scheme, address)
	certSecretName1 := "integration-test-cert-1"

	// Create an OIDCProvider with a spec.tls.secretName.
	oidcProvider1 := library.CreateTestOIDCProvider(ctx, t, issuer1, certSecretName1, "")
	requireStatus(t, pinnipedClient, oidcProvider1.Namespace, oidcProvider1.Name, v1alpha1.SuccessOIDCProviderStatusCondition)

	// The spec.tls.secretName Secret does not exist, so the endpoints should fail with TLS errors.
	requireEndpointHasTLSErrorBecauseCertificatesAreNotReady(t, issuer1)

	// Create the Secret.
	ca1 := createTLSCertificateSecret(ctx, t, ns, hostname1, nil, certSecretName1, kubeClient)

	// Now that the Secret exists, we should be able to access the endpoints by hostname using the CA.
	_ = requireDiscoveryEndpointsAreWorking(t, scheme, address, string(ca1.Bundle()), issuer1, nil)

	// Update the config to with a new .spec.tls.secretName.
	certSecretName1update := "integration-test-cert-1-update"
	oidcProvider1LatestVersion, err := pinnipedClient.ConfigV1alpha1().OIDCProviders(ns).Get(ctx, oidcProvider1.Name, metav1.GetOptions{})
	require.NoError(t, err)
	oidcProvider1LatestVersion.Spec.TLS = &v1alpha1.OIDCProviderTLSSpec{SecretName: certSecretName1update}
	_, err = pinnipedClient.ConfigV1alpha1().OIDCProviders(ns).Update(ctx, oidcProvider1LatestVersion, metav1.UpdateOptions{})
	require.NoError(t, err)

	// The the endpoints should fail with TLS errors again.
	requireEndpointHasTLSErrorBecauseCertificatesAreNotReady(t, issuer1)

	// Create a Secret at the updated name.
	ca1update := createTLSCertificateSecret(ctx, t, ns, hostname1, nil, certSecretName1update, kubeClient)

	// Now that the Secret exists at the new name, we should be able to access the endpoints by hostname using the CA.
	_ = requireDiscoveryEndpointsAreWorking(t, scheme, address, string(ca1update.Bundle()), issuer1, nil)

	// To test SNI virtual hosting, send requests to discovery endpoints when the public address is different from the issuer name.
	hostname2 := "some-issuer-host-and-port-that-doesnt-match-public-supervisor-address.com"
	hostnamePort2 := "2684"
	issuer2 := fmt.Sprintf("%s://%s:%s/issuer2", scheme, hostname2, hostnamePort2)
	certSecretName2 := "integration-test-cert-2"

	// Create an OIDCProvider with a spec.tls.secretName.
	oidcProvider2 := library.CreateTestOIDCProvider(ctx, t, issuer2, certSecretName2, "")
	requireStatus(t, pinnipedClient, oidcProvider2.Namespace, oidcProvider2.Name, v1alpha1.SuccessOIDCProviderStatusCondition)

	// Create the Secret.
	ca2 := createTLSCertificateSecret(ctx, t, ns, hostname2, nil, certSecretName2, kubeClient)

	// Now that the Secret exists, we should be able to access the endpoints by hostname using the CA.
	_ = requireDiscoveryEndpointsAreWorking(t, scheme, hostname2+":"+hostnamePort2, string(ca2.Bundle()), issuer2, map[string]string{
		hostname2 + ":" + hostnamePort2: address,
	})
}

func TestSupervisorTLSTerminationWithDefaultCerts(t *testing.T) {
	env := library.IntegrationEnv(t)
	pinnipedClient := library.NewSupervisorClientset(t)
	kubeClient := library.NewClientset(t)

	ns := env.SupervisorNamespace
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	temporarilyRemoveAllOIDCProvidersAndDefaultTLSCertSecret(ctx, t, ns, defaultTLSCertSecretName(env), pinnipedClient, kubeClient)

	scheme := "https"
	address := env.SupervisorHTTPSAddress // hostname and port for direct access to the supervisor's port 8443

	hostAndPortSegments := strings.Split(address, ":")
	// hostnames are case-insensitive, so test mis-matching the case of the issuer URL and the request URL
	hostname := strings.ToLower(hostAndPortSegments[0])
	port := "8443"
	if len(hostAndPortSegments) > 1 {
		port = hostAndPortSegments[1]
	}

	ips, err := library.LookupIP(ctx, hostname)
	require.NoError(t, err)
	require.NotEmpty(t, ips)
	ipWithPort := ips[0].String() + ":" + port

	issuerUsingIPAddress := fmt.Sprintf("%s://%s/issuer1", scheme, ipWithPort)
	issuerUsingHostname := fmt.Sprintf("%s://%s/issuer1", scheme, address)

	// Create an OIDCProvider without a spec.tls.secretName.
	oidcProvider1 := library.CreateTestOIDCProvider(ctx, t, issuerUsingIPAddress, "", "")
	requireStatus(t, pinnipedClient, oidcProvider1.Namespace, oidcProvider1.Name, v1alpha1.SuccessOIDCProviderStatusCondition)

	// There is no default TLS cert and the spec.tls.secretName was not set, so the endpoints should fail with TLS errors.
	requireEndpointHasTLSErrorBecauseCertificatesAreNotReady(t, issuerUsingIPAddress)

	// Create a Secret at the special name which represents the default TLS cert.
	defaultCA := createTLSCertificateSecret(ctx, t, ns, "cert-hostname-doesnt-matter", []net.IP{ips[0]}, defaultTLSCertSecretName(env), kubeClient)

	// Now that the Secret exists, we should be able to access the endpoints by IP address using the CA.
	_ = requireDiscoveryEndpointsAreWorking(t, scheme, ipWithPort, string(defaultCA.Bundle()), issuerUsingIPAddress, nil)

	// Create an OIDCProvider with a spec.tls.secretName.
	certSecretName := "integration-test-cert-1"
	oidcProvider2 := library.CreateTestOIDCProvider(ctx, t, issuerUsingHostname, certSecretName, "")
	requireStatus(t, pinnipedClient, oidcProvider2.Namespace, oidcProvider2.Name, v1alpha1.SuccessOIDCProviderStatusCondition)

	// Create the Secret.
	certCA := createTLSCertificateSecret(ctx, t, ns, hostname, nil, certSecretName, kubeClient)

	// Now that the Secret exists, we should be able to access the endpoints by hostname using the CA from the SNI cert.
	// Hostnames are case-insensitive, so the request should still work even if the case of the hostname is different
	// from the case of the issuer URL's hostname.
	_ = requireDiscoveryEndpointsAreWorking(t, scheme, strings.ToUpper(hostname)+":"+port, string(certCA.Bundle()), issuerUsingHostname, nil)

	// And we can still access the other issuer using the default cert.
	_ = requireDiscoveryEndpointsAreWorking(t, scheme, ipWithPort, string(defaultCA.Bundle()), issuerUsingIPAddress, nil)
}

func defaultTLSCertSecretName(env *library.TestEnv) string {
	return env.SupervisorAppName + "-default-tls-certificate" //nolint:gosec // this is not a hardcoded credential
}

func createTLSCertificateSecret(ctx context.Context, t *testing.T, ns string, hostname string, ips []net.IP, secretName string, kubeClient kubernetes.Interface) *certauthority.CA {
	// Create a CA.
	ca, err := certauthority.New(pkix.Name{CommonName: "Acme Corp"}, 1000*time.Hour)
	require.NoError(t, err)

	// Using the CA, create a TLS server cert.
	tlsCert, err := ca.Issue(pkix.Name{CommonName: hostname}, []string{hostname}, ips, 1000*time.Hour)
	require.NoError(t, err)

	// Write the serving cert to the SNI secret.
	tlsCertChainPEM, tlsPrivateKeyPEM, err := certauthority.ToPEM(tlsCert)
	require.NoError(t, err)
	secret := corev1.Secret{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
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
		err := kubeClient.CoreV1().Secrets(ns).Delete(deleteCtx, secretName, metav1.DeleteOptions{})
		require.NoError(t, err)
	})

	return ca
}

func temporarilyRemoveAllOIDCProvidersAndDefaultTLSCertSecret(
	ctx context.Context,
	t *testing.T,
	ns string,
	defaultTLSCertSecretName string,
	pinnipedClient pinnipedclientset.Interface,
	kubeClient kubernetes.Interface,
) {
	// Temporarily remove any existing OIDCProviders from the cluster so we can test from a clean slate.
	originalConfigList, err := pinnipedClient.ConfigV1alpha1().OIDCProviders(ns).List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	for _, config := range originalConfigList.Items {
		err := pinnipedClient.ConfigV1alpha1().OIDCProviders(ns).Delete(ctx, config.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	}

	// Also remove the supervisor's default TLS cert
	originalSecret, err := kubeClient.CoreV1().Secrets(ns).Get(ctx, defaultTLSCertSecretName, metav1.GetOptions{})
	notFound := k8serrors.IsNotFound(err)
	require.False(t, err != nil && !notFound, "unexpected error when getting %s", defaultTLSCertSecretName)
	if notFound {
		originalSecret = nil
	} else {
		err = kubeClient.CoreV1().Secrets(ns).Delete(ctx, defaultTLSCertSecretName, metav1.DeleteOptions{})
		require.NoError(t, err)
	}

	// When this test has finished, recreate any OIDCProviders and default secret that had existed on the cluster before this test.
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		for _, config := range originalConfigList.Items {
			thisConfig := config
			thisConfig.ResourceVersion = "" // Get rid of resource version since we can't create an object with one.
			_, err := pinnipedClient.ConfigV1alpha1().OIDCProviders(ns).Create(cleanupCtx, &thisConfig, metav1.CreateOptions{})
			require.NoError(t, err)
		}

		if originalSecret != nil {
			originalSecret.ResourceVersion = "" // Get rid of resource version since we can't create an object with one.
			_, err = kubeClient.CoreV1().Secrets(ns).Create(cleanupCtx, originalSecret, metav1.CreateOptions{})
			require.NoError(t, err)
		}
	})
}

func jwksURLForIssuer(scheme, host, path string) string {
	if path == "" {
		return fmt.Sprintf("%s://%s/jwks.json", scheme, host)
	}
	return fmt.Sprintf("%s://%s/%s/jwks.json", scheme, host, strings.TrimPrefix(path, "/"))
}

func wellKnownURLForIssuer(scheme, host, path string) string {
	if path == "" {
		return fmt.Sprintf("%s://%s/.well-known/openid-configuration", scheme, host)
	}
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
	require.EqualError(t, err, fmt.Sprintf(`Get "%s": remote error: tls: unrecognized name`, url))
}

func requireCreatingOIDCProviderCausesDiscoveryEndpointsToAppear(
	ctx context.Context,
	t *testing.T,
	supervisorScheme, supervisorAddress, supervisorCABundle string,
	issuerName string,
	client pinnipedclientset.Interface,
) (*v1alpha1.OIDCProvider, *ExpectedJWKSResponseFormat) {
	t.Helper()
	newOIDCProvider := library.CreateTestOIDCProvider(ctx, t, issuerName, "", "")
	jwksResult := requireDiscoveryEndpointsAreWorking(t, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName, nil)
	requireStatus(t, client, newOIDCProvider.Namespace, newOIDCProvider.Name, v1alpha1.SuccessOIDCProviderStatusCondition)
	return newOIDCProvider, jwksResult
}

func requireDiscoveryEndpointsAreWorking(t *testing.T, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName string, dnsOverrides map[string]string) *ExpectedJWKSResponseFormat {
	requireWellKnownEndpointIsWorking(t, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName, dnsOverrides)
	jwksResult := requireJWKSEndpointIsWorking(t, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName, dnsOverrides)
	return jwksResult
}

func requireDeletingOIDCProviderCausesDiscoveryEndpointsToDisappear(
	t *testing.T,
	existingOIDCProvider *v1alpha1.OIDCProvider,
	client pinnipedclientset.Interface,
	ns string,
	supervisorScheme, supervisorAddress, supervisorCABundle string,
	issuerName string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Delete the OIDCProvider.
	err := client.ConfigV1alpha1().OIDCProviders(ns).Delete(ctx, existingOIDCProvider.Name, metav1.DeleteOptions{})
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
      "jwks_uri": "%s/jwks.json",
      "scopes_supported": ["openid", "offline"],
      "response_types_supported": ["code"],
      "claims_supported": ["groups"],
      "subject_types_supported": ["public"],
      "id_token_signing_alg_values_supported": ["ES256"]
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

	// Define a request to the new discovery endpoint which should have been created by an OIDCProvider.
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

func editOIDCProviderIssuerName(
	t *testing.T,
	existingOIDCProvider *v1alpha1.OIDCProvider,
	client pinnipedclientset.Interface,
	ns string,
	newIssuerName string,
) *v1alpha1.OIDCProvider {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	mostRecentVersion, err := client.ConfigV1alpha1().OIDCProviders(ns).Get(ctx, existingOIDCProvider.Name, metav1.GetOptions{})
	require.NoError(t, err)

	mostRecentVersion.Spec.Issuer = newIssuerName
	updated, err := client.ConfigV1alpha1().OIDCProviders(ns).Update(ctx, mostRecentVersion, metav1.UpdateOptions{})
	require.NoError(t, err)

	return updated
}

func requireDelete(t *testing.T, client pinnipedclientset.Interface, ns, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.ConfigV1alpha1().OIDCProviders(ns).Delete(ctx, name, metav1.DeleteOptions{})
	require.NoError(t, err)
}

func requireStatus(t *testing.T, client pinnipedclientset.Interface, ns, name string, status v1alpha1.OIDCProviderStatusCondition) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var opc *v1alpha1.OIDCProvider
	var err error
	assert.Eventually(t, func() bool {
		opc, err = client.ConfigV1alpha1().OIDCProviders(ns).Get(ctx, name, metav1.GetOptions{})
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
