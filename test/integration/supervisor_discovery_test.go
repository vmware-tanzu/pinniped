// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"

	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	supervisorclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/test/testlib"
)

// TestSupervisorOIDCDiscovery_Disruptive is intended to exercise the supervisor's HTTPS port.
// It can either access it directly via the env.SupervisorHTTPSAddress setting, or it can access
// it indirectly through a TLS-enabled Ingress which uses the supervisor's HTTPS port as its backend
// (via the env.SupervisorHTTPSIngressAddress and env.SupervisorHTTPSIngressCABundle settings),
// or it can exercise it both ways when all of those env settings are present.
// Never run this test in parallel since deleting all federation domains is disruptive, see main_test.go.
func TestSupervisorOIDCDiscovery_Disruptive(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	client := testlib.NewSupervisorClientset(t)
	kubeClient := testlib.NewKubernetesClientset(t)

	ns := env.SupervisorNamespace

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	temporarilyRemoveAllFederationDomainsAndDefaultTLSCertSecret(ctx, t, ns, env.DefaultTLSCertSecretName(), client, testlib.NewKubernetesClientset(t))
	defaultCA := createTLSCertificateSecret(
		ctx,
		t,
		ns,
		testlib.NewSupervisorIssuer(t, env.SupervisorHTTPSAddress),
		env.DefaultTLSCertSecretName(),
		kubeClient,
	)

	tests := []struct {
		Name     string
		Scheme   string
		Address  string
		CABundle string
	}{
		{Name: "direct https", Scheme: "https", Address: env.SupervisorHTTPSAddress, CABundle: string(defaultCA.Bundle())},
		{Name: "ingress https", Scheme: "https", Address: env.SupervisorHTTPSIngressAddress, CABundle: env.SupervisorHTTPSIngressCABundle},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			scheme := test.Scheme
			addr := test.Address
			caBundle := test.CABundle

			if addr == "" {
				// Both cases are not required, so when one is empty skip it.
				t.Skip("no address defined")
			}

			addr, _ = strings.CutPrefix(addr, "https://")

			// Create any IDP so that any FederationDomain created later by this test will see that exactly one IDP exists.
			testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
				Issuer: "https://example.cluster.local/fake-issuer-url-does-not-matter",
				Client: idpv1alpha1.OIDCClient{SecretName: "this-will-not-exist-but-does-not-matter"},
			}, idpv1alpha1.PhaseError)

			// Test that there is no default discovery endpoint available when there are no FederationDomains.
			requireDiscoveryEndpointsAreNotFound(t, scheme, addr, caBundle, fmt.Sprintf("%s://%s", scheme, addr))

			// Define several unique issuer URLs. Always use https in the issuer URL even when we are accessing the http port.
			issuer1 := fmt.Sprintf("https://%s/nested/issuer1", addr)
			issuer2 := fmt.Sprintf("https://%s/nested/issuer2", addr)
			issuer3 := fmt.Sprintf("https://%s/issuer3", addr)
			issuer4 := fmt.Sprintf("https://%s/issuer4", addr)
			issuer5 := fmt.Sprintf("https://%s/issuer5", addr)
			issuer6 := fmt.Sprintf("https://%s/issuer6", addr)
			badIssuer := fmt.Sprintf("https://%s/badIssuer?cannot-use=queries", addr)

			// When FederationDomains are created in sequence they each cause a discovery endpoint to appear only for as long as the FederationDomain exists.
			config1, jwks1 := requireCreatingFederationDomainCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer1, client)
			requireDeletingFederationDomainCausesDiscoveryEndpointsToDisappear(t, config1, client, ns, scheme, addr, caBundle, issuer1)
			config2, jwks2 := requireCreatingFederationDomainCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer2, client)
			requireDeletingFederationDomainCausesDiscoveryEndpointsToDisappear(t, config2, client, ns, scheme, addr, caBundle, issuer2)
			// The auto-created JWK's were different from each other.
			require.NotEqual(t, jwks1.Keys[0]["x"], jwks2.Keys[0]["x"])
			require.NotEqual(t, jwks1.Keys[0]["y"], jwks2.Keys[0]["y"])

			// When multiple FederationDomains exist at the same time they each serve a unique discovery endpoint.
			config3, jwks3 := requireCreatingFederationDomainCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer3, client)
			config4, jwks4 := requireCreatingFederationDomainCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer4, client)
			requireStandardDiscoveryEndpointsAreWorking(t, scheme, addr, caBundle, issuer3, nil) // discovery for issuer3 is still working after issuer4 started working
			// The auto-created JWK's were different from each other.
			require.NotEqual(t, jwks3.Keys[0]["x"], jwks4.Keys[0]["x"])
			require.NotEqual(t, jwks3.Keys[0]["y"], jwks4.Keys[0]["y"])

			// Editing a FederationDomain to change the issuer URL updates the endpoints that are being served.
			updatedConfig4 := editFederationDomainIssuerName(t, config4, client, ns, issuer5)
			requireDiscoveryEndpointsAreNotFound(t, scheme, addr, caBundle, issuer4)
			jwks5 := requireStandardDiscoveryEndpointsAreWorking(t, scheme, addr, caBundle, issuer5, nil)
			// The JWK did not change when the issuer name was updated.
			require.Equal(t, jwks4.Keys[0], jwks5.Keys[0])

			// When they are deleted they stop serving discovery endpoints.
			requireDeletingFederationDomainCausesDiscoveryEndpointsToDisappear(t, config3, client, ns, scheme, addr, caBundle, issuer3)
			requireDeletingFederationDomainCausesDiscoveryEndpointsToDisappear(t, updatedConfig4, client, ns, scheme, addr, caBundle, issuer5)

			// When the same issuer URL is added to two FederationDomains, both FederationDomains are marked as duplicates, and neither is serving.
			config6Duplicate1, _ := requireCreatingFederationDomainCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer6, client)
			config6Duplicate2 := testlib.CreateTestFederationDomain(ctx, t, supervisorconfigv1alpha1.FederationDomainSpec{Issuer: issuer6}, supervisorconfigv1alpha1.FederationDomainPhaseError)
			requireStatus(t, client, ns, config6Duplicate1.Name, supervisorconfigv1alpha1.FederationDomainPhaseError, withFalseConditions([]string{"Ready", "IssuerIsUnique"}))
			requireStatus(t, client, ns, config6Duplicate2.Name, supervisorconfigv1alpha1.FederationDomainPhaseError, withFalseConditions([]string{"Ready", "IssuerIsUnique"}))
			requireDiscoveryEndpointsAreNotFound(t, scheme, addr, caBundle, issuer6)

			// If we delete the first duplicate FederationDomain, the second duplicate FederationDomain starts serving.
			requireDelete(t, client, ns, config6Duplicate1.Name)
			requireWellKnownEndpointIsWorking(t, scheme, addr, caBundle, issuer6, nil)
			requireStatus(t, client, ns, config6Duplicate2.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady, withAllSuccessfulConditions())

			// When we finally delete all FederationDomains, the discovery endpoints should be down.
			requireDeletingFederationDomainCausesDiscoveryEndpointsToDisappear(t, config6Duplicate2, client, ns, scheme, addr, caBundle, issuer6)

			// "Host" headers can be used to send requests to discovery endpoints when the public address is different from the issuer URL.
			issuer7 := "https://some-issuer-host-and-port-that-doesnt-match-public-supervisor-address.com:2684/issuer7"
			config7, _ := requireCreatingFederationDomainCausesDiscoveryEndpointsToAppear(ctx, t, scheme, addr, caBundle, issuer7, client)
			requireDeletingFederationDomainCausesDiscoveryEndpointsToDisappear(t, config7, client, ns, scheme, addr, caBundle, issuer7)

			// When we create a FederationDomain with an invalid issuer url, the status is set to invalid.
			badConfig := testlib.CreateTestFederationDomain(ctx, t, supervisorconfigv1alpha1.FederationDomainSpec{Issuer: badIssuer}, supervisorconfigv1alpha1.FederationDomainPhaseError)
			requireStatus(t, client, ns, badConfig.Name, supervisorconfigv1alpha1.FederationDomainPhaseError, withFalseConditions([]string{"Ready", "IssuerURLValid"}))
			requireDiscoveryEndpointsAreNotFound(t, scheme, addr, caBundle, badIssuer)
			requireDeletingFederationDomainCausesDiscoveryEndpointsToDisappear(t, badConfig, client, ns, scheme, addr, caBundle, badIssuer)

			issuer8 := fmt.Sprintf("https://%s/issuer8multipleIDP", addr)
			config8 := requireIDPsListedByIDPDiscoveryEndpoint(t, env, ctx, kubeClient, ns, scheme, addr, caBundle, issuer8)

			// requireJWKSEndpointIsWorking() will give us a bit of an idea what to do...
			requireDeletingFederationDomainCausesDiscoveryEndpointsToDisappear(t, config8, client, ns, scheme, addr, caBundle, issuer8)
		})
	}
}

// Never run this test in parallel since deleting all federation domains is disruptive, see main_test.go.
func TestSupervisorTLSTerminationWithSNI_Disruptive(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	pinnipedClient := testlib.NewSupervisorClientset(t)
	kubeClient := testlib.NewKubernetesClientset(t)

	ns := env.SupervisorNamespace
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Create any IDP so that any FederationDomain created later by this test will see that exactly one IDP exists.
	testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
		Issuer: "https://example.cluster.local/fake-issuer-url-does-not-matter",
		Client: idpv1alpha1.OIDCClient{SecretName: "this-will-not-exist-but-does-not-matter"},
	}, idpv1alpha1.PhaseError)

	temporarilyRemoveAllFederationDomainsAndDefaultTLSCertSecret(ctx, t, ns, env.DefaultTLSCertSecretName(), pinnipedClient, kubeClient)

	scheme := "https"
	supervisorIssuer := testlib.NewSupervisorIssuer(t, env.SupervisorHTTPSAddress)
	address := supervisorIssuer.Address() // hostname and port WITHOUT SCHEME for direct access to the supervisor's port 8443

	issuer1 := fmt.Sprintf("%s://%s/issuer1", scheme, address)
	certSecretName1 := "integration-test-cert-1"

	// Create an FederationDomain with a spec.tls.secretName.
	federationDomain1 := testlib.CreateTestFederationDomain(ctx, t,
		supervisorconfigv1alpha1.FederationDomainSpec{
			Issuer: issuer1,
			TLS:    &supervisorconfigv1alpha1.FederationDomainTLSSpec{SecretName: certSecretName1},
		}, supervisorconfigv1alpha1.FederationDomainPhaseReady)
	requireStatus(t, pinnipedClient, federationDomain1.Namespace, federationDomain1.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady, withAllSuccessfulConditions())

	// The spec.tls.secretName Secret does not exist, so the endpoints should fail with TLS errors.
	requireEndpointHasBootstrapTLSErrorBecauseCertificatesAreNotReady(t, issuer1)

	// Create the Secret.
	ca1 := createTLSCertificateSecret(ctx, t, ns, supervisorIssuer, certSecretName1, kubeClient)

	// Now that the Secret exists, we should be able to access the endpoints by hostname using the CA.
	_ = requireStandardDiscoveryEndpointsAreWorking(t, scheme, address, string(ca1.Bundle()), issuer1, nil)

	// Update the config to with a new .spec.tls.secretName.
	certSecretName1update := "integration-test-cert-1-update"
	require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		federationDomain1LatestVersion, err := pinnipedClient.ConfigV1alpha1().FederationDomains(ns).Get(ctx, federationDomain1.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		federationDomain1LatestVersion.Spec.TLS = &supervisorconfigv1alpha1.FederationDomainTLSSpec{SecretName: certSecretName1update}
		_, err = pinnipedClient.ConfigV1alpha1().FederationDomains(ns).Update(ctx, federationDomain1LatestVersion, metav1.UpdateOptions{})
		return err
	}))

	// The endpoints should fail with TLS errors again.
	requireEndpointHasBootstrapTLSErrorBecauseCertificatesAreNotReady(t, issuer1)

	// Create a Secret at the updated name.
	ca1update := createTLSCertificateSecret(ctx, t, ns, supervisorIssuer, certSecretName1update, kubeClient)

	// Now that the Secret exists at the new name, we should be able to access the endpoints by hostname using the CA.
	_ = requireStandardDiscoveryEndpointsAreWorking(t, scheme, address, string(ca1update.Bundle()), issuer1, nil)

	// To test SNI virtual hosting, send requests to discovery endpoints when the public address is different from the issuer name.
	hostname2 := "some-issuer-host-and-port-that-doesnt-match-public-supervisor-address.com"
	hostnamePort2 := "2684"
	issuer2 := fmt.Sprintf("%s://%s:%s/issuer2", scheme, hostname2, hostnamePort2)
	certSecretName2 := "integration-test-cert-2"

	// Create an FederationDomain with a spec.tls.secretName.
	federationDomain2 := testlib.CreateTestFederationDomain(ctx, t,
		supervisorconfigv1alpha1.FederationDomainSpec{
			Issuer: issuer2,
			TLS:    &supervisorconfigv1alpha1.FederationDomainTLSSpec{SecretName: certSecretName2},
		}, supervisorconfigv1alpha1.FederationDomainPhaseReady)
	requireStatus(t, pinnipedClient, federationDomain2.Namespace, federationDomain2.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady, withAllSuccessfulConditions())

	// Create the Secret.
	ca2 := createTLSCertificateSecret(ctx, t, ns, testlib.NewSupervisorIssuer(t, issuer2), certSecretName2, kubeClient)

	// Now that the Secret exists, we should be able to access the endpoints by hostname using the CA.
	_ = requireStandardDiscoveryEndpointsAreWorking(t, scheme, hostname2+":"+hostnamePort2, string(ca2.Bundle()), issuer2, map[string]string{
		hostname2 + ":" + hostnamePort2: address,
	})
}

// Never run this test in parallel since deleting all federation domains is disruptive, see main_test.go.
func TestSupervisorTLSTerminationWithDefaultCerts_Disruptive(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	pinnipedClient := testlib.NewSupervisorClientset(t)
	kubeClient := testlib.NewKubernetesClientset(t)

	ns := env.SupervisorNamespace
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Create any IDP so that any FederationDomain created later by this test will see that exactly one IDP exists.
	testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
		Issuer: "https://example.cluster.local/fake-issuer-url-does-not-matter",
		Client: idpv1alpha1.OIDCClient{SecretName: "this-will-not-exist-but-does-not-matter"},
	}, idpv1alpha1.PhaseError)

	temporarilyRemoveAllFederationDomainsAndDefaultTLSCertSecret(ctx, t, ns, env.DefaultTLSCertSecretName(), pinnipedClient, kubeClient)

	scheme := "https"
	supervisorIssuer := testlib.NewSupervisorIssuer(t, env.SupervisorHTTPSAddress)
	address := supervisorIssuer.Address() // hostname and port WITHOUT SCHEME for direct access to the supervisor's port 8443

	// hostnames are case-insensitive, so test mis-matching the case of the issuer URL and the request URL
	hostname := strings.ToLower(supervisorIssuer.Hostname())
	port := supervisorIssuer.Port("8443")

	ips, err := testlib.LookupIP(ctx, hostname)
	require.NoError(t, err)
	require.NotEmpty(t, ips)
	ipAsHostname := ips[0].String()
	ipWithPort := ipAsHostname + ":" + port

	// Use different paths just in case the hostname is the IP address!
	issuerUsingIPAddress := fmt.Sprintf("%s://%s/issuer1", scheme, ipWithPort)
	issuerUsingHostname := fmt.Sprintf("%s://%s/issuer2", scheme, address)

	// Create an FederationDomain without a spec.tls.secretName.
	federationDomain1 := testlib.CreateTestFederationDomain(ctx, t, supervisorconfigv1alpha1.FederationDomainSpec{Issuer: issuerUsingIPAddress}, supervisorconfigv1alpha1.FederationDomainPhaseReady)
	requireStatus(t, pinnipedClient, federationDomain1.Namespace, federationDomain1.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady, withAllSuccessfulConditions())

	// There is no default TLS cert and the spec.tls.secretName was not set, so the endpoints should fail with TLS errors.
	requireEndpointHasBootstrapTLSErrorBecauseCertificatesAreNotReady(t, issuerUsingIPAddress)

	// Create a Secret at the special name which represents the default TLS cert.
	defaultCA := createTLSCertificateSecret(ctx, t, ns, testlib.NewSupervisorIssuer(t, issuerUsingIPAddress), env.DefaultTLSCertSecretName(), kubeClient)

	// Now that the Secret exists, we should be able to access the endpoints by IP address using the CA.
	_ = requireStandardDiscoveryEndpointsAreWorking(t, scheme, ipWithPort, string(defaultCA.Bundle()), issuerUsingIPAddress, nil)

	// Create an FederationDomain with a spec.tls.secretName.
	certSecretName := "integration-test-cert-1"
	federationDomain2 := testlib.CreateTestFederationDomain(ctx, t,
		supervisorconfigv1alpha1.FederationDomainSpec{
			Issuer: issuerUsingHostname,
			TLS:    &supervisorconfigv1alpha1.FederationDomainTLSSpec{SecretName: certSecretName},
		}, supervisorconfigv1alpha1.FederationDomainPhaseReady)
	requireStatus(t, pinnipedClient, federationDomain2.Namespace, federationDomain2.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady, withAllSuccessfulConditions())

	// Create the Secret.
	certCA := createTLSCertificateSecret(ctx, t, ns, supervisorIssuer, certSecretName, kubeClient)

	// Now that the Secret exists, we should be able to access the endpoints by hostname using the CA from the SNI cert.
	// Hostnames are case-insensitive, so the request should still work even if the case of the hostname is different
	// from the case of the issuer URL's hostname.
	_ = requireStandardDiscoveryEndpointsAreWorking(t, scheme, strings.ToUpper(hostname)+":"+port, string(certCA.Bundle()), issuerUsingHostname, nil)

	// And we can still access the other issuer using the default cert.
	_ = requireStandardDiscoveryEndpointsAreWorking(t, scheme, ipWithPort, string(defaultCA.Bundle()), issuerUsingIPAddress, nil)
}

func createTLSCertificateSecret(
	ctx context.Context,
	t *testing.T,
	namespace string,
	supervisorIssuer testlib.SupervisorIssuer,
	secretName string,
	kubeClient kubernetes.Interface,
) *certauthority.CA {
	// Create a CA.
	ca, err := certauthority.New("Acme Corp", 1000*time.Hour)
	require.NoError(t, err)

	// Using the CA, create a TLS server cert.
	certPEM, keyPEM := supervisorIssuer.IssuerServerCert(t, ca)

	// Write the serving cert to the SNI secret.
	secret := corev1.Secret{
		Type:     corev1.SecretTypeTLS,
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		StringData: map[string]string{
			"tls.crt": string(certPEM),
			"tls.key": string(keyPEM),
		},
	}
	_, err = kubeClient.CoreV1().Secrets(namespace).Create(ctx, &secret, metav1.CreateOptions{})
	require.NoError(t, err)

	// Delete the Secret when the test ends.
	t.Cleanup(func() {
		t.Helper()
		deleteCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		err := kubeClient.CoreV1().Secrets(namespace).Delete(deleteCtx, secretName, metav1.DeleteOptions{})
		require.NoError(t, err)
	})

	return ca
}

func temporarilyRemoveAllFederationDomainsAndDefaultTLSCertSecret(
	ctx context.Context,
	t *testing.T,
	ns string,
	defaultTLSCertSecretName string,
	pinnipedClient supervisorclientset.Interface,
	kubeClient kubernetes.Interface,
) {
	// Temporarily remove any existing FederationDomains from the cluster so we can test from a clean slate.
	originalConfigList, err := pinnipedClient.ConfigV1alpha1().FederationDomains(ns).List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	for _, config := range originalConfigList.Items {
		err := pinnipedClient.ConfigV1alpha1().FederationDomains(ns).Delete(ctx, config.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	}

	// Also remove the supervisor's default TLS cert
	originalSecret, err := kubeClient.CoreV1().Secrets(ns).Get(ctx, defaultTLSCertSecretName, metav1.GetOptions{})
	notFound := apierrors.IsNotFound(err)
	require.False(t, err != nil && !notFound, "unexpected error when getting %s", defaultTLSCertSecretName)
	if notFound {
		originalSecret = nil
	} else {
		err = kubeClient.CoreV1().Secrets(ns).Delete(ctx, defaultTLSCertSecretName, metav1.DeleteOptions{})
		require.NoError(t, err)
	}

	// When this test has finished, recreate any FederationDomains and default secret that had existed on the cluster before this test.
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		for _, config := range originalConfigList.Items {
			thisConfig := config
			thisConfig.ResourceVersion = "" // Get rid of resource version since we can't create an object with one.
			_, err := pinnipedClient.ConfigV1alpha1().FederationDomains(ns).Create(cleanupCtx, &thisConfig, metav1.CreateOptions{})
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

	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		requestNonExistentPath, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		require.NoError(t, err)

		requestNonExistentPath.Host = host

		response, err := httpClient.Do(requestNonExistentPath)
		requireEventually.NoError(err)
		requireEventually.NoError(response.Body.Close())
		requireEventually.Equal(http.StatusNotFound, response.StatusCode)
	}, 2*time.Minute, 200*time.Millisecond)
}

func requireEndpointHasBootstrapTLSErrorBecauseCertificatesAreNotReady(t *testing.T, url string) {
	t.Helper()

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // there is no way for us to know the bootstrap CA
		},
	}

	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		requireEventually.NoError(err)

		response, err := httpClient.Do(request)
		requireEventually.NoError(err)

		t.Cleanup(func() {
			_ = response.Body.Close()
		})

		requireEventually.Equal(http.StatusInternalServerError, response.StatusCode)

		body, err := io.ReadAll(response.Body)
		requireEventually.NoError(err)

		requireEventually.Equal("pinniped supervisor has invalid TLS serving certificate configuration\n", string(body))
	}, 2*time.Minute, 200*time.Millisecond)
}

func requireCreatingFederationDomainCausesDiscoveryEndpointsToAppear(
	ctx context.Context,
	t *testing.T,
	supervisorScheme, supervisorAddress, supervisorCABundle string,
	issuerName string,
	client supervisorclientset.Interface,
) (*supervisorconfigv1alpha1.FederationDomain, *ExpectedJWKSResponseFormat) {
	t.Helper()
	newFederationDomain := testlib.CreateTestFederationDomain(ctx, t, supervisorconfigv1alpha1.FederationDomainSpec{Issuer: issuerName}, supervisorconfigv1alpha1.FederationDomainPhaseReady)
	jwksResult := requireStandardDiscoveryEndpointsAreWorking(t, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName, nil)
	requireStatus(t, client, newFederationDomain.Namespace, newFederationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady, withAllSuccessfulConditions())
	return newFederationDomain, jwksResult
}

func requireStandardDiscoveryEndpointsAreWorking(t *testing.T, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName string, dnsOverrides map[string]string) *ExpectedJWKSResponseFormat {
	requireWellKnownEndpointIsWorking(t, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName, dnsOverrides)
	jwksResult := requireJWKSEndpointIsWorking(t, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName, dnsOverrides)
	return jwksResult
}

func requireDeletingFederationDomainCausesDiscoveryEndpointsToDisappear(
	t *testing.T,
	existingFederationDomain *supervisorconfigv1alpha1.FederationDomain,
	client supervisorclientset.Interface,
	ns string,
	supervisorScheme, supervisorAddress, supervisorCABundle string,
	issuerName string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Delete the FederationDomain.
	err := client.ConfigV1alpha1().FederationDomains(ns).Delete(ctx, existingFederationDomain.Name, metav1.DeleteOptions{})
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
      "scopes_supported": ["openid", "offline_access", "pinniped:request-audience", "username", "groups"],
      "response_types_supported": ["code"],
      "response_modes_supported": ["query", "form_post"],
      "code_challenge_methods_supported": ["S256"],
      "claims_supported": ["username", "groups", "additionalClaims"],
      "discovery.supervisor.pinniped.dev/v1alpha1": {"pinniped_identity_providers_endpoint": "%s/v1alpha1/pinniped_identity_providers"},
      "subject_types_supported": ["public"],
      "id_token_signing_alg_values_supported": ["ES256"]
    }`)
	expectedJSON := fmt.Sprintf(expectedResultTemplate, issuerName, issuerName, issuerName, issuerName, issuerName)

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

	issuerURL, err := url.Parse(issuer)
	require.NoError(t, err)

	// Fetch that discovery endpoint. Give it some time for the endpoint to come into existence.
	var response *http.Response
	var responseBody []byte
	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Define a request to the new discovery endpoint which should have been created by an FederationDomain.
		requestDiscoveryEndpoint, err := http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			endpointURL,
			nil,
		)
		requireEventually.NoError(err)

		// Set the host header on the request to match the issuer's hostname, which could potentially be different
		// from the public ingress address, e.g. when a load balancer is used, so we want to test here that the host
		// header is respected by the supervisor server.
		requestDiscoveryEndpoint.Host = issuerURL.Host

		response, err = httpClient.Do(requestDiscoveryEndpoint)
		requireEventually.NoError(err)
		defer func() { _ = response.Body.Close() }()

		requireEventually.Equal(http.StatusOK, response.StatusCode)

		responseBody, err = io.ReadAll(response.Body)
		requireEventually.NoError(err)
	}, 2*time.Minute, 200*time.Millisecond)

	return response, string(responseBody)
}

func editFederationDomainIssuerName(
	t *testing.T,
	existingFederationDomain *supervisorconfigv1alpha1.FederationDomain,
	client supervisorclientset.Interface,
	ns string,
	newIssuerName string,
) *supervisorconfigv1alpha1.FederationDomain {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var updated *supervisorconfigv1alpha1.FederationDomain
	require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		mostRecentVersion, err := client.ConfigV1alpha1().FederationDomains(ns).Get(ctx, existingFederationDomain.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		mostRecentVersion.Spec.Issuer = newIssuerName
		updated, err = client.ConfigV1alpha1().FederationDomains(ns).Update(ctx, mostRecentVersion, metav1.UpdateOptions{})
		return err
	}))
	return updated
}

func requireDelete(t *testing.T, client supervisorclientset.Interface, ns, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	err := client.ConfigV1alpha1().FederationDomains(ns).Delete(ctx, name, metav1.DeleteOptions{})
	require.NoError(t, err)
}

func withAllSuccessfulConditions() map[string]metav1.ConditionStatus {
	return map[string]metav1.ConditionStatus{
		"Ready":                                         metav1.ConditionTrue,
		"IssuerIsUnique":                                metav1.ConditionTrue,
		"IdentityProvidersFound":                        metav1.ConditionTrue,
		"OneTLSSecretPerIssuerHostname":                 metav1.ConditionTrue,
		"IssuerURLValid":                                metav1.ConditionTrue,
		"IdentityProvidersObjectRefKindValid":           metav1.ConditionTrue,
		"IdentityProvidersObjectRefAPIGroupSuffixValid": metav1.ConditionTrue,
		"IdentityProvidersDisplayNamesUnique":           metav1.ConditionTrue,
		"TransformsExpressionsValid":                    metav1.ConditionTrue,
		"TransformsExamplesPassed":                      metav1.ConditionTrue,
	}
}

func withFalseConditions(falseConditionTypes []string) map[string]metav1.ConditionStatus {
	c := map[string]metav1.ConditionStatus{}
	for k, v := range withAllSuccessfulConditions() {
		if slices.Contains(falseConditionTypes, k) {
			c[k] = metav1.ConditionFalse
		} else {
			c[k] = v
		}
	}
	return c
}

func requireStatus(t *testing.T, client supervisorclientset.Interface, ns, name string, wantPhase supervisorconfigv1alpha1.FederationDomainPhase, wantConditionTypeToStatus map[string]metav1.ConditionStatus) {
	t.Helper()

	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		federationDomain, err := client.ConfigV1alpha1().FederationDomains(ns).Get(ctx, name, metav1.GetOptions{})
		requireEventually.NoError(err)

		actualPhase := federationDomain.Status.Phase
		t.Logf("found FederationDomain %s/%s with phase %s, wanted phase %s", ns, name, actualPhase, wantPhase)
		requireEventually.Equalf(wantPhase, actualPhase, "unexpected phase (conditions = '%#v')", federationDomain.Status.Conditions)

		actualConditionTypeToStatus := map[string]metav1.ConditionStatus{}
		for _, c := range federationDomain.Status.Conditions {
			actualConditionTypeToStatus[c.Type] = c.Status
		}
		t.Logf("found FederationDomain %s/%s with conditions %#v, wanted condtions %#v", ns, name, actualConditionTypeToStatus, wantConditionTypeToStatus)
		requireEventually.Equal(wantConditionTypeToStatus, actualConditionTypeToStatus, "unexpected statuses for conditions by type")
	}, 5*time.Minute, 200*time.Millisecond)
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
			TLSClientConfig: &tls.Config{MinVersion: ptls.SecureTLSConfigMinTLSVersion, RootCAs: caCertPool}, //nolint:gosec // this seems to be a false flag, min tls version is 1.3 in normal mode or 1.2 in fips mode
		}
	} else {
		c.Transport = &http.Transport{
			DialContext: overrideDialContext,
		}
	}

	return c
}

func requireIDPsListedByIDPDiscoveryEndpoint(
	t *testing.T,
	env *testlib.TestEnv,
	ctx context.Context,
	kubeClient kubernetes.Interface,
	ns, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName string) *supervisorconfigv1alpha1.FederationDomain {
	// github
	gitHubIDPSecretName := "github-idp-secret" //nolint:gosec // this is not a credential
	_, err := kubeClient.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{
		Type:     "secrets.pinniped.dev/github-client",
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      gitHubIDPSecretName,
			Namespace: ns,
		},
		StringData: map[string]string{
			"clientID":     "foo",
			"clientSecret": "bar",
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = kubeClient.CoreV1().Secrets(ns).Delete(ctx, gitHubIDPSecretName, metav1.DeleteOptions{})
	})

	ghIDP := testlib.CreateGitHubIdentityProvider(t, idpv1alpha1.GitHubIdentityProviderSpec{
		Client: idpv1alpha1.GitHubClientSpec{
			SecretName: gitHubIDPSecretName,
		},
		AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
			Organizations: idpv1alpha1.GitHubOrganizationsSpec{
				Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
			},
		},
	}, idpv1alpha1.GitHubPhaseReady)

	ldapBindSecret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ldap-service-account", corev1.SecretTypeBasicAuth,
		map[string]string{
			corev1.BasicAuthUsernameKey: env.SupervisorUpstreamLDAP.BindUsername,
			corev1.BasicAuthPasswordKey: env.SupervisorUpstreamLDAP.BindPassword,
		},
	)
	ldapIDP := testlib.CreateTestLDAPIdentityProvider(t, idpv1alpha1.LDAPIdentityProviderSpec{
		Host: env.SupervisorUpstreamLDAP.Host,
		TLS: &idpv1alpha1.TLSSpec{
			CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.CABundle)),
		},
		Bind: idpv1alpha1.LDAPIdentityProviderBind{
			SecretName: ldapBindSecret.Name,
		},
		UserSearch: idpv1alpha1.LDAPIdentityProviderUserSearch{
			Base:   env.SupervisorUpstreamLDAP.UserSearchBase,
			Filter: "",
			Attributes: idpv1alpha1.LDAPIdentityProviderUserSearchAttributes{
				Username: env.SupervisorUpstreamLDAP.TestUserMailAttributeName,
				UID:      env.SupervisorUpstreamLDAP.TestUserUniqueIDAttributeName,
			},
		},
		GroupSearch: idpv1alpha1.LDAPIdentityProviderGroupSearch{
			Base:   env.SupervisorUpstreamLDAP.GroupSearchBase,
			Filter: "", // use the default value of "member={}"
			Attributes: idpv1alpha1.LDAPIdentityProviderGroupSearchAttributes{
				GroupName: "", // use the default value of "dn"
			},
		},
	}, idpv1alpha1.LDAPPhaseReady)

	oidcIDP := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
		Issuer: env.SupervisorUpstreamOIDC.Issuer,
		TLS: &idpv1alpha1.TLSSpec{
			CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
		},
		AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
			AdditionalScopes: env.SupervisorUpstreamOIDC.AdditionalScopes,
		},
		Claims: idpv1alpha1.OIDCClaims{
			Username: env.SupervisorUpstreamOIDC.UsernameClaim,
			Groups:   env.SupervisorUpstreamOIDC.GroupsClaim,
		},
		Client: idpv1alpha1.OIDCClient{
			SecretName: testlib.CreateOIDCClientCredentialsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
		},
	}, idpv1alpha1.PhaseReady)

	var adIDP *idpv1alpha1.ActiveDirectoryIdentityProvider
	if activeDirectoryAvailable(t, env) {
		activeDirectoryBindSecret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ldap-service-account", corev1.SecretTypeBasicAuth,
			map[string]string{
				corev1.BasicAuthUsernameKey: env.SupervisorUpstreamActiveDirectory.BindUsername,
				corev1.BasicAuthPasswordKey: env.SupervisorUpstreamActiveDirectory.BindPassword,
			},
		)
		adIDP = testlib.CreateTestActiveDirectoryIdentityProvider(t, idpv1alpha1.ActiveDirectoryIdentityProviderSpec{
			Host: env.SupervisorUpstreamActiveDirectory.Host,
			TLS: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamActiveDirectory.CABundle)),
			},
			Bind: idpv1alpha1.ActiveDirectoryIdentityProviderBind{
				SecretName: activeDirectoryBindSecret.Name,
			},
		}, idpv1alpha1.ActiveDirectoryPhaseReady)
	}

	idpsForFD := []supervisorconfigv1alpha1.FederationDomainIdentityProvider{{
		DisplayName: ghIDP.Name,
		ObjectRef: corev1.TypedLocalObjectReference{
			APIGroup: ptr.To("idp.supervisor." + env.APIGroupSuffix),
			Kind:     "GitHubIdentityProvider",
			Name:     ghIDP.Name,
		},
	}, {
		DisplayName: ldapIDP.Name,
		ObjectRef: corev1.TypedLocalObjectReference{
			APIGroup: ptr.To("idp.supervisor." + env.APIGroupSuffix),
			Kind:     "LDAPIdentityProvider",
			Name:     ldapIDP.Name,
		},
	}, {
		DisplayName: oidcIDP.Name,
		ObjectRef: corev1.TypedLocalObjectReference{
			APIGroup: ptr.To("idp.supervisor." + env.APIGroupSuffix),
			Kind:     "OIDCIdentityProvider",
			Name:     oidcIDP.Name,
		},
	}}
	if activeDirectoryAvailable(t, env) {
		idpsForFD = append(idpsForFD, supervisorconfigv1alpha1.FederationDomainIdentityProvider{
			DisplayName: adIDP.Name,
			ObjectRef: corev1.TypedLocalObjectReference{
				APIGroup: ptr.To("idp.supervisor." + env.APIGroupSuffix),
				Kind:     "ActiveDirectoryIdentityProvider",
				Name:     adIDP.Name,
			},
		})
	}
	federationDomainConfig := testlib.CreateTestFederationDomain(ctx, t, supervisorconfigv1alpha1.FederationDomainSpec{
		Issuer:            issuerName,
		IdentityProviders: idpsForFD,
	}, supervisorconfigv1alpha1.FederationDomainPhaseReady)

	requireStandardDiscoveryEndpointsAreWorking(t, supervisorScheme, supervisorAddress, supervisorCABundle, issuerName, nil)
	issuer8URL, err := url.Parse(issuerName)
	require.NoError(t, err)
	wellKnownURL := wellKnownURLForIssuer(supervisorScheme, supervisorAddress, issuer8URL.Path)
	_, wellKnownResponseBody := requireSuccessEndpointResponse(t, wellKnownURL, issuerName, supervisorCABundle, nil) //nolint:bodyclose

	type WellKnownResponse struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JWKSUri               string `json:"jwks_uri"`
		DiscoverySupervisor   struct {
			IdentityProvidersEndpoint string `json:"pinniped_identity_providers_endpoint"`
		} `json:"discovery.supervisor.pinniped.dev/v1alpha1"`
	}
	var wellKnownResponse WellKnownResponse
	err = json.Unmarshal([]byte(wellKnownResponseBody), &wellKnownResponse)
	require.NoError(t, err)
	discoveryIDPEndpoint := wellKnownResponse.DiscoverySupervisor.IdentityProvidersEndpoint
	_, discoveryIDPResponseBody := requireSuccessEndpointResponse(t, discoveryIDPEndpoint, issuerName, supervisorCABundle, nil) //nolint:bodyclose
	type IdentityProviderListResponse struct {
		IdentityProviders []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"pinniped_identity_providers"`
	}
	var identityProviderListResponse IdentityProviderListResponse
	err = json.Unmarshal([]byte(discoveryIDPResponseBody), &identityProviderListResponse)
	require.NoError(t, err)

	allIDPs := []string{ghIDP.Name, ldapIDP.Name, oidcIDP.Name}
	if activeDirectoryAvailable(t, env) {
		allIDPs = append(allIDPs, adIDP.Name)
	}
	require.Equal(t, len(identityProviderListResponse.IdentityProviders), len(allIDPs), "all IDPs should be listed by idp discovery endpoint")
	for _, provider := range identityProviderListResponse.IdentityProviders {
		require.Contains(t, allIDPs, provider.Name, fmt.Sprintf("provider name should be listed in IDP discovery: %s", provider.Name))
	}

	return federationDomainConfig
}

func activeDirectoryAvailable(t *testing.T, env *testlib.TestEnv) bool {
	t.Helper()
	hasLDAPPorts := env.HasCapability(testlib.CanReachInternetLDAPPorts)
	hasADHost := testlib.IntegrationEnv(t).SupervisorUpstreamActiveDirectory.Host != ""
	return hasLDAPPorts && hasADHost
}
