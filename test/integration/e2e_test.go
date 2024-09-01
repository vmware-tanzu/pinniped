// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/utils/ptr"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	supervisorclient "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/typed/config/v1alpha1"
	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/filesession"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	"go.pinniped.dev/test/testlib"
	"go.pinniped.dev/test/testlib/browsertest"
)

// TestE2EFullIntegration_Browser tests a full integration scenario that combines the supervisor, concierge, and CLI.
func TestE2EFullIntegration_Browser(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	allScopes := []string{"openid", "offline_access", "pinniped:request-audience", "username", "groups"}

	// Avoid allowing PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW to interfere with these tests.
	originalFlowEnvVarValue, flowOverrideEnvVarSet := os.LookupEnv("PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW")
	if flowOverrideEnvVarSet {
		require.NoError(t, os.Unsetenv("PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW"))
		t.Cleanup(func() {
			require.NoError(t, os.Setenv("PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW", originalFlowEnvVarValue))
		})
	}

	topSetupCtx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancelFunc()
	supervisorClient := testlib.NewSupervisorClientset(t)
	kubeClient := testlib.NewKubernetesClientset(t)
	temporarilyRemoveAllFederationDomainsAndDefaultTLSCertSecret(
		topSetupCtx,
		t,
		env.SupervisorNamespace,
		env.DefaultTLSCertSecretName(),
		supervisorClient,
		kubeClient,
	)

	// Build pinniped CLI.
	pinnipedExe := testlib.PinnipedCLIPath(t)

	supervisorIssuer := env.InferSupervisorIssuerURL(t)

	// Generate a CA bundle with which to serve this provider.
	t.Logf("generating test CA")
	tlsServingCertForSupervisorSecretName := "federation-domain-serving-cert-" + testlib.RandHex(t, 8)

	federationDomainSelfSignedCA := createTLSServingCertSecretForSupervisor(
		topSetupCtx,
		t,
		env,
		supervisorIssuer,
		tlsServingCertForSupervisorSecretName,
		kubeClient,
	)

	// Save that bundle plus the one that signs the upstream issuer, for test purposes.
	federationDomainCABundlePath := filepath.Join(t.TempDir(), "test-ca.pem")
	federationDomainCABundlePEM := federationDomainSelfSignedCA.Bundle()
	require.NoError(t, os.WriteFile(federationDomainCABundlePath, federationDomainCABundlePEM, 0600))

	// Create the downstream FederationDomain.
	// This helper function will nil out spec.TLS if spec.Issuer is an IP address.
	federationDomain := testlib.CreateTestFederationDomain(topSetupCtx, t,
		supervisorconfigv1alpha1.FederationDomainSpec{
			Issuer: supervisorIssuer.Issuer(),
			TLS:    &supervisorconfigv1alpha1.FederationDomainTLSSpec{SecretName: tlsServingCertForSupervisorSecretName},
		},
		supervisorconfigv1alpha1.FederationDomainPhaseError, // in phase error until there is an IDP created
	)

	// Create a JWTAuthenticator that will validate the tokens from the downstream issuer.
	// If the FederationDomain is not Ready, the JWTAuthenticator cannot be ready, either.
	clusterAudience := "test-cluster-" + testlib.RandHex(t, 8)
	defaultJWTAuthenticatorSpec := authenticationv1alpha1.JWTAuthenticatorSpec{
		Issuer:   federationDomain.Spec.Issuer,
		Audience: clusterAudience,
		TLS:      &authenticationv1alpha1.TLSSpec{CertificateAuthorityData: base64.StdEncoding.EncodeToString(federationDomainCABundlePEM)},
	}

	// Add an OIDC upstream IDP and try using it to authenticate during kubectl commands.
	t.Run("with Supervisor OIDC upstream IDP and browser flow with with form_post automatic authcode delivery to CLI", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		// Start a fresh browser driver because we don't want to share cookies between the various tests in this file.
		browser := browsertest.OpenBrowser(t)

		expectedUsername := env.SupervisorUpstreamOIDC.Username
		expectedGroups := env.SupervisorUpstreamOIDC.ExpectedGroups

		// Create a ClusterRoleBinding to give our test user from the upstream read-only access to the cluster.
		testlib.CreateTestClusterRoleBinding(t,
			rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: expectedUsername},
			rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "view"},
		)
		testlib.WaitForUserToHaveAccess(t, expectedUsername, []string{}, &authorizationv1.ResourceAttributes{
			Verb:     "get",
			Group:    "",
			Version:  "v1",
			Resource: "namespaces",
		})

		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, defaultJWTAuthenticatorSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)
		// Create upstream OIDC provider and wait for it to become ready.
		createdProvider := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
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
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-ca-bundle", federationDomainCABundlePath,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// Run "kubectl get namespaces" which should trigger a browser login via the plugin.
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath, "-v", "6")
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())

		// Run the kubectl command, wait for the Pinniped CLI to print the authorization URL, and open it in the browser.
		kubectlOutputChan := startKubectlAndOpenAuthorizationURLInBrowser(testCtx, t, kubectlCmd, browser)

		// Confirm that we got to the upstream IDP's login page, fill out the form, and submit the form.
		browsertest.LoginToUpstreamOIDC(t, browser, env.SupervisorUpstreamOIDC)

		// Expect to be redirected to the downstream callback which is serving the form_post HTML.
		t.Logf("waiting for response page %s", federationDomain.Spec.Issuer)
		browser.WaitForURL(t, regexp.MustCompile(regexp.QuoteMeta(federationDomain.Spec.Issuer)))

		// The response page should have done the background fetch() and POST'ed to the CLI's callback.
		// It should now be in the "success" state.
		formpostExpectSuccessState(t, browser)

		requireKubectlGetNamespaceOutput(t, env, waitForKubectlOutput(t, kubectlOutputChan))

		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, createdProvider.Name, kubeconfigPath,
			sessionCachePath, pinnipedExe, expectedUsername, expectedGroups, allScopes)
	})

	// If the username and groups scope are not requested by the CLI, then the CLI still gets them, to allow for
	// backwards compatibility with old CLIs that did not request those scopes because they did not exist yet.
	t.Run("with Supervisor OIDC upstream IDP and browser flow, downstream username and groups scopes not requested", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		// Start a fresh browser driver because we don't want to share cookies between the various tests in this file.
		browser := browsertest.OpenBrowser(t)

		expectedUsername := env.SupervisorUpstreamOIDC.Username
		expectedGroups := env.SupervisorUpstreamOIDC.ExpectedGroups

		// Create a ClusterRoleBinding to give our test user from the upstream read-only access to the cluster.
		testlib.CreateTestClusterRoleBinding(t,
			rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: expectedUsername},
			rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "view"},
		)
		testlib.WaitForUserToHaveAccess(t, expectedUsername, []string{}, &authorizationv1.ResourceAttributes{
			Verb:     "get",
			Group:    "",
			Version:  "v1",
			Resource: "namespaces",
		})

		// in this test, use a secret of type TLS to source ca bundle for the JWT authenticator
		caSecret := testlib.CreateTestSecret(t, env.ConciergeNamespace, "ca-cert", corev1.SecretTypeTLS,
			map[string]string{
				"ca.crt":  string(federationDomainCABundlePEM),
				"tls.crt": "",
				"tls.key": "",
			})
		jwtAuthnSpec := defaultJWTAuthenticatorSpec.DeepCopy()
		jwtAuthnSpec.TLS.CertificateAuthorityData = ""
		jwtAuthnSpec.TLS.CertificateAuthorityDataSource = &authenticationv1alpha1.CertificateAuthorityDataSourceSpec{
			Kind: "Secret",
			Name: caSecret.Name,
			Key:  "ca.crt",
		}
		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, *jwtAuthnSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)

		// Create upstream OIDC provider and wait for it to become ready.
		createdProvider := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
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
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-ca-bundle", federationDomainCABundlePath,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			"--oidc-scopes", "offline_access,openid,pinniped:request-audience", // does not request username or groups
		})

		// Run "kubectl get namespaces" which should trigger a browser login via the plugin.
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath, "-v", "6")
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())

		// Run the kubectl command, wait for the Pinniped CLI to print the authorization URL, and open it in the browser.
		kubectlOutputChan := startKubectlAndOpenAuthorizationURLInBrowser(testCtx, t, kubectlCmd, browser)

		// Confirm that we got to the upstream IDP's login page, fill out the form, and submit the form.
		browsertest.LoginToUpstreamOIDC(t, browser, env.SupervisorUpstreamOIDC)

		// Expect to be redirected to the downstream callback which is serving the form_post HTML.
		t.Logf("waiting for response page %s", federationDomain.Spec.Issuer)
		browser.WaitForURL(t, regexp.MustCompile(regexp.QuoteMeta(federationDomain.Spec.Issuer)))

		// The response page should have done the background fetch() and POST'ed to the CLI's callback.
		// It should now be in the "success" state.
		formpostExpectSuccessState(t, browser)

		requireKubectlGetNamespaceOutput(t, env, waitForKubectlOutput(t, kubectlOutputChan))

		// Note that the list of scopes param here is used to form the cache key for looking up local session storage.
		// The scopes portion of the cache key is made up of the requested scopes from the CLI flag, not the granted
		// scopes returned by the Supervisor, so list the requested scopes from the CLI flag here. This helper will
		// assert that the expected username and groups claims/values are in the downstream ID token.
		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, createdProvider.Name, kubeconfigPath,
			sessionCachePath, pinnipedExe, expectedUsername, expectedGroups, []string{"offline_access", "openid", "pinniped:request-audience"})
	})

	t.Run("with Supervisor OIDC upstream IDP and manual authcode copy-paste from browser flow", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		// Start a fresh browser driver because we don't want to share cookies between the various tests in this file.
		browser := browsertest.OpenBrowser(t)

		expectedUsername := env.SupervisorUpstreamOIDC.Username
		expectedGroups := env.SupervisorUpstreamOIDC.ExpectedGroups

		// Create a ClusterRoleBinding to give our test user from the upstream read-only access to the cluster.
		testlib.CreateTestClusterRoleBinding(t,
			rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: expectedUsername},
			rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "view"},
		)
		testlib.WaitForUserToHaveAccess(t, expectedUsername, []string{}, &authorizationv1.ResourceAttributes{
			Verb:     "get",
			Group:    "",
			Version:  "v1",
			Resource: "namespaces",
		})

		// in this test, use a secret of type opaque to source ca bundle for the JWT authenticator
		caSecret := testlib.CreateTestSecret(t, env.ConciergeNamespace, "ca-cert", corev1.SecretTypeOpaque,
			map[string]string{
				"ca.crt": string(federationDomainCABundlePEM),
			})
		jwtAuthnSpec := defaultJWTAuthenticatorSpec.DeepCopy()
		jwtAuthnSpec.TLS.CertificateAuthorityData = ""
		jwtAuthnSpec.TLS.CertificateAuthorityDataSource = &authenticationv1alpha1.CertificateAuthorityDataSourceSpec{
			Kind: "Secret",
			Name: caSecret.Name,
			Key:  "ca.crt",
		}
		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, *jwtAuthnSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)

		// Create upstream OIDC provider and wait for it to become ready.
		createdProvider := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
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
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-skip-listen",
			"--oidc-ca-bundle", federationDomainCABundlePath,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// Run "kubectl get namespaces" which should trigger a browser login via the plugin.
		start := time.Now()
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())

		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Wait for the subprocess to print the login prompt.
		t.Logf("waiting for CLI to output login URL and manual prompt")
		output := readFromFileUntilStringIsSeen(t, ptyFile, "Optionally, paste your authorization code: ")
		require.Contains(t, output, "Log in by visiting this link:")
		require.Contains(t, output, "Optionally, paste your authorization code: ")

		// Find the line with the login URL.
		var loginURL string
		for _, line := range strings.Split(output, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "https://") {
				loginURL = trimmed
			}
		}
		require.NotEmptyf(t, loginURL, "didn't find login URL in output: %s", output)

		t.Logf("navigating to login page")
		browser.Navigate(t, loginURL)

		// Expect to be redirected to the upstream provider and log in.
		browsertest.LoginToUpstreamOIDC(t, browser, env.SupervisorUpstreamOIDC)

		// Expect to be redirected to the downstream callback which is serving the form_post HTML.
		t.Logf("waiting for response page %s", federationDomain.Spec.Issuer)
		browser.WaitForURL(t, regexp.MustCompile(regexp.QuoteMeta(federationDomain.Spec.Issuer)))

		// The response page should have failed to automatically post, and should now be showing the manual instructions.
		authCode := formpostExpectManualState(t, browser)

		// Enter the auth code in the waiting prompt, followed by a newline.
		t.Logf("'manually' pasting authorization code with length %d to waiting prompt", len(authCode))
		_, err = ptyFile.WriteString(authCode + "\n")
		require.NoError(t, err)

		// Read all the remaining output from the subprocess until EOF.
		t.Logf("waiting for kubectl to output namespace list")
		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlOutputBytes, _ := io.ReadAll(ptyFile)
		requireKubectlGetNamespaceOutput(t, env, string(kubectlOutputBytes))

		t.Logf("first kubectl command took %s", time.Since(start).String())

		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, createdProvider.Name, kubeconfigPath,
			sessionCachePath, pinnipedExe, expectedUsername, expectedGroups, allScopes)
	})

	t.Run("access token based refresh with Supervisor OIDC upstream IDP and manual authcode copy-paste from browser flow", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		// Start a fresh browser driver because we don't want to share cookies between the various tests in this file.
		browser := browsertest.OpenBrowser(t)

		expectedUsername := env.SupervisorUpstreamOIDC.Username
		expectedGroups := env.SupervisorUpstreamOIDC.ExpectedGroups

		// Create a ClusterRoleBinding to give our test user from the upstream read-only access to the cluster.
		testlib.CreateTestClusterRoleBinding(t,
			rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: expectedUsername},
			rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "view"},
		)
		testlib.WaitForUserToHaveAccess(t, expectedUsername, []string{}, &authorizationv1.ResourceAttributes{
			Verb:     "get",
			Group:    "",
			Version:  "v1",
			Resource: "namespaces",
		})

		var additionalScopes []string
		// To ensure that access token refresh happens rather than refresh token, don't ask for the offline_access scope.
		for _, additionalScope := range env.SupervisorUpstreamOIDC.AdditionalScopes {
			if additionalScope != "offline_access" {
				additionalScopes = append(additionalScopes, additionalScope)
			}
		}

		// in this test, use a configmap to source ca bundle for the JWT authenticator
		caConfigMap := testlib.CreateTestConfigMap(t, env.ConciergeNamespace, "ca-cert",
			map[string]string{
				"ca.crt": string(federationDomainCABundlePEM),
			})
		jwtAuthnSpec := defaultJWTAuthenticatorSpec.DeepCopy()
		jwtAuthnSpec.TLS.CertificateAuthorityData = ""
		jwtAuthnSpec.TLS.CertificateAuthorityDataSource = &authenticationv1alpha1.CertificateAuthorityDataSourceSpec{
			Kind: "ConfigMap",
			Name: caConfigMap.Name,
			Key:  "ca.crt",
		}
		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, *jwtAuthnSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)

		// Create upstream OIDC provider and wait for it to become ready.
		createdProvider := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
			Issuer: env.SupervisorUpstreamOIDC.Issuer,
			TLS: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
			},
			AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
				AdditionalScopes: additionalScopes,
			},
			Claims: idpv1alpha1.OIDCClaims{
				Username: env.SupervisorUpstreamOIDC.UsernameClaim,
				Groups:   env.SupervisorUpstreamOIDC.GroupsClaim,
			},
			Client: idpv1alpha1.OIDCClient{
				SecretName: testlib.CreateOIDCClientCredentialsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
			},
		}, idpv1alpha1.PhaseReady)
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-skip-listen",
			"--oidc-ca-bundle", federationDomainCABundlePath,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// Run "kubectl get namespaces" which should trigger a browser login via the plugin.
		start := time.Now()
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())
		var kubectlStdoutPipe io.ReadCloser
		if runtime.GOOS != "darwin" {
			// For some unknown reason this breaks the pty library on some macOS machines.
			// The problem doesn't reproduce for everyone, so this is just a workaround.
			var err error
			kubectlStdoutPipe, err = kubectlCmd.StdoutPipe()
			require.NoError(t, err)
		}
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Wait for the subprocess to print the login prompt.
		t.Logf("waiting for CLI to output login URL and manual prompt")
		output := readFromFileUntilStringIsSeen(t, ptyFile, "Optionally, paste your authorization code: ")
		require.Contains(t, output, "Log in by visiting this link:")
		require.Contains(t, output, "Optionally, paste your authorization code: ")

		// Find the line with the login URL.
		var loginURL string
		for _, line := range strings.Split(output, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "https://") {
				loginURL = trimmed
			}
		}
		require.NotEmptyf(t, loginURL, "didn't find login URL in output: %s", output)

		t.Logf("navigating to login page")
		browser.Navigate(t, loginURL)

		// Expect to be redirected to the upstream provider and log in.
		browsertest.LoginToUpstreamOIDC(t, browser, env.SupervisorUpstreamOIDC)

		// Expect to be redirected to the downstream callback which is serving the form_post HTML.
		t.Logf("waiting for response page %s", federationDomain.Spec.Issuer)
		browser.WaitForURL(t, regexp.MustCompile(regexp.QuoteMeta(federationDomain.Spec.Issuer)))

		// The response page should have failed to automatically post, and should now be showing the manual instructions.
		authCode := formpostExpectManualState(t, browser)

		// Enter the auth code in the waiting prompt, followed by a newline.
		t.Logf("'manually' pasting authorization code with length %d to waiting prompt", len(authCode))
		_, err = ptyFile.WriteString(authCode + "\n")
		require.NoError(t, err)

		// Read all the remaining output from the subprocess until EOF.
		t.Logf("waiting for kubectl to output namespace list")
		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlPtyOutputBytes, _ := io.ReadAll(ptyFile)
		if kubectlStdoutPipe != nil {
			// On non-MacOS check that stdout of the CLI contains the expected output.
			kubectlStdOutOutputBytes, _ := io.ReadAll(kubectlStdoutPipe)
			requireKubectlGetNamespaceOutput(t, env, string(kubectlStdOutOutputBytes))
		} else {
			// On macOS check that the pty (stdout+stderr+stdin) of the CLI contains the expected output.
			requireKubectlGetNamespaceOutput(t, env, string(kubectlPtyOutputBytes))
		}
		// Due to the GOOS check in the code above, on macOS the pty will include stdout, and other platforms it will not.
		// This warning message is supposed to be printed by the CLI on stderr.
		require.Contains(t, string(kubectlPtyOutputBytes),
			"Access token from identity provider has lifetime of less than 3 hours. Expect frequent prompts to log in.")

		t.Logf("first kubectl command took %s", time.Since(start).String())

		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, createdProvider.Name, kubeconfigPath,
			sessionCachePath, pinnipedExe, expectedUsername, expectedGroups, allScopes)
	})

	t.Run("with Supervisor OIDC upstream IDP and CLI password flow without web browser", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		expectedUsername := env.SupervisorUpstreamOIDC.Username
		expectedGroups := env.SupervisorUpstreamOIDC.ExpectedGroups

		// Create a ClusterRoleBinding to give our test user from the upstream read-only access to the cluster.
		testlib.CreateTestClusterRoleBinding(t,
			rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: expectedUsername},
			rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "view"},
		)
		testlib.WaitForUserToHaveAccess(t, expectedUsername, []string{}, &authorizationv1.ResourceAttributes{
			Verb:     "get",
			Group:    "",
			Version:  "v1",
			Resource: "namespaces",
		})

		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, defaultJWTAuthenticatorSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)
		// Create upstream OIDC provider and wait for it to become ready.
		createdProvider := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
			Issuer: env.SupervisorUpstreamOIDC.Issuer,
			TLS: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
			},
			AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
				AdditionalScopes:   env.SupervisorUpstreamOIDC.AdditionalScopes,
				AllowPasswordGrant: true, // allow the CLI password flow for this OIDCIdentityProvider
			},
			Claims: idpv1alpha1.OIDCClaims{
				Username: env.SupervisorUpstreamOIDC.UsernameClaim,
				Groups:   env.SupervisorUpstreamOIDC.GroupsClaim,
			},
			Client: idpv1alpha1.OIDCClient{
				SecretName: testlib.CreateOIDCClientCredentialsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
			},
		}, idpv1alpha1.PhaseReady)
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-skip-listen",
			"--upstream-identity-provider-flow", "cli_password", // create a kubeconfig configured to use the cli_password flow
			"--oidc-ca-bundle", federationDomainCABundlePath,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// Run "kubectl get namespaces" which should trigger a browser-less CLI prompt login via the plugin.
		start := time.Now()
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Wait for the subprocess to print the username prompt, then type the user's username.
		readFromFileUntilStringIsSeen(t, ptyFile, "Username: ")
		_, err = ptyFile.WriteString(expectedUsername + "\n")
		require.NoError(t, err)

		// Wait for the subprocess to print the password prompt, then type the user's password.
		readFromFileUntilStringIsSeen(t, ptyFile, "Password: ")
		_, err = ptyFile.WriteString(env.SupervisorUpstreamOIDC.Password + "\n")
		require.NoError(t, err)

		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlOutputBytes, _ := io.ReadAll(ptyFile)
		requireKubectlGetNamespaceOutput(t, env, string(kubectlOutputBytes))

		t.Logf("first kubectl command took %s", time.Since(start).String())

		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, createdProvider.Name, kubeconfigPath,
			sessionCachePath, pinnipedExe, expectedUsername, expectedGroups, allScopes)
	})

	t.Run("with Supervisor OIDC upstream IDP and CLI password flow when OIDCIdentityProvider disallows it", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, defaultJWTAuthenticatorSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)
		// Create upstream OIDC provider and wait for it to become ready.
		oidcIdentityProvider := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
			Issuer: env.SupervisorUpstreamOIDC.Issuer,
			TLS: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
			},
			AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
				AdditionalScopes:   env.SupervisorUpstreamOIDC.AdditionalScopes,
				AllowPasswordGrant: false, // disallow the CLI password flow for this OIDCIdentityProvider!
			},
			Claims: idpv1alpha1.OIDCClaims{
				Username: env.SupervisorUpstreamOIDC.UsernameClaim,
				Groups:   env.SupervisorUpstreamOIDC.GroupsClaim,
			},
			Client: idpv1alpha1.OIDCClient{
				SecretName: testlib.CreateOIDCClientCredentialsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
			},
		}, idpv1alpha1.PhaseReady)
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-skip-listen",
			// Create a kubeconfig configured to use the cli_password flow. By specifying all
			// available --upstream-identity-provider-* options the CLI should skip IDP discovery
			// and use the provided values without validating them. "cli_password" will not show
			// up in the list of available flows for this IDP in the discovery response.
			"--upstream-identity-provider-name", oidcIdentityProvider.Name,
			"--upstream-identity-provider-type", "oidc",
			"--upstream-identity-provider-flow", "cli_password",
			"--oidc-ca-bundle", federationDomainCABundlePath,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// Run "kubectl get --raw /healthz" which should trigger a browser-less CLI prompt login via the plugin.
		// Avoid using something like "kubectl get namespaces" for this test because we expect the auth to fail,
		// and kubectl might call the credential exec plugin a second time to try to auth again if it needs to do API
		// discovery, in which case this test would hang until the kubectl subprocess is killed because the process
		// would be stuck waiting for input on the second username prompt. "kubectl get --raw /healthz" doesn't need
		// to do API discovery, so we know it will only call the credential exec plugin once.
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "--raw", "/healthz", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlOutputBytes, _ := io.ReadAll(ptyFile)
		kubectlOutput := string(kubectlOutputBytes)

		// The output should fail IDP discovery validation, because the OIDCIdentityProvider disallows password grants.
		t.Log("kubectl command output (expecting a login failed error):\n", kubectlOutput)
		require.Contains(t, kubectlOutput,
			fmt.Sprintf(`could not complete Pinniped login: unable to find upstream identity provider with name "%[1]s" and type "oidc" and flow "cli_password". Found these providers: [{"name":"%[1]s","type":"oidc","flows":["browser_authcode"]}]`, oidcIdentityProvider.Name),
		)
	})

	// Add an LDAP upstream IDP and try using it to authenticate during kubectl commands
	// by interacting with the CLI's username and password prompts.
	t.Run("with Supervisor LDAP upstream IDP using username and password prompts", func(t *testing.T) {
		testlib.SkipTestWhenLDAPIsUnavailable(t, env)

		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		expectedUsername := env.SupervisorUpstreamLDAP.TestUserMailAttributeValue
		expectedGroups := env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs

		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, defaultJWTAuthenticatorSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)
		createdProvider := setupClusterForEndToEndLDAPTest(t, expectedUsername, env)
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// Run "kubectl get namespaces" which should trigger an LDAP-style login CLI prompt via the plugin.
		start := time.Now()
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Wait for the subprocess to print the username prompt, then type the user's username.
		readFromFileUntilStringIsSeen(t, ptyFile, "Username: ")
		_, err = ptyFile.WriteString(expectedUsername + "\n")
		require.NoError(t, err)

		// Wait for the subprocess to print the password prompt, then type the user's password.
		readFromFileUntilStringIsSeen(t, ptyFile, "Password: ")
		_, err = ptyFile.WriteString(env.SupervisorUpstreamLDAP.TestUserPassword + "\n")
		require.NoError(t, err)

		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlOutputBytes, _ := io.ReadAll(ptyFile)
		requireKubectlGetNamespaceOutput(t, env, string(kubectlOutputBytes))

		t.Logf("first kubectl command took %s", time.Since(start).String())

		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, createdProvider.Name, kubeconfigPath,
			sessionCachePath, pinnipedExe, expectedUsername, expectedGroups, allScopes)
	})

	// If the username and groups scope are not requested by the CLI, then the CLI still gets them, to allow for
	// backwards compatibility with old CLIs that did not request those scopes because they did not exist yet.
	t.Run("with Supervisor LDAP upstream IDP using username and password prompts, downstream username and groups scopes not requested", func(t *testing.T) {
		testlib.SkipTestWhenLDAPIsUnavailable(t, env)

		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		expectedUsername := env.SupervisorUpstreamLDAP.TestUserMailAttributeValue
		expectedGroups := env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs

		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, defaultJWTAuthenticatorSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)
		createdProvider := setupClusterForEndToEndLDAPTest(t, expectedUsername, env)
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			"--oidc-scopes", "offline_access,openid,pinniped:request-audience", // does not request username or groups
		})

		// Run "kubectl get namespaces" which should trigger an LDAP-style login CLI prompt via the plugin.
		start := time.Now()
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Wait for the subprocess to print the username prompt, then type the user's username.
		readFromFileUntilStringIsSeen(t, ptyFile, "Username: ")
		_, err = ptyFile.WriteString(expectedUsername + "\n")
		require.NoError(t, err)

		// Wait for the subprocess to print the password prompt, then type the user's password.
		readFromFileUntilStringIsSeen(t, ptyFile, "Password: ")
		_, err = ptyFile.WriteString(env.SupervisorUpstreamLDAP.TestUserPassword + "\n")
		require.NoError(t, err)

		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlOutputBytes, _ := io.ReadAll(ptyFile)
		requireKubectlGetNamespaceOutput(t, env, string(kubectlOutputBytes))

		t.Logf("first kubectl command took %s", time.Since(start).String())

		// Note that the list of scopes param here is used to form the cache key for looking up local session storage.
		// The scopes portion of the cache key is made up of the requested scopes from the CLI flag, not the granted
		// scopes returned by the Supervisor, so list the requested scopes from the CLI flag here. This helper will
		// assert that the expected username and groups claims/values are in the downstream ID token.
		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, createdProvider.Name, kubeconfigPath,
			sessionCachePath, pinnipedExe, expectedUsername, expectedGroups, []string{"offline_access", "openid", "pinniped:request-audience"})
	})

	// Add an LDAP upstream IDP and try using it to authenticate during kubectl commands
	// by passing username and password via environment variables, thus avoiding the CLI's username and password prompts.
	t.Run("with Supervisor LDAP upstream IDP using PINNIPED_USERNAME and PINNIPED_PASSWORD env vars", func(t *testing.T) {
		testlib.SkipTestWhenLDAPIsUnavailable(t, env)

		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		expectedUsername := env.SupervisorUpstreamLDAP.TestUserMailAttributeValue
		expectedGroups := env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs

		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, defaultJWTAuthenticatorSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)
		createdProvider := setupClusterForEndToEndLDAPTest(t, expectedUsername, env)
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// Set up the username and password env vars to avoid the interactive prompts.
		const usernameEnvVar = "PINNIPED_USERNAME"
		originalUsername, hadOriginalUsername := os.LookupEnv(usernameEnvVar)
		t.Cleanup(func() {
			if hadOriginalUsername {
				require.NoError(t, os.Setenv(usernameEnvVar, originalUsername))
			}
		})
		require.NoError(t, os.Setenv(usernameEnvVar, expectedUsername))
		const passwordEnvVar = "PINNIPED_PASSWORD" //nolint:gosec // this is not a credential
		originalPassword, hadOriginalPassword := os.LookupEnv(passwordEnvVar)
		t.Cleanup(func() {
			if hadOriginalPassword {
				require.NoError(t, os.Setenv(passwordEnvVar, originalPassword))
			}
		})
		require.NoError(t, os.Setenv(passwordEnvVar, env.SupervisorUpstreamLDAP.TestUserPassword))

		// Run "kubectl get namespaces" which should run an LDAP-style login without interactive prompts for username and password.
		start := time.Now()
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlOutputBytes, _ := io.ReadAll(ptyFile)
		requireKubectlGetNamespaceOutput(t, env, string(kubectlOutputBytes))

		t.Logf("first kubectl command took %s", time.Since(start).String())

		// The next kubectl command should not require auth, so we should be able to run it without these env vars.
		require.NoError(t, os.Unsetenv(usernameEnvVar))
		require.NoError(t, os.Unsetenv(passwordEnvVar))

		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, createdProvider.Name, kubeconfigPath,
			sessionCachePath, pinnipedExe, expectedUsername, expectedGroups, allScopes)
	})

	// Add an Active Directory upstream IDP and try using it to authenticate during kubectl commands
	// by interacting with the CLI's username and password prompts.
	t.Run("with Supervisor ActiveDirectory upstream IDP using username and password prompts", func(t *testing.T) {
		testlib.SkipTestWhenActiveDirectoryIsUnavailable(t, env)

		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		expectedUsername := env.SupervisorUpstreamActiveDirectory.TestUserPrincipalNameValue
		expectedGroups := env.SupervisorUpstreamActiveDirectory.TestUserIndirectGroupsSAMAccountPlusDomainNames

		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, defaultJWTAuthenticatorSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)
		createdProvider := setupClusterForEndToEndActiveDirectoryTest(t, expectedUsername, env)
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// Run "kubectl get namespaces" which should trigger an LDAP-style login CLI prompt via the plugin.
		start := time.Now()
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Wait for the subprocess to print the username prompt, then type the user's username.
		readFromFileUntilStringIsSeen(t, ptyFile, "Username: ")
		_, err = ptyFile.WriteString(expectedUsername + "\n")
		require.NoError(t, err)

		// Wait for the subprocess to print the password prompt, then type the user's password.
		readFromFileUntilStringIsSeen(t, ptyFile, "Password: ")
		_, err = ptyFile.WriteString(env.SupervisorUpstreamActiveDirectory.TestUserPassword + "\n")
		require.NoError(t, err)

		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlOutputBytes, _ := io.ReadAll(ptyFile)
		requireKubectlGetNamespaceOutput(t, env, string(kubectlOutputBytes))

		t.Logf("first kubectl command took %s", time.Since(start).String())

		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, createdProvider.Name, kubeconfigPath,
			sessionCachePath, pinnipedExe, expectedUsername, expectedGroups, allScopes)
	})

	// Add an ActiveDirectory upstream IDP and try using it to authenticate during kubectl commands
	// by passing username and password via environment variables, thus avoiding the CLI's username and password prompts.
	t.Run("with Supervisor ActiveDirectory upstream IDP using PINNIPED_USERNAME and PINNIPED_PASSWORD env vars", func(t *testing.T) {
		testlib.SkipTestWhenActiveDirectoryIsUnavailable(t, env)

		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		expectedUsername := env.SupervisorUpstreamActiveDirectory.TestUserPrincipalNameValue
		expectedGroups := env.SupervisorUpstreamActiveDirectory.TestUserIndirectGroupsSAMAccountPlusDomainNames

		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, defaultJWTAuthenticatorSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)
		createdProvider := setupClusterForEndToEndActiveDirectoryTest(t, expectedUsername, env)
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// Set up the username and password env vars to avoid the interactive prompts.
		const usernameEnvVar = "PINNIPED_USERNAME"
		originalUsername, hadOriginalUsername := os.LookupEnv(usernameEnvVar)
		t.Cleanup(func() {
			if hadOriginalUsername {
				require.NoError(t, os.Setenv(usernameEnvVar, originalUsername))
			}
		})
		require.NoError(t, os.Setenv(usernameEnvVar, expectedUsername))
		const passwordEnvVar = "PINNIPED_PASSWORD" //nolint:gosec // this is not a credential
		originalPassword, hadOriginalPassword := os.LookupEnv(passwordEnvVar)
		t.Cleanup(func() {
			if hadOriginalPassword {
				require.NoError(t, os.Setenv(passwordEnvVar, originalPassword))
			}
		})
		require.NoError(t, os.Setenv(passwordEnvVar, env.SupervisorUpstreamActiveDirectory.TestUserPassword))

		// Run "kubectl get namespaces" which should run an LDAP-style login without interactive prompts for username and password.
		start := time.Now()
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlOutputBytes, _ := io.ReadAll(ptyFile)
		requireKubectlGetNamespaceOutput(t, env, string(kubectlOutputBytes))

		t.Logf("first kubectl command took %s", time.Since(start).String())

		// The next kubectl command should not require auth, so we should be able to run it without these env vars.
		require.NoError(t, os.Unsetenv(usernameEnvVar))
		require.NoError(t, os.Unsetenv(passwordEnvVar))

		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, createdProvider.Name, kubeconfigPath,
			sessionCachePath, pinnipedExe, expectedUsername, expectedGroups, allScopes)
	})

	// Add an LDAP upstream IDP and try using it to authenticate during kubectl commands, using the browser flow.
	t.Run("with Supervisor LDAP upstream IDP and browser flow with with form_post automatic authcode delivery to CLI", func(t *testing.T) {
		testlib.SkipTestWhenLDAPIsUnavailable(t, env)

		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		// Start a fresh browser driver because we don't want to share cookies between the various tests in this file.
		browser := browsertest.OpenBrowser(t)

		expectedUsername := env.SupervisorUpstreamLDAP.TestUserMailAttributeValue
		expectedGroups := env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs

		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, defaultJWTAuthenticatorSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)
		createdProvider := setupClusterForEndToEndLDAPTest(t, expectedUsername, env)
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-ca-bundle", federationDomainCABundlePath,
			"--upstream-identity-provider-flow", "browser_authcode",
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// Run "kubectl get namespaces" which should trigger a browser login via the plugin.
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath, "-v", "6")
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())

		// Run the kubectl command, wait for the Pinniped CLI to print the authorization URL, and open it in the browser.
		kubectlOutputChan := startKubectlAndOpenAuthorizationURLInBrowser(testCtx, t, kubectlCmd, browser)

		// Confirm that we got to the Supervisor's login page, fill out the form, and submit the form.
		browsertest.LoginToUpstreamLDAP(t, browser, federationDomain.Spec.Issuer,
			expectedUsername, env.SupervisorUpstreamLDAP.TestUserPassword)

		formpostExpectSuccessState(t, browser)

		requireKubectlGetNamespaceOutput(t, env, waitForKubectlOutput(t, kubectlOutputChan))

		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, createdProvider.Name, kubeconfigPath,
			sessionCachePath, pinnipedExe, expectedUsername, expectedGroups, allScopes)
	})

	// Add an Active Directory upstream IDP and try using it to authenticate during kubectl commands, using the browser flow.
	t.Run("with Supervisor Active Directory upstream IDP and browser flow with with form_post automatic authcode delivery to CLI", func(t *testing.T) {
		testlib.SkipTestWhenActiveDirectoryIsUnavailable(t, env)

		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		// Start a fresh browser driver because we don't want to share cookies between the various tests in this file.
		browser := browsertest.OpenBrowser(t)

		expectedUsername := env.SupervisorUpstreamActiveDirectory.TestUserPrincipalNameValue
		expectedGroups := env.SupervisorUpstreamActiveDirectory.TestUserIndirectGroupsSAMAccountPlusDomainNames

		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, defaultJWTAuthenticatorSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)
		createdProvider := setupClusterForEndToEndActiveDirectoryTest(t, expectedUsername, env)
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-ca-bundle", federationDomainCABundlePath,
			"--upstream-identity-provider-flow", "browser_authcode",
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// Run "kubectl get namespaces" which should trigger a browser login via the plugin.
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath, "-v", "6")
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())

		// Run the kubectl command, wait for the Pinniped CLI to print the authorization URL, and open it in the browser.
		kubectlOutputChan := startKubectlAndOpenAuthorizationURLInBrowser(testCtx, t, kubectlCmd, browser)

		// Confirm that we got to the Supervisor's login page, fill out the form, and submit the form.
		browsertest.LoginToUpstreamLDAP(t, browser, federationDomain.Spec.Issuer,
			expectedUsername, env.SupervisorUpstreamActiveDirectory.TestUserPassword)

		formpostExpectSuccessState(t, browser)

		requireKubectlGetNamespaceOutput(t, env, waitForKubectlOutput(t, kubectlOutputChan))

		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, createdProvider.Name, kubeconfigPath,
			sessionCachePath, pinnipedExe, expectedUsername, expectedGroups, allScopes)
	})

	// Add an LDAP upstream IDP and try using it to authenticate during kubectl commands, using the env var to choose the browser flow.
	t.Run("with Supervisor LDAP upstream IDP and browser flow selected by env var override with with form_post automatic authcode delivery to CLI", func(t *testing.T) {
		testlib.SkipTestWhenLDAPIsUnavailable(t, env)

		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		// Start a fresh browser driver because we don't want to share cookies between the various tests in this file.
		browser := browsertest.OpenBrowser(t)

		expectedUsername := env.SupervisorUpstreamLDAP.TestUserMailAttributeValue
		expectedGroups := env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs

		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, defaultJWTAuthenticatorSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)
		createdProvider := setupClusterForEndToEndLDAPTest(t, expectedUsername, env)
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-ca-bundle", federationDomainCABundlePath,
			"--upstream-identity-provider-flow", "cli_password", // put cli_password in the kubeconfig, so we can override it with the env var
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// Override the --upstream-identity-provider-flow flag from the kubeconfig using the env var.
		require.NoError(t, os.Setenv("PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW", "browser_authcode"))
		t.Cleanup(func() {
			require.NoError(t, os.Unsetenv("PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW"))
		})

		// Run "kubectl get namespaces" which should trigger a browser login via the plugin.
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath, "-v", "6")
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())

		// Run the kubectl command, wait for the Pinniped CLI to print the authorization URL, and open it in the browser.
		kubectlOutputChan := startKubectlAndOpenAuthorizationURLInBrowser(testCtx, t, kubectlCmd, browser)

		// Confirm that we got to the Supervisor's login page, fill out the form, and submit the form.
		browsertest.LoginToUpstreamLDAP(t, browser, federationDomain.Spec.Issuer,
			expectedUsername, env.SupervisorUpstreamLDAP.TestUserPassword)

		formpostExpectSuccessState(t, browser)

		requireKubectlGetNamespaceOutput(t, env, waitForKubectlOutput(t, kubectlOutputChan))

		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, createdProvider.Name, kubeconfigPath,
			sessionCachePath, pinnipedExe, expectedUsername, expectedGroups, allScopes)
	})

	t.Run("with Supervisor GitHub upstream IDP and browser flow with with form_post automatic authcode delivery to CLI", func(t *testing.T) {
		testlib.SkipTestWhenGitHubIsUnavailable(t)

		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		// Start a fresh browser driver because we don't want to share cookies between the various tests in this file.
		browser := browsertest.OpenBrowser(t)

		expectedUsername := env.SupervisorUpstreamGithub.TestUserUsername + ":" + env.SupervisorUpstreamGithub.TestUserID
		expectedGroups := env.SupervisorUpstreamGithub.TestUserExpectedTeamSlugs

		// Create a ClusterRoleBinding to give our test user from the upstream read-only access to the cluster.
		testlib.CreateTestClusterRoleBinding(t,
			rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: expectedUsername},
			rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "view"},
		)
		testlib.WaitForUserToHaveAccess(t, expectedUsername, []string{}, &authorizationv1.ResourceAttributes{
			Verb:     "get",
			Group:    "",
			Version:  "v1",
			Resource: "namespaces",
		})

		// Create upstream GitHub provider and wait for it to become ready.
		createdProvider := testlib.CreateTestGitHubIdentityProvider(t, idpv1alpha1.GitHubIdentityProviderSpec{
			AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
				Organizations: idpv1alpha1.GitHubOrganizationsSpec{
					Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
				},
			},
			Claims: idpv1alpha1.GitHubClaims{
				Username: ptr.To(idpv1alpha1.GitHubUsernameLoginAndID),
				Groups:   ptr.To(idpv1alpha1.GitHubUseTeamSlugForGroupName),
			},
			Client: idpv1alpha1.GitHubClientSpec{
				SecretName: testlib.CreateGitHubClientCredentialsSecret(t,
					env.SupervisorUpstreamGithub.GithubAppClientID,
					env.SupervisorUpstreamGithub.GithubAppClientSecret,
				).Name,
			},
		}, idpv1alpha1.GitHubPhaseReady)
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, defaultJWTAuthenticatorSpec, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-ca-bundle", federationDomainCABundlePath,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// Run "kubectl get namespaces" which should trigger a browser login via the plugin.
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath, "-v", "6")
		kubectlCmd.Env = append(os.Environ(), env.ProxyEnv()...)

		// Run the kubectl command, wait for the Pinniped CLI to print the authorization URL, and open it in the browser.
		kubectlOutputChan := startKubectlAndOpenAuthorizationURLInBrowser(testCtx, t, kubectlCmd, browser)

		// Confirm that we got to the upstream IDP's login page, fill out the form, and submit the form.
		browsertest.LoginToUpstreamGitHub(t, browser, env.SupervisorUpstreamGithub)

		// Expect to be redirected to the downstream callback which is serving the form_post HTML.
		t.Logf("waiting for response page %s", federationDomain.Spec.Issuer)
		browser.WaitForURL(t, regexp.MustCompile(regexp.QuoteMeta(federationDomain.Spec.Issuer)))

		// The response page should have done the background fetch() and POST'ed to the CLI's callback.
		// It should now be in the "success" state.
		formpostExpectSuccessState(t, browser)

		requireKubectlGetNamespaceOutput(t, env, waitForKubectlOutput(t, kubectlOutputChan))

		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, createdProvider.Name, kubeconfigPath,
			sessionCachePath, pinnipedExe, expectedUsername, expectedGroups, allScopes)
	})

	t.Run("with multiple IDPs: one OIDC and one LDAP", func(t *testing.T) {
		testlib.SkipTestWhenLDAPIsUnavailable(t, env)

		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		// Start a fresh browser driver because we don't want to share cookies between the various tests in this file.
		browser := browsertest.OpenBrowser(t)

		downstreamPrefix := "pre:"

		expectedUpstreamLDAPUsername := env.SupervisorUpstreamLDAP.TestUserMailAttributeValue
		expectedDownstreamLDAPUsername := downstreamPrefix + expectedUpstreamLDAPUsername
		expectedUpstreamLDAPGroups := env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs
		expectedDownstreamLDAPGroups := make([]string, 0, len(expectedUpstreamLDAPGroups))
		for _, g := range expectedUpstreamLDAPGroups {
			expectedDownstreamLDAPGroups = append(expectedDownstreamLDAPGroups, downstreamPrefix+g)
		}

		expectedUpstreamOIDCUsername := env.SupervisorUpstreamOIDC.Username
		expectedDownstreamOIDCUsername := downstreamPrefix + expectedUpstreamOIDCUsername
		expectedUpstreamOIDCGroups := env.SupervisorUpstreamOIDC.ExpectedGroups
		expectedDownstreamOIDCGroups := make([]string, 0, len(expectedUpstreamOIDCGroups))
		for _, g := range expectedUpstreamOIDCGroups {
			expectedDownstreamOIDCGroups = append(expectedDownstreamOIDCGroups, downstreamPrefix+g)
		}

		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, defaultJWTAuthenticatorSpec, authenticationv1alpha1.JWTAuthenticatorPhaseError)
		createdLDAPProvider := setupClusterForEndToEndLDAPTest(t, expectedDownstreamLDAPUsername, env)
		// Having one IDP should put the FederationDomain into a ready state.
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Create a ClusterRoleBinding to give our test user from the upstream read-only access to the cluster.
		testlib.CreateTestClusterRoleBinding(t,
			rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: expectedDownstreamOIDCUsername},
			rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "view"},
		)
		testlib.WaitForUserToHaveAccess(t, expectedDownstreamOIDCUsername, []string{}, &authorizationv1.ResourceAttributes{
			Verb:     "get",
			Group:    "",
			Version:  "v1",
			Resource: "namespaces",
		})

		// Create upstream OIDC provider and wait for it to become ready.
		createdOIDCProvider := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
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

		// Having a second IDP should put the FederationDomain back into an error state until we tell it which one to use.
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseError)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Update the FederationDomain to use the two IDPs.
		federationDomainsClient := supervisorClient.ConfigV1alpha1().FederationDomains(env.SupervisorNamespace)
		gotFederationDomain, err := federationDomainsClient.Get(testCtx, federationDomain.Name, metav1.GetOptions{})
		require.NoError(t, err)

		t.Cleanup(func() {
			removeFederationDomainIdentityProviders(t, federationDomainsClient, federationDomain.Name)
		})

		ldapIDPDisplayName := "My LDAP IDP 💾"
		oidcIDPDisplayName := "My OIDC IDP 🚀"

		gotFederationDomain.Spec.IdentityProviders = []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
			{
				DisplayName: ldapIDPDisplayName,
				ObjectRef: corev1.TypedLocalObjectReference{
					APIGroup: ptr.To("idp.supervisor." + env.APIGroupSuffix),
					Kind:     "LDAPIdentityProvider",
					Name:     createdLDAPProvider.Name,
				},
				Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{
					Constants: []supervisorconfigv1alpha1.FederationDomainTransformsConstant{
						{Name: "allowedUser", Type: "string", StringValue: expectedUpstreamLDAPUsername},
						{Name: "allowedUsers", Type: "stringList", StringListValue: []string{"someone else", expectedUpstreamLDAPUsername, "someone else"}},
					},
					Expressions: []supervisorconfigv1alpha1.FederationDomainTransformsExpression{
						{Type: "policy/v1", Expression: `username == strConst.allowedUser && username in strListConst.allowedUsers`, Message: "only special users allowed"},
						{Type: "username/v1", Expression: fmt.Sprintf(`"%s" + username`, downstreamPrefix)},
						{Type: "groups/v1", Expression: fmt.Sprintf(`groups.map(g, "%s" + g)`, downstreamPrefix)},
					},
					Examples: []supervisorconfigv1alpha1.FederationDomainTransformsExample{
						{
							Username: expectedUpstreamLDAPUsername,
							Groups:   []string{"a", "b"},
							Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
								Username: expectedDownstreamLDAPUsername,
								Groups:   []string{downstreamPrefix + "a", downstreamPrefix + "b"},
							},
						},
						{
							Username: "someone other user",
							Groups:   []string{"a", "b"},
							Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
								Rejected: true,
								Message:  "only special users allowed",
							},
						},
					},
				},
			},
			{
				DisplayName: oidcIDPDisplayName,
				ObjectRef: corev1.TypedLocalObjectReference{
					APIGroup: ptr.To("idp.supervisor." + env.APIGroupSuffix),
					Kind:     "OIDCIdentityProvider",
					Name:     createdOIDCProvider.Name,
				},
				Transforms: supervisorconfigv1alpha1.FederationDomainTransforms{
					Constants: []supervisorconfigv1alpha1.FederationDomainTransformsConstant{
						{Name: "allowedUser", Type: "string", StringValue: expectedUpstreamOIDCUsername},
						{Name: "allowedUsers", Type: "stringList", StringListValue: []string{"someone else", expectedUpstreamOIDCUsername, "someone else"}},
					},
					Expressions: []supervisorconfigv1alpha1.FederationDomainTransformsExpression{
						{Type: "policy/v1", Expression: `username == strConst.allowedUser && username in strListConst.allowedUsers`, Message: "only special users allowed"},
						{Type: "username/v1", Expression: fmt.Sprintf(`"%s" + username`, downstreamPrefix)},
						{Type: "groups/v1", Expression: fmt.Sprintf(`groups.map(g, "%s" + g)`, downstreamPrefix)},
					},
					Examples: []supervisorconfigv1alpha1.FederationDomainTransformsExample{
						{
							Username: expectedUpstreamOIDCUsername,
							Groups:   []string{"a", "b"},
							Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
								Username: expectedDownstreamOIDCUsername,
								Groups:   []string{downstreamPrefix + "a", downstreamPrefix + "b"},
							},
						},
						{
							Username: "someone other user",
							Groups:   []string{"a", "b"},
							Expects: supervisorconfigv1alpha1.FederationDomainTransformsExampleExpects{
								Rejected: true,
								Message:  "only special users allowed",
							},
						},
					},
				},
			},
		}
		_, err = federationDomainsClient.Update(testCtx, gotFederationDomain, metav1.UpdateOptions{})
		require.NoError(t, err)

		// The FederationDomain should be valid after the above update.
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		ldapKubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			"--upstream-identity-provider-name", ldapIDPDisplayName,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		oidcKubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			"--upstream-identity-provider-name", oidcIDPDisplayName,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// Run "kubectl get namespaces" which should trigger an LDAP-style login CLI prompt via the plugin for the LDAP IDP.
		t.Log("starting LDAP auth via kubectl")
		start := time.Now()
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", ldapKubeconfigPath)
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Wait for the subprocess to print the username prompt, then type the user's username.
		readFromFileUntilStringIsSeen(t, ptyFile, "Username: ")
		_, err = ptyFile.WriteString(expectedUpstreamLDAPUsername + "\n")
		require.NoError(t, err)

		// Wait for the subprocess to print the password prompt, then type the user's password.
		readFromFileUntilStringIsSeen(t, ptyFile, "Password: ")
		_, err = ptyFile.WriteString(env.SupervisorUpstreamLDAP.TestUserPassword + "\n")
		require.NoError(t, err)

		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlOutputBytes, _ := io.ReadAll(ptyFile)
		requireKubectlGetNamespaceOutput(t, env, string(kubectlOutputBytes))

		t.Logf("first kubectl command took %s", time.Since(start).String())

		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, ldapIDPDisplayName, ldapKubeconfigPath,
			sessionCachePath, pinnipedExe, expectedDownstreamLDAPUsername, expectedDownstreamLDAPGroups, allScopes)

		// Run "kubectl get namespaces" which should trigger a browser login via the plugin for the OIDC IDP.
		t.Log("starting OIDC auth via kubectl")
		kubectlCmd = exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", oidcKubeconfigPath, "-v", "6")
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())

		// Run the kubectl command, wait for the Pinniped CLI to print the authorization URL, and open it in the browser.
		kubectlOutputChan := startKubectlAndOpenAuthorizationURLInBrowser(testCtx, t, kubectlCmd, browser)

		// Confirm that we got to the upstream IDP's login page, fill out the form, and submit the form.
		browsertest.LoginToUpstreamOIDC(t, browser, env.SupervisorUpstreamOIDC)

		// Expect to be redirected to the downstream callback which is serving the form_post HTML.
		t.Logf("waiting for response page %s", federationDomain.Spec.Issuer)
		browser.WaitForURL(t, regexp.MustCompile(regexp.QuoteMeta(federationDomain.Spec.Issuer)))

		// The response page should have done the background fetch() and POST'ed to the CLI's callback.
		// It should now be in the "success" state.
		formpostExpectSuccessState(t, browser)

		requireKubectlGetNamespaceOutput(t, env, waitForKubectlOutput(t, kubectlOutputChan))

		// The user is now logged in to the cluster as two different identities simultaneously, and can switch
		// back and forth by switching kubeconfigs, without needing to auth again.
		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, oidcIDPDisplayName, oidcKubeconfigPath,
			sessionCachePath, pinnipedExe, expectedDownstreamOIDCUsername, expectedDownstreamOIDCGroups, allScopes)
		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, ldapIDPDisplayName, ldapKubeconfigPath,
			sessionCachePath, pinnipedExe, expectedDownstreamLDAPUsername, expectedDownstreamLDAPGroups, allScopes)
		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, oidcIDPDisplayName, oidcKubeconfigPath,
			sessionCachePath, pinnipedExe, expectedDownstreamOIDCUsername, expectedDownstreamOIDCGroups, allScopes)

		// Update the policies of both IDPs on the FederationDomain to reject the expected upstream usernames during authentication.
		// Remove the examples since we are changing the transforms.
		_, err = federationDomainsClient.Patch(testCtx, gotFederationDomain.Name, types.JSONPatchType,
			[]byte(here.Doc(
				`[
					{
					  "op": "replace",
					  "path": "/spec/identityProviders/0/transforms/expressions/0",
					  "value": {
						"type": "policy/v1",
						"expression": "username != strConst.allowedUser",
						"message": "only special LDAP users allowed"
					  }
					},
					{
					  "op": "replace",
					  "path": "/spec/identityProviders/1/transforms/expressions/0",
					  "value": {
						"type": "policy/v1",
						"expression": "username != strConst.allowedUser",
						"message": "only special OIDC users allowed"
					  }
					},
					{
					  "op": "remove",
					  "path": "/spec/identityProviders/0/transforms/examples"
					},
					{
					  "op": "remove",
					  "path": "/spec/identityProviders/1/transforms/examples"
					}
				 ]`,
			)),
			metav1.PatchOptions{},
		)
		require.NoError(t, err)

		// Wait for the status conditions to have observed the current spec generation, so we can be sure that the
		// controller has observed our latest update.
		testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
			fd, err := federationDomainsClient.Get(testCtx, federationDomain.Name, metav1.GetOptions{})
			require.NoError(t, err)
			t.Log("saw FederationDomain", fd)
			requireEventually.Equal(fd.Generation, fd.Status.Conditions[0].ObservedGeneration)
		}, 20*time.Second, 250*time.Millisecond)
		// The FederationDomain should be valid after the above update.
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Log out so we can try fresh logins again.
		require.NoError(t, os.Remove(credentialCachePath))
		require.NoError(t, os.Remove(sessionCachePath))

		// Policies don't impact the kubeconfig files, so we can reuse the existing kubeconfig files.
		// Try to log again, and this time expect to be rejected by the configured policies.

		// Run "kubectl get namespaces" which should trigger an LDAP-style login CLI prompt via the plugin for the LDAP IDP.
		t.Log("starting second LDAP auth via kubectl")
		kubectlCmd = exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", ldapKubeconfigPath)
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())
		ptyFile, err = pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Wait for the subprocess to print the username prompt, then type the user's username.
		readFromFileUntilStringIsSeen(t, ptyFile, "Username: ")
		_, err = ptyFile.WriteString(expectedUpstreamLDAPUsername + "\n")
		require.NoError(t, err)

		// Wait for the subprocess to print the password prompt, then type the user's password.
		readFromFileUntilStringIsSeen(t, ptyFile, "Password: ")
		_, err = ptyFile.WriteString(env.SupervisorUpstreamLDAP.TestUserPassword + "\n")
		require.NoError(t, err)

		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlOutputBytes, _ = io.ReadAll(ptyFile)
		t.Log("kubectl command output:\n", string(kubectlOutputBytes))
		require.Contains(t, string(kubectlOutputBytes),
			`Error: could not complete Pinniped login: login failed with code "access_denied": `+
				`The resource owner or authorization server denied the request. `+
				`Reason: configured identity policy rejected this authentication: only special LDAP users allowed.`)
		require.Contains(t, string(kubectlOutputBytes), "pinniped failed with exit code 1")
	})

	t.Run("with OIDC and LDAP, verify that 'pinniped login oidc' will infer the login flow from IDP discovery", func(t *testing.T) {
		testlib.SkipTestWhenLDAPIsUnavailable(t, env)

		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		tempDir := t.TempDir() // per-test tmp dir to avoid sharing files between tests

		// Start a fresh browser driver because we don't want to share cookies between the various tests in this file.
		browser := browsertest.OpenBrowser(t)

		expectedDownstreamLDAPUsername := env.SupervisorUpstreamLDAP.TestUserMailAttributeValue
		expectedDownstreamOIDCUsername := env.SupervisorUpstreamOIDC.Username
		expectedDownstreamLDAPGroups := env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs
		expectedDownstreamOIDCGroups := env.SupervisorUpstreamOIDC.ExpectedGroups

		createdLDAPProvider := setupClusterForEndToEndLDAPTest(t, expectedDownstreamLDAPUsername, env)
		// Having one IDP should put the FederationDomain into a ready state.
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		authenticator := testlib.CreateTestJWTAuthenticator(testCtx, t, defaultJWTAuthenticatorSpec, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Create a ClusterRoleBinding to give our test user from the upstream read-only access to the cluster.
		testlib.CreateTestClusterRoleBinding(t,
			rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: expectedDownstreamOIDCUsername},
			rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "view"},
		)
		testlib.WaitForUserToHaveAccess(t, expectedDownstreamOIDCUsername, []string{}, &authorizationv1.ResourceAttributes{
			Verb:     "get",
			Group:    "",
			Version:  "v1",
			Resource: "namespaces",
		})

		// Create upstream OIDC provider and wait for it to become ready.
		createdOIDCProvider := testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
			Issuer: env.SupervisorUpstreamOIDC.Issuer,
			TLS: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamOIDC.CABundle)),
			},
			AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
				AdditionalScopes:   env.SupervisorUpstreamOIDC.AdditionalScopes,
				AllowPasswordGrant: true, // We specifically want this OIDC to support both 'cli_password' and 'browser_authcode'
			},
			Claims: idpv1alpha1.OIDCClaims{
				Username: env.SupervisorUpstreamOIDC.UsernameClaim,
				Groups:   env.SupervisorUpstreamOIDC.GroupsClaim,
			},
			Client: idpv1alpha1.OIDCClient{
				SecretName: testlib.CreateOIDCClientCredentialsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
			},
		}, idpv1alpha1.PhaseReady)

		// Having a second IDP should put the FederationDomain back into an error state until we tell it which one to use.
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseError)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Update the FederationDomain to use the two IDPs.
		federationDomainsClient := supervisorClient.ConfigV1alpha1().FederationDomains(env.SupervisorNamespace)
		gotFederationDomain, err := federationDomainsClient.Get(testCtx, federationDomain.Name, metav1.GetOptions{})
		require.NoError(t, err)

		t.Cleanup(func() {
			removeFederationDomainIdentityProviders(t, federationDomainsClient, federationDomain.Name)
		})

		ldapIDPDisplayName := "My LDAP IDP 💾"
		oidcIDPDisplayName := "My OIDC IDP 🚀"

		gotFederationDomain.Spec.IdentityProviders = []supervisorconfigv1alpha1.FederationDomainIdentityProvider{
			{
				DisplayName: ldapIDPDisplayName,
				ObjectRef: corev1.TypedLocalObjectReference{
					APIGroup: ptr.To("idp.supervisor." + env.APIGroupSuffix),
					Kind:     "LDAPIdentityProvider",
					Name:     createdLDAPProvider.Name,
				},
			},
			{
				DisplayName: oidcIDPDisplayName,
				ObjectRef: corev1.TypedLocalObjectReference{
					APIGroup: ptr.To("idp.supervisor." + env.APIGroupSuffix),
					Kind:     "OIDCIdentityProvider",
					Name:     createdOIDCProvider.Name,
				},
			},
		}
		_, err = federationDomainsClient.Update(testCtx, gotFederationDomain, metav1.UpdateOptions{})
		require.NoError(t, err)

		// The FederationDomain should be valid after the above update.
		testlib.WaitForFederationDomainStatusPhase(testCtx, t, federationDomain.Name, supervisorconfigv1alpha1.FederationDomainPhaseReady)
		testlib.WaitForJWTAuthenticatorStatusPhase(testCtx, t, authenticator.Name, authenticationv1alpha1.JWTAuthenticatorPhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/test-sessions.yaml"
		credentialCachePath := tempDir + "/test-credentials.yaml"

		// We want to be sure that "pinniped login oidc" will infer "cli_password" when we override the flow type
		// with PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW="". So we'll set this to be the non-default login flow.
		nonDefaultLDAPLoginFlow := "browser_authcode"

		ldapKubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			"--upstream-identity-provider-name", ldapIDPDisplayName,
			"--upstream-identity-provider-flow", nonDefaultLDAPLoginFlow,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// We want to be sure that "pinniped login oidc" will infer "browser_authcode" when we override the flow type
		// with PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW="". So we'll set this to be the non-default login flow.
		nonDefaultOIDCLoginFlow := "cli_password"

		oidcKubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-session-cache", sessionCachePath,
			"--credential-cache", credentialCachePath,
			"--upstream-identity-provider-name", oidcIDPDisplayName,
			"--upstream-identity-provider-flow", nonDefaultOIDCLoginFlow,
			// use default for --oidc-scopes, which is to request all relevant scopes
		})

		// Run "kubectl get namespaces" which should trigger an LDAP-style login CLI prompt via the plugin for the LDAP IDP.
		t.Log("starting LDAP auth via kubectl")
		start := time.Now()
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", ldapKubeconfigPath)
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv(), []string{"PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW="})
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Wait for the subprocess to print the username prompt, then type the user's username.
		readFromFileUntilStringIsSeen(t, ptyFile, "Username: ")
		_, err = ptyFile.WriteString(expectedDownstreamLDAPUsername + "\n")
		require.NoError(t, err)

		// Wait for the subprocess to print the password prompt, then type the user's password.
		readFromFileUntilStringIsSeen(t, ptyFile, "Password: ")
		_, err = ptyFile.WriteString(env.SupervisorUpstreamLDAP.TestUserPassword + "\n")
		require.NoError(t, err)

		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlOutputBytes, _ := io.ReadAll(ptyFile)
		requireKubectlGetNamespaceOutput(t, env, string(kubectlOutputBytes))

		t.Logf("first kubectl command took %s", time.Since(start).String())

		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, ldapIDPDisplayName, ldapKubeconfigPath,
			sessionCachePath, pinnipedExe, expectedDownstreamLDAPUsername, expectedDownstreamLDAPGroups, allScopes)

		// Run "kubectl get namespaces" which should trigger a browser login via the plugin for the OIDC IDP.
		t.Log("starting OIDC auth via kubectl")
		kubectlCmd = exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", oidcKubeconfigPath, "-v", "6")
		kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv(), []string{"PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW="})

		// Run the kubectl command, wait for the Pinniped CLI to print the authorization URL, and open it in the browser.
		kubectlOutputChan := startKubectlAndOpenAuthorizationURLInBrowser(testCtx, t, kubectlCmd, browser)

		// Confirm that we got to the upstream IDP's login page, fill out the form, and submit the form.
		browsertest.LoginToUpstreamOIDC(t, browser, env.SupervisorUpstreamOIDC)

		// Expect to be redirected to the downstream callback which is serving the form_post HTML.
		t.Logf("waiting for response page %s", federationDomain.Spec.Issuer)
		browser.WaitForURL(t, regexp.MustCompile(regexp.QuoteMeta(federationDomain.Spec.Issuer)))

		// The response page should have done the background fetch() and POST'ed to the CLI's callback.
		// It should now be in the "success" state.
		formpostExpectSuccessState(t, browser)

		requireKubectlGetNamespaceOutput(t, env, waitForKubectlOutput(t, kubectlOutputChan))

		// The user is now logged in to the cluster as two different identities simultaneously, and can switch
		// back and forth by switching kubeconfigs, without needing to auth again.
		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, oidcIDPDisplayName, oidcKubeconfigPath,
			sessionCachePath, pinnipedExe, expectedDownstreamOIDCUsername, expectedDownstreamOIDCGroups, allScopes)
		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, ldapIDPDisplayName, ldapKubeconfigPath,
			sessionCachePath, pinnipedExe, expectedDownstreamLDAPUsername, expectedDownstreamLDAPGroups, allScopes)
		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env, federationDomain, oidcIDPDisplayName, oidcKubeconfigPath,
			sessionCachePath, pinnipedExe, expectedDownstreamOIDCUsername, expectedDownstreamOIDCGroups, allScopes)
	})
}

func removeFederationDomainIdentityProviders(t *testing.T, federationDomainsClient supervisorclient.FederationDomainInterface, federationDomainName string) {
	t.Helper()

	cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	gotFederationDomain, err := federationDomainsClient.Get(cleanupContext, federationDomainName, metav1.GetOptions{})
	require.NoError(t, err)

	// remove the FederationDomain's identity providers
	gotFederationDomain.Spec.IdentityProviders = nil
	_, err = federationDomainsClient.Update(cleanupContext, gotFederationDomain, metav1.UpdateOptions{})
	require.NoError(t, err)
}

func startKubectlAndOpenAuthorizationURLInBrowser(testCtx context.Context, t *testing.T, kubectlCmd *exec.Cmd, b *browsertest.Browser) chan string {
	// Wrap the stdout and stderr pipes with TeeReaders which will copy each incremental read to an
	// in-memory buffer, so we can have the full output available to us at the end.
	originalStderrPipe, err := kubectlCmd.StderrPipe()
	require.NoError(t, err)
	originalStdoutPipe, err := kubectlCmd.StdoutPipe()
	require.NoError(t, err)
	var stderrPipeBuf, stdoutPipeBuf bytes.Buffer
	stderrPipe := io.TeeReader(originalStderrPipe, &stderrPipeBuf)
	stdoutPipe := io.TeeReader(originalStdoutPipe, &stdoutPipeBuf)

	t.Logf("starting kubectl subprocess")
	require.NoError(t, kubectlCmd.Start())
	t.Cleanup(func() {
		// Consume readers so that the tee buffers will contain all the output so far.
		_, stdoutReadAllErr := readAllCtx(testCtx, stdoutPipe)
		_, stderrReadAllErr := readAllCtx(testCtx, stderrPipe)

		// Note that Wait closes the stdout/stderr pipes, so we don't need to close them ourselves.
		waitErr := kubectlCmd.Wait()
		t.Logf("kubectl subprocess exited with code %d", kubectlCmd.ProcessState.ExitCode())

		// Upon failure, print the full output so far of the kubectl command.
		var testAlreadyFailedErr error
		if t.Failed() {
			testAlreadyFailedErr = errors.New("test failed prior to clean up function")
		}
		cleanupErrs := utilerrors.NewAggregate([]error{waitErr, stdoutReadAllErr, stderrReadAllErr, testAlreadyFailedErr})

		if cleanupErrs != nil {
			t.Logf("kubectl stdout was:\n----start of stdout\n%s\n----end of stdout", stdoutPipeBuf.String())
			t.Logf("kubectl stderr was:\n----start of stderr\n%s\n----end of stderr", stderrPipeBuf.String())
		}
		require.NoErrorf(t, cleanupErrs, "kubectl process did not exit cleanly and/or the test failed. "+
			"Note: if kubectl's first call to the Pinniped CLI results in the Pinniped CLI returning an error, "+
			"then kubectl may call the Pinniped CLI again, which may hang because it will wait for the user "+
			"to finish the login. This test will kill the kubectl process after a timeout. In this case, the "+
			" kubectl output printed above will include multiple prompts for the user to enter their authcode.",
		)
	})

	// Start a background goroutine to read stderr from the CLI and parse out the login URL.
	loginURLChan := make(chan string, 1)
	spawnTestGoroutine(testCtx, t, func() error {
		reader := bufio.NewReader(testlib.NewLoggerReader(t, "stderr", stderrPipe))
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			loginURL, err := url.Parse(strings.TrimSpace(scanner.Text()))
			if err == nil && loginURL.Scheme == "https" {
				loginURLChan <- loginURL.String() // this channel is buffered so this will not block
				return nil
			}
		}
		return fmt.Errorf("expected stderr to contain login URL")
	})

	// Start a background goroutine to read stdout from kubectl and return the result as a string.
	kubectlOutputChan := make(chan string, 1)
	spawnTestGoroutine(testCtx, t, func() error {
		output, err := readAllCtx(testCtx, stdoutPipe)
		if err != nil {
			return err
		}
		t.Logf("kubectl output:\n%s\n", output)
		kubectlOutputChan <- string(output) // this channel is buffered so this will not block
		return nil
	})

	// Wait for the CLI to print out the login URL and open the browser to it.
	t.Logf("waiting for CLI to output login URL")
	var loginURL string
	select {
	case <-time.After(1 * time.Minute):
		require.Fail(t, "timed out waiting for login URL")
	case loginURL = <-loginURLChan:
	}
	t.Logf("navigating to login page: %q", loginURL)
	b.Navigate(t, loginURL)

	return kubectlOutputChan
}

func waitForKubectlOutput(t *testing.T, kubectlOutputChan chan string) string {
	t.Logf("waiting for kubectl output")
	var kubectlOutput string
	select {
	case <-time.After(1 * time.Minute):
		require.Fail(t, "timed out waiting for kubectl output")
	case kubectlOutput = <-kubectlOutputChan:
	}
	return kubectlOutput
}

func setupClusterForEndToEndLDAPTest(t *testing.T, username string, env *testlib.TestEnv) *idpv1alpha1.LDAPIdentityProvider {
	// Create a ClusterRoleBinding to give our test user from the upstream read-only access to the cluster.
	testlib.CreateTestClusterRoleBinding(t,
		rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: username},
		rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "view"},
	)
	testlib.WaitForUserToHaveAccess(t, username, []string{}, &authorizationv1.ResourceAttributes{
		Verb:     "get",
		Group:    "",
		Version:  "v1",
		Resource: "namespaces",
	})

	// Put the bind service account's info into a Secret.
	bindSecret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ldap-service-account", corev1.SecretTypeBasicAuth,
		map[string]string{
			corev1.BasicAuthUsernameKey: env.SupervisorUpstreamLDAP.BindUsername,
			corev1.BasicAuthPasswordKey: env.SupervisorUpstreamLDAP.BindPassword,
		},
	)

	// Create upstream LDAP provider and wait for it to become ready.
	return testlib.CreateTestLDAPIdentityProvider(t, idpv1alpha1.LDAPIdentityProviderSpec{
		Host: env.SupervisorUpstreamLDAP.Host,
		TLS: &idpv1alpha1.TLSSpec{
			CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamLDAP.CABundle)),
		},
		Bind: idpv1alpha1.LDAPIdentityProviderBind{
			SecretName: bindSecret.Name,
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
}

func setupClusterForEndToEndActiveDirectoryTest(t *testing.T, username string, env *testlib.TestEnv) *idpv1alpha1.ActiveDirectoryIdentityProvider {
	// Create a ClusterRoleBinding to give our test user from the upstream read-only access to the cluster.
	testlib.CreateTestClusterRoleBinding(t,
		rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: username},
		rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "view"},
	)
	testlib.WaitForUserToHaveAccess(t, username, []string{}, &authorizationv1.ResourceAttributes{
		Verb:     "get",
		Group:    "",
		Version:  "v1",
		Resource: "namespaces",
	})

	// Put the bind service account's info into a Secret.
	bindSecret := testlib.CreateTestSecret(t, env.SupervisorNamespace, "ldap-service-account", corev1.SecretTypeBasicAuth,
		map[string]string{
			corev1.BasicAuthUsernameKey: env.SupervisorUpstreamActiveDirectory.BindUsername,
			corev1.BasicAuthPasswordKey: env.SupervisorUpstreamActiveDirectory.BindPassword,
		},
	)

	// Create upstream LDAP provider and wait for it to become ready.
	return testlib.CreateTestActiveDirectoryIdentityProvider(t, idpv1alpha1.ActiveDirectoryIdentityProviderSpec{
		Host: env.SupervisorUpstreamActiveDirectory.Host,
		TLS: &idpv1alpha1.TLSSpec{
			CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorUpstreamActiveDirectory.CABundle)),
		},
		Bind: idpv1alpha1.ActiveDirectoryIdentityProviderBind{
			SecretName: bindSecret.Name,
		},
	}, idpv1alpha1.ActiveDirectoryPhaseReady)
}

func readFromFileUntilStringIsSeen(t *testing.T, f *os.File, until string) string {
	readFromFile := ""

	testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
		someOutput, foundEOF := readAvailableOutput(t, f)
		readFromFile += someOutput
		if strings.Contains(readFromFile, until) {
			return true, nil // found it! finished.
		}
		if foundEOF {
			return false, fmt.Errorf("reached EOF of subcommand's output without seeing expected string %q. Output read so far was:\n%s", until, readFromFile)
		}
		return false, nil // keep waiting and reading
	}, 1*time.Minute, 1*time.Second)
	return readFromFile
}

func readAvailableOutput(t *testing.T, r io.Reader) (string, bool) {
	buf := make([]byte, 1024)
	n, err := r.Read(buf)
	if err != nil {
		if err == io.EOF {
			return string(buf[:n]), true
		}
		require.NoError(t, err)
	}
	return string(buf[:n]), false
}

func requireKubectlGetNamespaceOutput(t *testing.T, env *testlib.TestEnv, kubectlOutput string) {
	t.Log("kubectl command output:\n", kubectlOutput)
	require.Greaterf(t, len(kubectlOutput), 0, "expected to get some more output from the kubectl subcommand, but did not")

	// Should look generally like a list of namespaces, with one namespace listed per line in a table format.
	require.Greaterf(t, len(strings.Split(kubectlOutput, "\n")), 2, "expected some namespaces to be returned, got %q", kubectlOutput)
	require.Contains(t, kubectlOutput, fmt.Sprintf("\n%s ", env.ConciergeNamespace))
	require.Contains(t, kubectlOutput, fmt.Sprintf("\n%s ", env.SupervisorNamespace))
	if len(env.ToolsNamespace) > 0 {
		require.Contains(t, kubectlOutput, fmt.Sprintf("\n%s ", env.ToolsNamespace))
	}
}

func requireUserCanUseKubectlWithoutAuthenticatingAgain(
	ctx context.Context,
	t *testing.T,
	env *testlib.TestEnv,
	downstream *supervisorconfigv1alpha1.FederationDomain,
	upstreamProviderName string,
	kubeconfigPath string,
	sessionCachePath string,
	pinnipedExe string,
	expectedUsername string,
	expectedGroups []string,
	downstreamScopes []string,
) {
	// 	Run kubectl, which should work without any prompting for authentication.
	kubectlCmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
	kubectlCmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())
	startTime := time.Now()
	kubectlOutput2, err := kubectlCmd.CombinedOutput()
	require.NoError(t, err)
	require.Greaterf(t, len(bytes.Split(kubectlOutput2, []byte("\n"))), 2, "expected some namespaces to be returned again")
	t.Logf("second kubectl command took %s", time.Since(startTime).String())

	// Probe our cache for the current ID token as a proxy for a whoami API.
	cache := filesession.New(sessionCachePath, filesession.WithErrorReporter(func(err error) {
		require.NoError(t, err)
	}))

	sort.Strings(downstreamScopes)
	token := cache.GetToken(oidcclient.SessionCacheKey{
		Issuer:               downstream.Spec.Issuer,
		ClientID:             "pinniped-cli",
		Scopes:               downstreamScopes,
		RedirectURI:          "http://localhost:0/callback",
		UpstreamProviderName: upstreamProviderName,
	})
	require.NotNil(t, token)

	requireGCAnnotationsOnSessionStorage(ctx, t, env.SupervisorNamespace, startTime, token)

	idTokenClaims := token.IDToken.Claims
	require.Equal(t, expectedUsername, idTokenClaims["username"])

	if expectedGroups == nil {
		require.Nil(t, idTokenClaims["groups"])
	} else {
		// The groups claim in the file ends up as an []any, so adjust our expectation to match.
		expectedGroupsAsEmptyInterfaces := make([]any, 0, len(expectedGroups))
		for _, g := range expectedGroups {
			expectedGroupsAsEmptyInterfaces = append(expectedGroupsAsEmptyInterfaces, g)
		}
		require.ElementsMatch(t, expectedGroupsAsEmptyInterfaces, idTokenClaims["groups"])
	}

	expectedGroupsPlusAuthenticated := expectedGroups
	expectedGroupsPlusAuthenticated = append(expectedGroupsPlusAuthenticated, "system:authenticated")

	// Confirm we are the right user according to Kube by calling the WhoAmIRequest API.
	// Use --validate=false with this command because running this command against any cluster which has
	// the ServerSideFieldValidation feature gate enabled causes this command to return an RBAC error
	// complaining that this user does not have permission to list CRDs:
	//   error validating data: failed to check CRD: failed to list CRDs: customresourcedefinitions.apiextensions.k8s.io is forbidden:
	//   User "pinny" cannot list resource "customresourcedefinitions" in API group "apiextensions.k8s.io" at the cluster scope; if you choose to ignore these errors, turn validation off with --validate=false
	// While it is true that the user cannot list CRDs, that fact seems unrelated to making a create call to the
	// aggregated API endpoint, so this is a strange error, but it can be easily reproduced.
	kubectlCmd3 := exec.CommandContext(ctx, "kubectl", "create", "-f", "-", "-o", "yaml", "--kubeconfig", kubeconfigPath, "--validate=false")
	kubectlCmd3.Env = slices.Concat(os.Environ(), env.ProxyEnv())
	kubectlCmd3.Stdin = strings.NewReader(here.Docf(`
			apiVersion: identity.concierge.%s/v1alpha1
			kind: WhoAmIRequest
	`, env.APIGroupSuffix))

	kubectlOutput3, err := kubectlCmd3.CombinedOutput()
	require.NoErrorf(t, err,
		"expected no error but got error, combined stdout/stderr was:\n----start of output\n%s\n----end of output", kubectlOutput3)

	whoAmI := deserializeWhoAmIRequest(t, string(kubectlOutput3), env.APIGroupSuffix)
	require.Equal(t, expectedUsername, whoAmI.Status.KubernetesUserInfo.User.Username)
	require.ElementsMatch(t, expectedGroupsPlusAuthenticated, whoAmI.Status.KubernetesUserInfo.User.Groups)

	// Validate that `pinniped whoami` returns the correct identity.
	assertWhoami(
		ctx,
		t,
		true,
		pinnipedExe,
		kubeconfigPath,
		expectedUsername,
		expectedGroupsPlusAuthenticated,
	)
}

func requireGCAnnotationsOnSessionStorage(ctx context.Context, t *testing.T, supervisorNamespace string, startTime time.Time, token *oidctypes.Token) {
	// check that the access token is new (since it's just been refreshed) and has close to two minutes left.
	testutil.RequireTimeInDelta(t, startTime.Add(2*time.Minute), token.AccessToken.Expiry.Time, 15*time.Second)

	kubeClient := testlib.NewKubernetesClientset(t).CoreV1()

	// get the access token secret that matches the signature from the cache
	accessTokenSignature := strings.Split(token.AccessToken.Token, ".")[1]
	accessSecretName := getSecretNameFromSignature(t, accessTokenSignature, "access-token")
	accessTokenSecret, err := kubeClient.Secrets(supervisorNamespace).Get(ctx, accessSecretName, metav1.GetOptions{})
	require.NoError(t, err)

	// Check that the access token garbage-collect-after value is 9 hours from now
	accessTokenGCTimeString := accessTokenSecret.Annotations["storage.pinniped.dev/garbage-collect-after"]
	accessTokenGCTime, err := time.Parse(crud.SecretLifetimeAnnotationDateFormat, accessTokenGCTimeString)
	require.NoError(t, err)
	require.True(t, accessTokenGCTime.After(time.Now().Add(9*time.Hour)))

	// get the refresh token secret that matches the signature from the cache
	refreshTokenSignature := strings.Split(token.RefreshToken.Token, ".")[1]
	refreshSecretName := getSecretNameFromSignature(t, refreshTokenSignature, "refresh-token")
	refreshTokenSecret, err := kubeClient.Secrets(supervisorNamespace).Get(ctx, refreshSecretName, metav1.GetOptions{})
	require.NoError(t, err)

	// Check that the refresh token garbage-collect-after value is 9 hours
	refreshTokenGCTimeString := refreshTokenSecret.Annotations["storage.pinniped.dev/garbage-collect-after"]
	refreshTokenGCTime, err := time.Parse(crud.SecretLifetimeAnnotationDateFormat, refreshTokenGCTimeString)
	require.NoError(t, err)
	require.True(t, refreshTokenGCTime.After(time.Now().Add(9*time.Hour)))

	// the access token and the refresh token should be garbage collected at essentially the same time
	testutil.RequireTimeInDelta(t, accessTokenGCTime, refreshTokenGCTime, 1*time.Minute)
}

func runPinnipedGetKubeconfig(t *testing.T, env *testlib.TestEnv, pinnipedExe string, tempDir string, pinnipedCLICommand []string) string {
	// Run "pinniped get kubeconfig" to get a kubeconfig YAML.
	envVarsWithProxy := slices.Concat(os.Environ(), env.ProxyEnv())
	kubeconfigYAML, stderr := runPinnipedCLI(t, envVarsWithProxy, pinnipedExe, pinnipedCLICommand...)
	t.Logf("stderr output from 'pinniped get kubeconfig':\n%s\n\n", stderr)
	t.Logf("test kubeconfig:\n%s\n\n", kubeconfigYAML)

	restConfig := testlib.NewRestConfigFromKubeconfig(t, kubeconfigYAML)
	require.NotNil(t, restConfig.ExecProvider)
	require.Equal(t, []string{"login", "oidc"}, restConfig.ExecProvider.Args[:2])

	kubeconfigPath := filepath.Join(tempDir, fmt.Sprintf("kubeconfig-%s.yaml", testlib.RandHex(t, 8)))
	require.NoError(t, os.WriteFile(kubeconfigPath, []byte(kubeconfigYAML), 0600))

	return kubeconfigPath
}

func getSecretNameFromSignature(t *testing.T, signature string, typeLabel string) string {
	t.Helper()
	// try to decode base64 signatures to prevent double encoding of binary data
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)
	require.NoError(t, err)
	// lower case base32 encoding insures that our secret name is valid per ValidateSecretName in k/k
	var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)
	signatureAsValidName := strings.ToLower(b32.EncodeToString(signatureBytes))
	return fmt.Sprintf("pinniped-storage-%s-%s", typeLabel, signatureAsValidName)
}

func readAllCtx(ctx context.Context, r io.Reader) ([]byte, error) {
	errCh := make(chan error, 1)
	data := &atomic.Value{}
	go func() { // copied from io.ReadAll and modified to use the atomic.Value above
		b := make([]byte, 0, 512)
		data.Store(string(b)) // cast to string to make a copy of the byte slice
		for {
			if len(b) == cap(b) {
				// Add more capacity (let append pick how much).
				b = append(b, 0)[:len(b)]
				data.Store(string(b)) // cast to string to make a copy of the byte slice
			}
			n, err := r.Read(b[len(b):cap(b)])
			b = b[:len(b)+n]
			data.Store(string(b)) // cast to string to make a copy of the byte slice
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				errCh <- err
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		b, _ := data.Load().(string)
		return nil, fmt.Errorf("failed to complete read all: %w, data read so far:\n%q", ctx.Err(), b)

	case err := <-errCh:
		b, _ := data.Load().(string)
		if len(b) == 0 {
			return nil, err
		}
		return []byte(b), err
	}
}
