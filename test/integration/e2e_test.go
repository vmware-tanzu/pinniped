// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
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
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	authv1alpha "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/crud"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/filesession"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	"go.pinniped.dev/test/testlib"
	"go.pinniped.dev/test/testlib/browsertest"
)

// TestE2EFullIntegration_Browser tests a full integration scenario that combines the supervisor, concierge, and CLI.
func TestE2EFullIntegration_Browser(t *testing.T) { // nolint:gocyclo
	env := testlib.IntegrationEnv(t)

	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancelFunc()

	// Build pinniped CLI.
	pinnipedExe := testlib.PinnipedCLIPath(t)
	tempDir := testutil.TempDir(t)

	// Infer the downstream issuer URL from the callback associated with the upstream test client registration.
	issuerURL, err := url.Parse(env.SupervisorUpstreamOIDC.CallbackURL)
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(issuerURL.Path, "/callback"))
	issuerURL.Path = strings.TrimSuffix(issuerURL.Path, "/callback")
	t.Logf("testing with downstream issuer URL %s", issuerURL.String())

	// Generate a CA bundle with which to serve this provider.
	t.Logf("generating test CA")
	ca, err := certauthority.New("Downstream Test CA", 1*time.Hour)
	require.NoError(t, err)

	// Save that bundle plus the one that signs the upstream issuer, for test purposes.
	testCABundlePath := filepath.Join(tempDir, "test-ca.pem")
	testCABundlePEM := []byte(string(ca.Bundle()) + "\n" + env.SupervisorUpstreamOIDC.CABundle)
	testCABundleBase64 := base64.StdEncoding.EncodeToString(testCABundlePEM)
	require.NoError(t, ioutil.WriteFile(testCABundlePath, testCABundlePEM, 0600))

	// Use the CA to issue a TLS server cert.
	t.Logf("issuing test certificate")
	tlsCert, err := ca.IssueServerCert([]string{issuerURL.Hostname()}, nil, 1*time.Hour)
	require.NoError(t, err)
	certPEM, keyPEM, err := certauthority.ToPEM(tlsCert)
	require.NoError(t, err)

	// Write the serving cert to a secret.
	certSecret := testlib.CreateTestSecret(t,
		env.SupervisorNamespace,
		"oidc-provider-tls",
		corev1.SecretTypeTLS,
		map[string]string{"tls.crt": string(certPEM), "tls.key": string(keyPEM)},
	)

	// Create the downstream FederationDomain and expect it to go into the success status condition.
	downstream := testlib.CreateTestFederationDomain(ctx, t,
		issuerURL.String(),
		certSecret.Name,
		configv1alpha1.SuccessFederationDomainStatusCondition,
	)

	// Create a JWTAuthenticator that will validate the tokens from the downstream issuer.
	clusterAudience := "test-cluster-" + testlib.RandHex(t, 8)
	authenticator := testlib.CreateTestJWTAuthenticator(ctx, t, authv1alpha.JWTAuthenticatorSpec{
		Issuer:   downstream.Spec.Issuer,
		Audience: clusterAudience,
		TLS:      &authv1alpha.TLSSpec{CertificateAuthorityData: testCABundleBase64},
	})

	// Add an OIDC upstream IDP and try using it to authenticate during kubectl commands.
	t.Run("with Supervisor OIDC upstream IDP and automatic flow", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		t.Cleanup(cancel)

		// Start a fresh browser driver because we don't want to share cookies between the various tests in this file.
		page := browsertest.Open(t)

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

		// Create upstream OIDC provider and wait for it to become ready.
		testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
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
				SecretName: testlib.CreateClientCredsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
			},
		}, idpv1alpha1.PhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/oidc-test-sessions.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-ca-bundle", testCABundlePath,
			"--oidc-session-cache", sessionCachePath,
		})

		// Run "kubectl get namespaces" which should trigger a browser login via the plugin.
		start := time.Now()
		kubectlCmd := exec.CommandContext(testCtx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath, "-v", "6")
		kubectlCmd.Env = append(os.Environ(), env.ProxyEnv()...)

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
		require.NoError(t, page.Navigate(loginURL))

		// Expect to be redirected to the upstream provider and log in.
		browsertest.LoginToUpstream(t, page, env.SupervisorUpstreamOIDC)

		// Expect to be redirected to the downstream callback which is serving the form_post HTML.
		t.Logf("waiting for response page %s", downstream.Spec.Issuer)
		browsertest.WaitForURL(t, page, regexp.MustCompile(regexp.QuoteMeta(downstream.Spec.Issuer)))

		// The response page should have done the background fetch() and POST'ed to the CLI's callback.
		// It should now be in the "success" state.
		formpostExpectSuccessState(t, page)

		// Expect the CLI to output a list of namespaces.
		t.Logf("waiting for kubectl to output namespace list")
		var kubectlOutput string
		select {
		case <-time.After(10 * time.Second):
			require.Fail(t, "timed out waiting for kubectl output")
		case kubectlOutput = <-kubectlOutputChan:
		}
		requireKubectlGetNamespaceOutput(t, env, kubectlOutput)

		t.Logf("first kubectl command took %s", time.Since(start).String())

		requireUserCanUseKubectlWithoutAuthenticatingAgain(testCtx, t, env,
			downstream,
			kubeconfigPath,
			sessionCachePath,
			pinnipedExe,
			expectedUsername,
			expectedGroups,
		)
	})

	t.Run("with Supervisor OIDC upstream IDP and manual authcode copy-paste from browser flow", func(t *testing.T) {
		// Start a fresh browser driver because we don't want to share cookies between the various tests in this file.
		page := browsertest.Open(t)

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

		// Create upstream OIDC provider and wait for it to become ready.
		testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
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
				SecretName: testlib.CreateClientCredsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
			},
		}, idpv1alpha1.PhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/oidc-test-sessions-manual.yaml"
		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-skip-listen",
			"--oidc-ca-bundle", testCABundlePath,
			"--oidc-session-cache", sessionCachePath,
		})

		// Run "kubectl get namespaces" which should trigger a browser login via the plugin.
		start := time.Now()
		kubectlCmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = append(os.Environ(), env.ProxyEnv()...)

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
		require.NoError(t, page.Navigate(loginURL))

		// Expect to be redirected to the upstream provider and log in.
		browsertest.LoginToUpstream(t, page, env.SupervisorUpstreamOIDC)

		// Expect to be redirected to the downstream callback which is serving the form_post HTML.
		t.Logf("waiting for response page %s", downstream.Spec.Issuer)
		browsertest.WaitForURL(t, page, regexp.MustCompile(regexp.QuoteMeta(downstream.Spec.Issuer)))

		// The response page should have failed to automatically post, and should now be showing the manual instructions.
		authCode := formpostExpectManualState(t, page)

		// Enter the auth code in the waiting prompt, followed by a newline.
		t.Logf("'manually' pasting authorization code %q to waiting prompt", authCode)
		_, err = ptyFile.WriteString(authCode + "\n")
		require.NoError(t, err)

		// Read all of the remaining output from the subprocess until EOF.
		t.Logf("waiting for kubectl to output namespace list")
		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlOutputBytes, _ := ioutil.ReadAll(ptyFile)
		requireKubectlGetNamespaceOutput(t, env, string(kubectlOutputBytes))

		t.Logf("first kubectl command took %s", time.Since(start).String())

		requireUserCanUseKubectlWithoutAuthenticatingAgain(ctx, t, env,
			downstream,
			kubeconfigPath,
			sessionCachePath,
			pinnipedExe,
			expectedUsername,
			expectedGroups,
		)
	})

	t.Run("access token based refresh with Supervisor OIDC upstream IDP and manual authcode copy-paste from browser flow", func(t *testing.T) {
		// Start a fresh browser driver because we don't want to share cookies between the various tests in this file.
		page := browsertest.Open(t)

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

		// Create upstream OIDC provider and wait for it to become ready.
		testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
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
				SecretName: testlib.CreateClientCredsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
			},
		}, idpv1alpha1.PhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/oidc-test-sessions-manual.yaml"
		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-skip-listen",
			"--oidc-ca-bundle", testCABundlePath,
			"--oidc-session-cache", sessionCachePath,
		})

		// Run "kubectl get namespaces" which should trigger a browser login via the plugin.
		start := time.Now()
		kubectlCmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = append(os.Environ(), env.ProxyEnv()...)
		var kubectlStdoutPipe io.ReadCloser
		if runtime.GOOS != "darwin" {
			// For some unknown reason this breaks the pty library on some MacOS machines.
			// The problem doesn't reproduce for everyone, so this is just a workaround.
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
		require.NoError(t, page.Navigate(loginURL))

		// Expect to be redirected to the upstream provider and log in.
		browsertest.LoginToUpstream(t, page, env.SupervisorUpstreamOIDC)

		// Expect to be redirected to the downstream callback which is serving the form_post HTML.
		t.Logf("waiting for response page %s", downstream.Spec.Issuer)
		browsertest.WaitForURL(t, page, regexp.MustCompile(regexp.QuoteMeta(downstream.Spec.Issuer)))

		// The response page should have failed to automatically post, and should now be showing the manual instructions.
		authCode := formpostExpectManualState(t, page)

		// Enter the auth code in the waiting prompt, followed by a newline.
		t.Logf("'manually' pasting authorization code %q to waiting prompt", authCode)
		_, err = ptyFile.WriteString(authCode + "\n")
		require.NoError(t, err)

		// Read all of the remaining output from the subprocess until EOF.
		t.Logf("waiting for kubectl to output namespace list")
		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlPtyOutputBytes, _ := ioutil.ReadAll(ptyFile)
		if kubectlStdoutPipe != nil {
			// On non-MacOS check that stdout of the CLI contains the expected output.
			kubectlStdOutOutputBytes, _ := ioutil.ReadAll(kubectlStdoutPipe)
			requireKubectlGetNamespaceOutput(t, env, string(kubectlStdOutOutputBytes))
		} else {
			// On MacOS check that the pty (stdout+stderr+stdin) of the CLI contains the expected output.
			requireKubectlGetNamespaceOutput(t, env, string(kubectlPtyOutputBytes))
		}
		// Due to the GOOS check in the code above, on MacOS the pty will include stdout, and other platforms it will not.
		// This warning message is supposed to be printed by the CLI on stderr.
		require.Contains(t, string(kubectlPtyOutputBytes),
			"Access token from identity provider has lifetime of less than 3 hours. Expect frequent prompts to log in.")

		t.Logf("first kubectl command took %s", time.Since(start).String())

		requireUserCanUseKubectlWithoutAuthenticatingAgain(ctx, t, env,
			downstream,
			kubeconfigPath,
			sessionCachePath,
			pinnipedExe,
			expectedUsername,
			expectedGroups,
		)
	})

	t.Run("with Supervisor OIDC upstream IDP and CLI password flow without web browser", func(t *testing.T) {
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

		// Create upstream OIDC provider and wait for it to become ready.
		testlib.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
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
				SecretName: testlib.CreateClientCredsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
			},
		}, idpv1alpha1.PhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/oidc-test-sessions-password-grant.yaml"
		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-skip-browser",
			"--oidc-skip-listen",
			"--upstream-identity-provider-flow", "cli_password", // create a kubeconfig configured to use the cli_password flow
			"--oidc-ca-bundle", testCABundlePath,
			"--oidc-session-cache", sessionCachePath,
		})

		// Run "kubectl get namespaces" which should trigger a browser-less CLI prompt login via the plugin.
		start := time.Now()
		kubectlCmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = append(os.Environ(), env.ProxyEnv()...)
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
		kubectlOutputBytes, _ := ioutil.ReadAll(ptyFile)
		requireKubectlGetNamespaceOutput(t, env, string(kubectlOutputBytes))

		t.Logf("first kubectl command took %s", time.Since(start).String())

		requireUserCanUseKubectlWithoutAuthenticatingAgain(ctx, t, env,
			downstream,
			kubeconfigPath,
			sessionCachePath,
			pinnipedExe,
			expectedUsername,
			expectedGroups,
		)
	})

	t.Run("with Supervisor OIDC upstream IDP and CLI password flow when OIDCIdentityProvider disallows it", func(t *testing.T) {
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
				SecretName: testlib.CreateClientCredsSecret(t, env.SupervisorUpstreamOIDC.ClientID, env.SupervisorUpstreamOIDC.ClientSecret).Name,
			},
		}, idpv1alpha1.PhaseReady)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/oidc-test-sessions-password-grant-negative-test.yaml"
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
			"--oidc-ca-bundle", testCABundlePath,
			"--oidc-session-cache", sessionCachePath,
		})

		// Run "kubectl get namespaces" which should trigger a browser-less CLI prompt login via the plugin.
		kubectlCmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = append(os.Environ(), env.ProxyEnv()...)
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Wait for the subprocess to print the username prompt, then type the user's username.
		readFromFileUntilStringIsSeen(t, ptyFile, "Username: ")
		_, err = ptyFile.WriteString(env.SupervisorUpstreamOIDC.Username + "\n")
		require.NoError(t, err)

		// Wait for the subprocess to print the password prompt, then type the user's password.
		readFromFileUntilStringIsSeen(t, ptyFile, "Password: ")
		_, err = ptyFile.WriteString(env.SupervisorUpstreamOIDC.Password + "\n")
		require.NoError(t, err)

		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlOutputBytes, _ := ioutil.ReadAll(ptyFile)
		kubectlOutput := string(kubectlOutputBytes)

		// The output should look like an authentication failure, because the OIDCIdentityProvider disallows password grants.
		t.Log("kubectl command output (expecting a login failed error):\n", kubectlOutput)
		require.Contains(t, kubectlOutput,
			`Error: could not complete Pinniped login: login failed with code "access_denied": `+
				`The resource owner or authorization server denied the request. `+
				`Resource owner password credentials grant is not allowed for this upstream provider according to its configuration.`,
		)
	})

	// Add an LDAP upstream IDP and try using it to authenticate during kubectl commands
	// by interacting with the CLI's username and password prompts.
	t.Run("with Supervisor LDAP upstream IDP using username and password prompts", func(t *testing.T) {
		if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
			t.Skip("LDAP integration test requires connectivity to an LDAP server")
		}

		expectedUsername := env.SupervisorUpstreamLDAP.TestUserMailAttributeValue
		expectedGroups := env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs

		setupClusterForEndToEndLDAPTest(t, expectedUsername, env)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/ldap-test-sessions.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-session-cache", sessionCachePath,
		})

		// Run "kubectl get namespaces" which should trigger an LDAP-style login CLI prompt via the plugin.
		start := time.Now()
		kubectlCmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = append(os.Environ(), env.ProxyEnv()...)
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
		kubectlOutputBytes, _ := ioutil.ReadAll(ptyFile)
		requireKubectlGetNamespaceOutput(t, env, string(kubectlOutputBytes))

		t.Logf("first kubectl command took %s", time.Since(start).String())

		requireUserCanUseKubectlWithoutAuthenticatingAgain(ctx, t, env,
			downstream,
			kubeconfigPath,
			sessionCachePath,
			pinnipedExe,
			expectedUsername,
			expectedGroups,
		)
	})

	// Add an LDAP upstream IDP and try using it to authenticate during kubectl commands
	// by passing username and password via environment variables, thus avoiding the CLI's username and password prompts.
	t.Run("with Supervisor LDAP upstream IDP using PINNIPED_USERNAME and PINNIPED_PASSWORD env vars", func(t *testing.T) {
		if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
			t.Skip("LDAP integration test requires connectivity to an LDAP server")
		}

		expectedUsername := env.SupervisorUpstreamLDAP.TestUserMailAttributeValue
		expectedGroups := env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs

		setupClusterForEndToEndLDAPTest(t, expectedUsername, env)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/ldap-test-with-env-vars-sessions.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-session-cache", sessionCachePath,
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
		kubectlCmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = append(os.Environ(), env.ProxyEnv()...)
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlOutputBytes, _ := ioutil.ReadAll(ptyFile)
		requireKubectlGetNamespaceOutput(t, env, string(kubectlOutputBytes))

		t.Logf("first kubectl command took %s", time.Since(start).String())

		// The next kubectl command should not require auth, so we should be able to run it without these env vars.
		require.NoError(t, os.Unsetenv(usernameEnvVar))
		require.NoError(t, os.Unsetenv(passwordEnvVar))

		requireUserCanUseKubectlWithoutAuthenticatingAgain(ctx, t, env,
			downstream,
			kubeconfigPath,
			sessionCachePath,
			pinnipedExe,
			expectedUsername,
			expectedGroups,
		)
	})

	// Add an Active Directory upstream IDP and try using it to authenticate during kubectl commands
	// by interacting with the CLI's username and password prompts.
	t.Run("with Supervisor ActiveDirectory upstream IDP using username and password prompts", func(t *testing.T) {
		if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
			t.Skip("Active Directory integration test requires connectivity to an LDAP server")
		}
		if env.SupervisorUpstreamActiveDirectory.Host == "" {
			t.Skip("Active Directory hostname not specified")
		}

		expectedUsername := env.SupervisorUpstreamActiveDirectory.TestUserPrincipalNameValue
		expectedGroups := env.SupervisorUpstreamActiveDirectory.TestUserIndirectGroupsSAMAccountPlusDomainNames

		setupClusterForEndToEndActiveDirectoryTest(t, expectedUsername, env)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/ad-test-sessions.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-session-cache", sessionCachePath,
		})

		// Run "kubectl get namespaces" which should trigger an LDAP-style login CLI prompt via the plugin.
		start := time.Now()
		kubectlCmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = append(os.Environ(), env.ProxyEnv()...)
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
		kubectlOutputBytes, _ := ioutil.ReadAll(ptyFile)
		requireKubectlGetNamespaceOutput(t, env, string(kubectlOutputBytes))

		t.Logf("first kubectl command took %s", time.Since(start).String())

		requireUserCanUseKubectlWithoutAuthenticatingAgain(ctx, t, env,
			downstream,
			kubeconfigPath,
			sessionCachePath,
			pinnipedExe,
			expectedUsername,
			expectedGroups,
		)
	})

	// Add an ActiveDirectory upstream IDP and try using it to authenticate during kubectl commands
	// by passing username and password via environment variables, thus avoiding the CLI's username and password prompts.
	t.Run("with Supervisor ActiveDirectory upstream IDP using PINNIPED_USERNAME and PINNIPED_PASSWORD env vars", func(t *testing.T) {
		if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
			t.Skip("ActiveDirectory integration test requires connectivity to an LDAP server")
		}

		if env.SupervisorUpstreamActiveDirectory.Host == "" {
			t.Skip("Active Directory hostname not specified")
		}

		expectedUsername := env.SupervisorUpstreamActiveDirectory.TestUserPrincipalNameValue
		expectedGroups := env.SupervisorUpstreamActiveDirectory.TestUserIndirectGroupsSAMAccountPlusDomainNames

		setupClusterForEndToEndActiveDirectoryTest(t, expectedUsername, env)

		// Use a specific session cache for this test.
		sessionCachePath := tempDir + "/ad-test-with-env-vars-sessions.yaml"

		kubeconfigPath := runPinnipedGetKubeconfig(t, env, pinnipedExe, tempDir, []string{
			"get", "kubeconfig",
			"--concierge-api-group-suffix", env.APIGroupSuffix,
			"--concierge-authenticator-type", "jwt",
			"--concierge-authenticator-name", authenticator.Name,
			"--oidc-session-cache", sessionCachePath,
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
		kubectlCmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = append(os.Environ(), env.ProxyEnv()...)
		ptyFile, err := pty.Start(kubectlCmd)
		require.NoError(t, err)

		// Read all output from the subprocess until EOF.
		// Ignore any errors returned because there is always an error on linux.
		kubectlOutputBytes, _ := ioutil.ReadAll(ptyFile)
		requireKubectlGetNamespaceOutput(t, env, string(kubectlOutputBytes))

		t.Logf("first kubectl command took %s", time.Since(start).String())

		// The next kubectl command should not require auth, so we should be able to run it without these env vars.
		require.NoError(t, os.Unsetenv(usernameEnvVar))
		require.NoError(t, os.Unsetenv(passwordEnvVar))

		requireUserCanUseKubectlWithoutAuthenticatingAgain(ctx, t, env,
			downstream,
			kubeconfigPath,
			sessionCachePath,
			pinnipedExe,
			expectedUsername,
			expectedGroups,
		)
	})
}

func setupClusterForEndToEndLDAPTest(t *testing.T, username string, env *testlib.TestEnv) {
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
	testlib.CreateTestLDAPIdentityProvider(t, idpv1alpha1.LDAPIdentityProviderSpec{
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

func setupClusterForEndToEndActiveDirectoryTest(t *testing.T, username string, env *testlib.TestEnv) {
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
	testlib.CreateTestActiveDirectoryIdentityProvider(t, idpv1alpha1.ActiveDirectoryIdentityProviderSpec{
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
	downstream *configv1alpha1.FederationDomain,
	kubeconfigPath string,
	sessionCachePath string,
	pinnipedExe string,
	expectedUsername string,
	expectedGroups []string,
) {
	// 	Run kubectl, which should work without any prompting for authentication.
	kubectlCmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
	kubectlCmd.Env = append(os.Environ(), env.ProxyEnv()...)
	startTime := time.Now()
	kubectlOutput2, err := kubectlCmd.CombinedOutput()
	require.NoError(t, err)
	require.Greaterf(t, len(bytes.Split(kubectlOutput2, []byte("\n"))), 2, "expected some namespaces to be returned again")
	t.Logf("second kubectl command took %s", time.Since(startTime).String())

	// Probe our cache for the current ID token as a proxy for a whoami API.
	cache := filesession.New(sessionCachePath, filesession.WithErrorReporter(func(err error) {
		require.NoError(t, err)
	}))

	downstreamScopes := []string{coreosoidc.ScopeOfflineAccess, coreosoidc.ScopeOpenID, "pinniped:request-audience"}
	sort.Strings(downstreamScopes)
	token := cache.GetToken(oidcclient.SessionCacheKey{
		Issuer:      downstream.Spec.Issuer,
		ClientID:    "pinniped-cli",
		Scopes:      downstreamScopes,
		RedirectURI: "http://localhost:0/callback",
	})
	require.NotNil(t, token)

	requireGCAnnotationsOnSessionStorage(ctx, t, env.SupervisorNamespace, startTime, token)

	idTokenClaims := token.IDToken.Claims
	require.Equal(t, expectedUsername, idTokenClaims[oidc.DownstreamUsernameClaim])

	// The groups claim in the file ends up as an []interface{}, so adjust our expectation to match.
	expectedGroupsAsEmptyInterfaces := make([]interface{}, 0, len(expectedGroups))
	for _, g := range expectedGroups {
		expectedGroupsAsEmptyInterfaces = append(expectedGroupsAsEmptyInterfaces, g)
	}
	require.ElementsMatch(t, expectedGroupsAsEmptyInterfaces, idTokenClaims[oidc.DownstreamGroupsClaim])

	expectedGroupsPlusAuthenticated := append([]string{}, expectedGroups...)
	expectedGroupsPlusAuthenticated = append(expectedGroupsPlusAuthenticated, "system:authenticated")

	// Confirm we are the right user according to Kube by calling the whoami API.
	kubectlCmd3 := exec.CommandContext(ctx, "kubectl", "create", "-f", "-", "-o", "yaml", "--kubeconfig", kubeconfigPath)
	kubectlCmd3.Env = append(os.Environ(), env.ProxyEnv()...)
	kubectlCmd3.Stdin = strings.NewReader(here.Docf(`
			apiVersion: identity.concierge.%s/v1alpha1
			kind: WhoAmIRequest
	`, env.APIGroupSuffix))

	kubectlOutput3, err := kubectlCmd3.CombinedOutput()
	require.NoError(t, err)

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
	envVarsWithProxy := append(os.Environ(), env.ProxyEnv()...)
	kubeconfigYAML, stderr := runPinnipedCLI(t, envVarsWithProxy, pinnipedExe, pinnipedCLICommand...)
	t.Logf("stderr output from 'pinniped get kubeconfig':\n%s\n\n", stderr)
	t.Logf("test kubeconfig:\n%s\n\n", kubeconfigYAML)

	restConfig := testlib.NewRestConfigFromKubeconfig(t, kubeconfigYAML)
	require.NotNil(t, restConfig.ExecProvider)
	require.Equal(t, []string{"login", "oidc"}, restConfig.ExecProvider.Args[:2])

	kubeconfigPath := filepath.Join(tempDir, "kubeconfig.yaml")
	require.NoError(t, ioutil.WriteFile(kubeconfigPath, []byte(kubeconfigYAML), 0600))

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
