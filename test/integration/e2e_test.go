// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
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
	"sort"
	"strings"
	"testing"
	"time"

	"go.pinniped.dev/pkg/oidcclient/oidctypes"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
	"go.pinniped.dev/test/testlib"
	"go.pinniped.dev/test/testlib/browsertest"
)

// TestE2EFullIntegration tests a full integration scenario that combines the supervisor, concierge, and CLI.
func TestE2EFullIntegration(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	ctx, cancelFunc := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancelFunc()

	// Build pinniped CLI.
	pinnipedExe := testlib.PinnipedCLIPath(t)
	tempDir := testutil.TempDir(t)

	// Start the browser driver.
	page := browsertest.Open(t)

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
	t.Run("with Supervisor OIDC upstream IDP", func(t *testing.T) {
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
		kubectlCmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
		kubectlCmd.Env = append(os.Environ(), env.ProxyEnv()...)
		stderrPipe, err := kubectlCmd.StderrPipe()
		require.NoError(t, err)
		stdoutPipe, err := kubectlCmd.StdoutPipe()
		require.NoError(t, err)

		t.Logf("starting kubectl subprocess")
		require.NoError(t, kubectlCmd.Start())
		t.Cleanup(func() {
			err := kubectlCmd.Wait()
			t.Logf("kubectl subprocess exited with code %d", kubectlCmd.ProcessState.ExitCode())
			stdout, stdoutErr := ioutil.ReadAll(stdoutPipe)
			if stdoutErr != nil {
				stdout = []byte("<error reading stdout: " + stdoutErr.Error() + ">")
			}
			stderr, stderrErr := ioutil.ReadAll(stderrPipe)
			if stderrErr != nil {
				stderr = []byte("<error reading stderr: " + stderrErr.Error() + ">")
			}
			require.NoErrorf(t, err, "kubectl process did not exit cleanly, stdout/stderr: %q/%q", string(stdout), string(stderr))
		})

		// Start a background goroutine to read stderr from the CLI and parse out the login URL.
		loginURLChan := make(chan string)
		spawnTestGoroutine(t, func() (err error) {
			defer func() {
				closeErr := stderrPipe.Close()
				if closeErr == nil || errors.Is(closeErr, os.ErrClosed) {
					return
				}
				if err == nil {
					err = fmt.Errorf("stderr stream closed with error: %w", closeErr)
				}
			}()

			reader := bufio.NewReader(testlib.NewLoggerReader(t, "stderr", stderrPipe))
			line, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("could not read login URL line from stderr: %w", err)
			}
			const prompt = "Please log in: "
			if !strings.HasPrefix(line, prompt) {
				return fmt.Errorf("expected %q to have prefix %q", line, prompt)
			}
			loginURLChan <- strings.TrimPrefix(line, prompt)
			return readAndExpectEmpty(reader)
		})

		// Start a background goroutine to read stdout from kubectl and return the result as a string.
		kubectlOutputChan := make(chan string)
		spawnTestGoroutine(t, func() (err error) {
			defer func() {
				closeErr := stdoutPipe.Close()
				if closeErr == nil || errors.Is(closeErr, os.ErrClosed) {
					return
				}
				if err == nil {
					err = fmt.Errorf("stdout stream closed with error: %w", closeErr)
				}
			}()
			output, err := ioutil.ReadAll(stdoutPipe)
			if err != nil {
				return err
			}
			t.Logf("kubectl output:\n%s\n", output)
			kubectlOutputChan <- string(output)
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
		t.Logf("navigating to login page")
		require.NoError(t, page.Navigate(loginURL))

		// Expect to be redirected to the upstream provider and log in.
		browsertest.LoginToUpstream(t, page, env.SupervisorUpstreamOIDC)

		// Expect to be redirected to the localhost callback.
		t.Logf("waiting for redirect to callback")
		browsertest.WaitForURL(t, page, regexp.MustCompile(`\Ahttp://127\.0\.0\.1:[0-9]+/callback\?.+\z`))

		// Wait for the "pre" element that gets rendered for a `text/plain` page, and
		// assert that it contains the success message.
		t.Logf("verifying success page")
		browsertest.WaitForVisibleElements(t, page, "pre")
		msg, err := page.First("pre").Text()
		require.NoError(t, err)
		require.Equal(t, "you have been logged in and may now close this tab", msg)

		// Expect the CLI to output a list of namespaces in JSON format.
		t.Logf("waiting for kubectl to output namespace list JSON")
		var kubectlOutput string
		select {
		case <-time.After(10 * time.Second):
			require.Fail(t, "timed out waiting for kubectl output")
		case kubectlOutput = <-kubectlOutputChan:
		}
		require.Greaterf(t, len(strings.Split(kubectlOutput, "\n")), 2, "expected some namespaces to be returned, got %q", kubectlOutput)
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

	// Add an LDAP upstream IDP and try using it to authenticate during kubectl commands.
	t.Run("with Supervisor LDAP upstream IDP", func(t *testing.T) {
		if len(env.ToolsNamespace) == 0 && !env.HasCapability(testlib.CanReachInternetLDAPPorts) {
			t.Skip("LDAP integration test requires connectivity to an LDAP server")
		}

		expectedUsername := env.SupervisorUpstreamLDAP.TestUserMailAttributeValue
		expectedGroups := env.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs

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

		// Read all of the remaining output from the subprocess until EOF.
		remainingOutput, _ := ioutil.ReadAll(ptyFile)
		// Ignore any errors returned because there is always an error on linux.
		require.Greaterf(t, len(remainingOutput), 0, "expected to get some more output from the kubectl subcommand, but did not")
		require.Greaterf(t, len(strings.Split(string(remainingOutput), "\n")), 2, "expected some namespaces to be returned, got %q", string(remainingOutput))
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
}

func readFromFileUntilStringIsSeen(t *testing.T, f *os.File, until string) {
	readFromFile := ""

	testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
		someOutput, foundEOF := readAvailableOutput(t, f)
		readFromFile += someOutput
		if strings.Contains(readFromFile, until) {
			return true, nil // found it! finished.
		}
		if foundEOF {
			return false, fmt.Errorf("reached EOF of subcommand's output without seeing expected string %q", until)
		}
		return false, nil // keep waiting and reading
	}, 1*time.Minute, 1*time.Second)
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
