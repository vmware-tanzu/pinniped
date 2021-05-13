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

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
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
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/filesession"
	"go.pinniped.dev/test/library"
	"go.pinniped.dev/test/library/browsertest"
)

// TestE2EFullIntegration tests a full integration scenario that combines the supervisor, concierge, and CLI.
func TestE2EFullIntegration(t *testing.T) {
	env := library.IntegrationEnv(t)

	ctx, cancelFunc := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancelFunc()

	// Build pinniped CLI.
	pinnipedExe := library.PinnipedCLIPath(t)
	tempDir := testutil.TempDir(t)

	// Start the browser driver.
	page := browsertest.Open(t)

	// Infer the downstream issuer URL from the callback associated with the upstream test client registration.
	issuerURL, err := url.Parse(env.SupervisorTestUpstream.CallbackURL)
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
	testCABundlePEM := []byte(string(ca.Bundle()) + "\n" + env.SupervisorTestUpstream.CABundle)
	testCABundleBase64 := base64.StdEncoding.EncodeToString(testCABundlePEM)
	require.NoError(t, ioutil.WriteFile(testCABundlePath, testCABundlePEM, 0600))

	// Use the CA to issue a TLS server cert.
	t.Logf("issuing test certificate")
	tlsCert, err := ca.IssueServerCert([]string{issuerURL.Hostname()}, nil, 1*time.Hour)
	require.NoError(t, err)
	certPEM, keyPEM, err := certauthority.ToPEM(tlsCert)
	require.NoError(t, err)

	// Write the serving cert to a secret.
	certSecret := library.CreateTestSecret(t,
		env.SupervisorNamespace,
		"oidc-provider-tls",
		corev1.SecretTypeTLS,
		map[string]string{"tls.crt": string(certPEM), "tls.key": string(keyPEM)},
	)

	// Create the downstream FederationDomain and expect it to go into the success status condition.
	downstream := library.CreateTestFederationDomain(ctx, t,
		issuerURL.String(),
		certSecret.Name,
		configv1alpha1.SuccessFederationDomainStatusCondition,
	)

	// Create upstream OIDC provider and wait for it to become ready.
	library.CreateTestOIDCIdentityProvider(t, idpv1alpha1.OIDCIdentityProviderSpec{
		Issuer: env.SupervisorTestUpstream.Issuer,
		TLS: &idpv1alpha1.TLSSpec{
			CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(env.SupervisorTestUpstream.CABundle)),
		},
		AuthorizationConfig: idpv1alpha1.OIDCAuthorizationConfig{
			AdditionalScopes: env.SupervisorTestUpstream.AdditionalScopes,
		},
		Claims: idpv1alpha1.OIDCClaims{
			Username: env.SupervisorTestUpstream.UsernameClaim,
			Groups:   env.SupervisorTestUpstream.GroupsClaim,
		},
		Client: idpv1alpha1.OIDCClient{
			SecretName: library.CreateClientCredsSecret(t, env.SupervisorTestUpstream.ClientID, env.SupervisorTestUpstream.ClientSecret).Name,
		},
	}, idpv1alpha1.PhaseReady)

	// Create a JWTAuthenticator that will validate the tokens from the downstream issuer.
	clusterAudience := "test-cluster-" + library.RandHex(t, 8)
	authenticator := library.CreateTestJWTAuthenticator(ctx, t, authv1alpha.JWTAuthenticatorSpec{
		Issuer:   downstream.Spec.Issuer,
		Audience: clusterAudience,
		TLS:      &authv1alpha.TLSSpec{CertificateAuthorityData: testCABundleBase64},
	})

	// Create a ClusterRoleBinding to give our test user from the upstream read-only access to the cluster.
	library.CreateTestClusterRoleBinding(t,
		rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: env.SupervisorTestUpstream.Username},
		rbacv1.RoleRef{Kind: "ClusterRole", APIGroup: rbacv1.GroupName, Name: "view"},
	)
	library.WaitForUserToHaveAccess(t, env.SupervisorTestUpstream.Username, []string{}, &authorizationv1.ResourceAttributes{
		Verb:     "get",
		Group:    "",
		Version:  "v1",
		Resource: "namespaces",
	})

	// Use a specific session cache for this test.
	sessionCachePath := tempDir + "/sessions.yaml"

	// Run "pinniped get kubeconfig" to get a kubeconfig YAML.
	kubeconfigYAML, stderr := runPinnipedCLI(t, nil, pinnipedExe, "get", "kubeconfig",
		"--concierge-api-group-suffix", env.APIGroupSuffix,
		"--concierge-authenticator-type", "jwt",
		"--concierge-authenticator-name", authenticator.Name,
		"--oidc-skip-browser",
		"--oidc-ca-bundle", testCABundlePath,
		"--oidc-session-cache", sessionCachePath,
	)
	t.Logf("stderr output from 'pinniped get kubeconfig':\n%s\n\n", stderr)
	t.Logf("test kubeconfig:\n%s\n\n", kubeconfigYAML)

	restConfig := library.NewRestConfigFromKubeconfig(t, kubeconfigYAML)
	require.NotNil(t, restConfig.ExecProvider)
	require.Equal(t, []string{"login", "oidc"}, restConfig.ExecProvider.Args[:2])
	kubeconfigPath := filepath.Join(tempDir, "kubeconfig.yaml")
	require.NoError(t, ioutil.WriteFile(kubeconfigPath, []byte(kubeconfigYAML), 0600))

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

		reader := bufio.NewReader(library.NewLoggerReader(t, "stderr", stderrPipe))
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
	browsertest.LoginToUpstream(t, page, env.SupervisorTestUpstream)

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

	// 	Run kubectl again, which should work with no browser interaction.
	kubectlCmd2 := exec.CommandContext(ctx, "kubectl", "get", "namespace", "--kubeconfig", kubeconfigPath)
	kubectlCmd2.Env = append(os.Environ(), env.ProxyEnv()...)
	start = time.Now()
	kubectlOutput2, err := kubectlCmd2.CombinedOutput()
	require.NoError(t, err)
	require.Greaterf(t, len(bytes.Split(kubectlOutput2, []byte("\n"))), 2, "expected some namespaces to be returned again")
	t.Logf("second kubectl command took %s", time.Since(start).String())

	// probe our cache for the current ID token as a proxy for a whoami API
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

	// check that the access token is new (since it's just been refreshed) and has close to two minutes left.
	testutil.RequireTimeInDelta(t, start.Add(2*time.Minute), token.AccessToken.Expiry.Time, 15*time.Second)

	kubeClient := library.NewKubernetesClientset(t).CoreV1()

	// get the access token secret that matches the signature from the cache
	accessTokenSignature := strings.Split(token.AccessToken.Token, ".")[1]
	accessSecretName := getSecretNameFromSignature(t, accessTokenSignature, "access-token")
	accessTokenSecret, err := kubeClient.Secrets(env.SupervisorNamespace).Get(ctx, accessSecretName, metav1.GetOptions{})
	require.NoError(t, err)

	// Check that the access token garbage-collect-after value is 9 hours from now
	accessTokenGCTimeString := accessTokenSecret.Annotations["storage.pinniped.dev/garbage-collect-after"]
	accessTokenGCTime, err := time.Parse(crud.SecretLifetimeAnnotationDateFormat, accessTokenGCTimeString)
	require.NoError(t, err)
	require.True(t, accessTokenGCTime.After(time.Now().Add(9*time.Hour)))

	// get the refresh token secret that matches the signature from the cache
	refreshTokenSignature := strings.Split(token.RefreshToken.Token, ".")[1]
	refreshSecretName := getSecretNameFromSignature(t, refreshTokenSignature, "refresh-token")
	refreshTokenSecret, err := kubeClient.Secrets(env.SupervisorNamespace).Get(ctx, refreshSecretName, metav1.GetOptions{})
	require.NoError(t, err)

	// Check that the refresh token garbage-collect-after value is 9 hours
	refreshTokenGCTimeString := refreshTokenSecret.Annotations["storage.pinniped.dev/garbage-collect-after"]
	refreshTokenGCTime, err := time.Parse(crud.SecretLifetimeAnnotationDateFormat, refreshTokenGCTimeString)
	require.NoError(t, err)
	require.True(t, refreshTokenGCTime.After(time.Now().Add(9*time.Hour)))

	// the access token and the refresh token should be garbage collected at essentially the same time
	testutil.RequireTimeInDelta(t, accessTokenGCTime, refreshTokenGCTime, 1*time.Minute)

	idTokenClaims := token.IDToken.Claims
	require.Equal(t, env.SupervisorTestUpstream.Username, idTokenClaims[oidc.DownstreamUsernameClaim])

	// The groups claim in the file ends up as an []interface{}, so adjust our expectation to match.
	expectedGroups := make([]interface{}, 0, len(env.SupervisorTestUpstream.ExpectedGroups))
	for _, g := range env.SupervisorTestUpstream.ExpectedGroups {
		expectedGroups = append(expectedGroups, g)
	}
	require.Equal(t, expectedGroups, idTokenClaims[oidc.DownstreamGroupsClaim])

	// confirm we are the right user according to Kube
	expectedYAMLGroups := func() string {
		var b strings.Builder
		for _, g := range env.SupervisorTestUpstream.ExpectedGroups {
			b.WriteString("\n")
			b.WriteString(`      - `)
			b.WriteString(g)
		}
		return b.String()
	}()
	kubectlCmd3 := exec.CommandContext(ctx, "kubectl", "create", "-f", "-", "-o", "yaml", "--kubeconfig", kubeconfigPath)
	kubectlCmd3.Env = append(os.Environ(), env.ProxyEnv()...)
	kubectlCmd3.Stdin = strings.NewReader(`
apiVersion: identity.concierge.` + env.APIGroupSuffix + `/v1alpha1
kind: WhoAmIRequest
`)
	kubectlOutput3, err := kubectlCmd3.CombinedOutput()
	require.NoError(t, err)
	require.Equal(t,
		`apiVersion: identity.concierge.`+env.APIGroupSuffix+`/v1alpha1
kind: WhoAmIRequest
metadata:
  creationTimestamp: null
spec: {}
status:
  kubernetesUserInfo:
    user:
      groups:`+expectedYAMLGroups+`
      - system:authenticated
      username: `+env.SupervisorTestUpstream.Username+`
`,
		string(kubectlOutput3))

	// Validate that `pinniped whoami` returns the correct identity.
	assertWhoami(
		ctx,
		t,
		true,
		pinnipedExe,
		kubeconfigPath,
		env.SupervisorTestUpstream.Username,
		append(env.SupervisorTestUpstream.ExpectedGroups, "system:authenticated"),
	)
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
