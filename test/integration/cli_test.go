// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	identityv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/identity/v1alpha1"
	conciergescheme "go.pinniped.dev/internal/concierge/scheme"
	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/filesession"
	"go.pinniped.dev/test/testlib"
	"go.pinniped.dev/test/testlib/browsertest"
)

// safe to run in parallel with serial tests since it only interacts with a test local webhook, see main_test.go.
func TestCLIGetKubeconfigStaticToken_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t).WithCapability(testlib.ClusterSigningKeyIsAvailable)

	// Create a test webhook configuration to use with the CLI.
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancelFunc()

	authenticator := testlib.CreateTestWebhookAuthenticator(ctx, t, &testlib.IntegrationEnv(t).TestWebhook, authenticationv1alpha1.WebhookAuthenticatorPhaseReady)

	// Build pinniped CLI.
	pinnipedExe := testlib.PinnipedCLIPath(t)

	credCacheDir := t.TempDir()
	stdout, stderr := runPinnipedCLI(t, nil, pinnipedExe, "get", "kubeconfig",
		"--static-token", env.TestUser.Token,
		"--concierge-api-group-suffix", env.APIGroupSuffix,
		"--concierge-authenticator-type", "webhook",
		"--concierge-authenticator-name", authenticator.Name,
		"--credential-cache", credCacheDir+"/credentials.yaml",
	)
	assert.Contains(t, stderr, "discovered CredentialIssuer")
	assert.Contains(t, stderr, "discovered Concierge endpoint")
	assert.Contains(t, stderr, "discovered Concierge certificate authority bundle")
	assert.Contains(t, stderr, "validated connection to the cluster")

	// Even the deprecated command should now generate a kubeconfig with the new "pinniped login static" command.
	restConfig := testlib.NewRestConfigFromKubeconfig(t, stdout)
	require.NotNil(t, restConfig.ExecProvider)
	require.Equal(t, []string{"login", "static"}, restConfig.ExecProvider.Args[:2])

	// In addition to the client-go based testing below, also try the kubeconfig
	// with kubectl to validate that it works.
	t.Run(
		"access as user with kubectl",
		testlib.AccessAsUserWithKubectlTest(stdout, env.TestUser.ExpectedUsername, env.ConciergeNamespace),
	)
	for _, group := range env.TestUser.ExpectedGroups {
		t.Run(
			"access as group "+group+" with kubectl",
			testlib.AccessAsGroupWithKubectlTest(stdout, group, env.ConciergeNamespace),
		)
	}

	// Create Kubernetes client with kubeconfig from pinniped CLI.
	kubeClient := testlib.NewClientsetForKubeConfig(t, stdout)

	// Validate that we can auth to the API via our user.
	t.Run("access as user with client-go", testlib.AccessAsUserTest(ctx, env.TestUser.ExpectedUsername, kubeClient))
	for _, group := range env.TestUser.ExpectedGroups {
		t.Run("access as group "+group+" with client-go", testlib.AccessAsGroupTest(ctx, group, kubeClient))
	}

	t.Run("whoami", func(t *testing.T) {
		// Validate that `pinniped whoami` returns the correct identity.
		kubeconfigPath := filepath.Join(t.TempDir(), "whoami-kubeconfig")
		require.NoError(t, os.WriteFile(kubeconfigPath, []byte(stdout), 0600))
		assertWhoami(
			ctx,
			t,
			false,
			pinnipedExe,
			kubeconfigPath,
			env.TestUser.ExpectedUsername,
			append(env.TestUser.ExpectedGroups, "system:authenticated"),
		)
	})
}

type testingT interface {
	Helper()
	Errorf(format string, args ...any)
	FailNow()
	Logf(format string, args ...any)
}

func runPinnipedCLI(t testingT, envVars []string, pinnipedExe string, args ...string) (string, string) {
	t.Helper()
	start := time.Now()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(pinnipedExe, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = envVars
	require.NoErrorf(t, cmd.Run(), "stderr:\n%s\n\nstdout:\n%s\n\n", stderr.String(), stdout.String())
	t.Logf("ran %q in %s", testlib.MaskTokens("pinniped "+strings.Join(args, " ")), time.Since(start).Round(time.Millisecond))
	return stdout.String(), stderr.String()
}

func assertWhoami(ctx context.Context, t *testing.T, useProxy bool, pinnipedExe, kubeconfigPath, wantUsername string, wantGroups []string) {
	t.Helper()

	apiGroupSuffix := testlib.IntegrationEnv(t).APIGroupSuffix

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(
		ctx,
		pinnipedExe,
		"whoami",
		"--kubeconfig",
		kubeconfigPath,
		"--output",
		"yaml",
		"--api-group-suffix",
		apiGroupSuffix,
	)
	if useProxy {
		cmd.Env = slices.Concat(os.Environ(), testlib.IntegrationEnv(t).ProxyEnv())
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	require.NoErrorf(t, cmd.Run(), "stderr:\n%s\n\nstdout:\n%s\n\n", stderr.String(), stdout.String())

	whoAmI := deserializeWhoAmIRequest(t, stdout.String(), apiGroupSuffix)
	require.Equal(t, wantUsername, whoAmI.Status.KubernetesUserInfo.User.Username)
	require.ElementsMatch(t, wantGroups, whoAmI.Status.KubernetesUserInfo.User.Groups)
}

func deserializeWhoAmIRequest(t *testing.T, data string, apiGroupSuffix string) *identityv1alpha1.WhoAmIRequest {
	t.Helper()

	scheme, _, _ := conciergescheme.New(apiGroupSuffix)
	codecs := serializer.NewCodecFactory(scheme)
	respInfo, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), runtime.ContentTypeYAML)
	require.True(t, ok)

	obj, err := runtime.Decode(respInfo.Serializer, []byte(data))
	require.NoError(t, err)

	return obj.(*identityv1alpha1.WhoAmIRequest)
}

func TestCLILoginOIDC_Browser(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	// Build pinniped CLI.
	pinnipedExe := testlib.PinnipedCLIPath(t)

	// Run "pinniped login oidc" to get an ExecCredential struct with an OIDC ID token.
	credOutput, sessionCachePath := runPinnipedLoginOIDC(ctx, t, pinnipedExe)

	// Assert some properties of the ExecCredential.
	t.Logf("validating ExecCredential")
	require.NotNil(t, credOutput.Status)
	require.Empty(t, credOutput.Status.ClientKeyData)
	require.Empty(t, credOutput.Status.ClientCertificateData)

	// There should be at least 1 minute of remaining expiration (probably more).
	require.NotNil(t, credOutput.Status.ExpirationTimestamp)
	ttl := time.Until(credOutput.Status.ExpirationTimestamp.Time)
	require.Greater(t, ttl.Milliseconds(), (1 * time.Minute).Milliseconds())

	// Assert some properties about the token, which should be a valid JWT.
	require.NotEmpty(t, credOutput.Status.Token)
	jws, err := jose.ParseSigned(credOutput.Status.Token, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	require.NoError(t, err)
	claims := map[string]any{}
	require.NoError(t, json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claims))
	require.Equal(t, env.CLIUpstreamOIDC.Issuer, claims["iss"])
	require.Equal(t, env.CLIUpstreamOIDC.ClientID, claims["aud"])
	require.Equal(t, env.CLIUpstreamOIDC.Username, claims["email"])
	require.NotEmpty(t, claims["nonce"])

	// Run the CLI again with the same session cache and login parameters.
	t.Logf("starting second CLI subprocess to test session caching")
	cmd2Output, err := oidcLoginCommand(ctx, t, pinnipedExe, sessionCachePath).CombinedOutput()
	require.NoError(t, err, string(cmd2Output))

	// Expect the CLI to output the same ExecCredential in JSON format.
	t.Logf("validating second ExecCredential")
	var credOutput2 clientauthenticationv1beta1.ExecCredential
	require.NoErrorf(t, json.Unmarshal(cmd2Output, &credOutput2),
		"command returned something other than an ExecCredential:\n%s", string(cmd2Output))
	require.Equal(t, credOutput, credOutput2)
	// the logs contain only the ExecCredential. There are 2 elements because the last one is "".
	require.Len(t, strings.Split(string(cmd2Output), "\n"), 2)

	// Overwrite the cache entry to remove the access and ID tokens.
	t.Logf("overwriting cache to remove valid ID token")
	cache := filesession.New(sessionCachePath)
	cacheKey := oidcclient.SessionCacheKey{
		Issuer:      env.CLIUpstreamOIDC.Issuer,
		ClientID:    env.CLIUpstreamOIDC.ClientID,
		Scopes:      []string{"email", "offline_access", "openid", "profile"},
		RedirectURI: strings.ReplaceAll(env.CLIUpstreamOIDC.CallbackURL, "127.0.0.1", "localhost"),
	}
	cached := cache.GetToken(cacheKey)
	require.NotNil(t, cached)
	require.NotNil(t, cached.RefreshToken)
	require.NotEmpty(t, cached.RefreshToken.Token)
	cached.IDToken = nil
	cached.AccessToken = nil
	cache.PutToken(cacheKey, cached)

	// Run the CLI a third time with the same session cache and login parameters.
	t.Logf("starting third CLI subprocess to test refresh flow")
	cmd3Output, err := oidcLoginCommand(ctx, t, pinnipedExe, sessionCachePath).CombinedOutput()
	require.NoError(t, err, string(cmd2Output))

	// Expect the CLI to output a new ExecCredential in JSON format (different from the one returned the first two times).
	t.Logf("validating third ExecCredential")
	var credOutput3 clientauthenticationv1beta1.ExecCredential
	require.NoErrorf(t, json.Unmarshal(cmd3Output, &credOutput3),
		"command returned something other than an ExecCredential:\n%s", string(cmd2Output))
	require.NotEqual(t, credOutput2.Status.Token, credOutput3.Status.Token)
	// the logs contain only the ExecCredential. There are 2 elements because the last one is "".
	require.Len(t, strings.Split(string(cmd3Output), "\n"), 2)

	t.Logf("starting fourth CLI subprocess to test debug logging")
	err = os.Setenv("PINNIPED_DEBUG", "true")
	require.NoError(t, err)
	command := oidcLoginCommand(ctx, t, pinnipedExe, sessionCachePath)
	cmd4CombinedOutput, err := command.CombinedOutput()
	cmd4StringOutput := string(cmd4CombinedOutput)
	require.NoError(t, err, cmd4StringOutput)

	// the logs contain only the 4 debug lines plus the ExecCredential. There are 6 elements because the last one is "".
	require.Len(t, strings.Split(cmd4StringOutput, "\n"), 6)
	require.Contains(t, cmd4StringOutput, "Performing OIDC login")
	require.Contains(t, cmd4StringOutput, "Found unexpired cached token")
	require.Contains(t, cmd4StringOutput, "No concierge configured, skipping token credential exchange")
	require.Contains(t, cmd4StringOutput, "caching cluster credential for future use.")
	require.Contains(t, cmd4StringOutput, credOutput3.Status.Token)
	err = os.Unsetenv("PINNIPED_DEBUG")
	require.NoError(t, err)
}

func runPinnipedLoginOIDC(
	ctx context.Context,
	t *testing.T,
	pinnipedExe string,
) (clientauthenticationv1beta1.ExecCredential, string) {
	t.Helper()

	env := testlib.IntegrationEnv(t)

	// Make a temp directory to hold the session cache for this test.
	sessionCachePath := t.TempDir() + "/sessions.yaml"

	// Start the browser driver.
	browser := browsertest.OpenBrowser(t)

	// Start the CLI running the "login oidc [...]" command with stdout/stderr connected to pipes.
	cmd := oidcLoginCommand(ctx, t, pinnipedExe, sessionCachePath)
	stderr, err := cmd.StderrPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	t.Logf("starting CLI subprocess")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		err := cmd.Wait() // handles closing of file descriptors
		t.Logf("CLI subprocess exited with code %d", cmd.ProcessState.ExitCode())
		require.NoErrorf(t, err, "CLI process did not exit cleanly")
	})

	// Start a background goroutine to read stderr from the CLI and parse out the login URL.
	loginURLChan := make(chan string, 1)
	spawnTestGoroutine(ctx, t, func() error {
		reader := bufio.NewReader(testlib.NewLoggerReader(t, "stderr", stderr))

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

	// Start a background goroutine to read stdout from the CLI and parse out an ExecCredential.
	credOutputChan := make(chan clientauthenticationv1beta1.ExecCredential, 1)
	spawnTestGoroutine(ctx, t, func() error {
		reader := bufio.NewReader(testlib.NewLoggerReader(t, "stdout", stdout))
		var out clientauthenticationv1beta1.ExecCredential
		if err := json.NewDecoder(reader).Decode(&out); err != nil {
			return fmt.Errorf("could not read ExecCredential from stdout: %w", err)
		}
		credOutputChan <- out // this channel is buffered so this will not block
		return readAndExpectEmpty(reader)
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
	browser.Navigate(t, loginURL)

	// Expect to be redirected to the upstream provider and log in.
	browsertest.LoginToUpstreamOIDC(t, browser, env.CLIUpstreamOIDC)

	// Expect to be redirected to the localhost callback.
	t.Logf("waiting for redirect to callback")
	callbackURLPattern := regexp.MustCompile(`\A` + regexp.QuoteMeta(env.CLIUpstreamOIDC.CallbackURL) + `(\?.+)?\z`)
	browser.WaitForURL(t, callbackURLPattern)

	// Wait for the "pre" element that gets rendered for a `text/plain` page, and
	// assert that it contains the success message.
	t.Logf("verifying success page")
	browser.WaitForVisibleElements(t, "pre")
	msg := browser.TextOfFirstMatch(t, "pre")
	require.Equal(t, "you have been logged in and may now close this tab", msg)

	// Expect the CLI to output an ExecCredential in JSON format.
	t.Logf("waiting for CLI to output ExecCredential JSON")
	var credOutput clientauthenticationv1beta1.ExecCredential
	select {
	case <-time.After(10 * time.Second):
		require.Fail(t, "timed out waiting for exec credential output")
	case credOutput = <-credOutputChan:
	}

	return credOutput, sessionCachePath
}

func readAndExpectEmpty(r io.Reader) (err error) {
	var remainder bytes.Buffer
	_, err = io.Copy(&remainder, r)
	if err != nil {
		return err
	}
	if r := remainder.String(); r != "" {
		return fmt.Errorf("expected remainder to be empty, but got %q", r)
	}
	return nil
}

// Note: Callers should ensure that f eventually returns, otherwise this helper will leak a go routine.
func spawnTestGoroutine(ctx context.Context, t *testing.T, f func() error) {
	t.Helper()

	var eg errgroup.Group
	t.Cleanup(func() {
		egCh := make(chan error, 1) // do not block the go routine from exiting even after the select has completed
		go func() {
			egCh <- eg.Wait()
		}()

		leewayCh := make(chan struct{})
		go func() {
			<-ctx.Done()
			// give f up to 30 seconds after the context is canceled to return
			// this prevents "race" conditions where f is orchestrated via the same context
			time.Sleep(30 * time.Second)
			close(leewayCh)
		}()

		select {
		case <-leewayCh:
			t.Errorf("background goroutine hung: %v", ctx.Err())

		case err := <-egCh:
			require.NoError(t, err, "background goroutine failed")
		}
	})
	eg.Go(f)
}

func oidcLoginCommand(ctx context.Context, t *testing.T, pinnipedExe string, sessionCachePath string) *exec.Cmd {
	env := testlib.IntegrationEnv(t)
	callbackURL, err := url.Parse(env.CLIUpstreamOIDC.CallbackURL)
	require.NoError(t, err)
	//nolint:gosec // not worried about these potentially tainted inputs
	cmd := exec.CommandContext(ctx, pinnipedExe, "login", "oidc",
		"--issuer", env.CLIUpstreamOIDC.Issuer,
		"--client-id", env.CLIUpstreamOIDC.ClientID,
		"--scopes", "offline_access,openid,email,profile",
		"--listen-port", callbackURL.Port(),
		"--session-cache", sessionCachePath,
		"--credential-cache", t.TempDir()+"/credentials.yaml",
		"--skip-browser",
	)

	// If there is a custom CA bundle, pass it via --ca-bundle and a temporary file.
	if env.CLIUpstreamOIDC.CABundle != "" {
		path := filepath.Join(t.TempDir(), "test-ca.pem")
		require.NoError(t, os.WriteFile(path, []byte(env.CLIUpstreamOIDC.CABundle), 0600))
		cmd.Args = append(cmd.Args, "--ca-bundle", path)
	}

	// If there is a custom proxy, set it using standard environment variables.
	cmd.Env = slices.Concat(os.Environ(), env.ProxyEnv())
	return cmd
}
