// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gopkg.in/square/go-jose.v2"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/filesession"
	"go.pinniped.dev/test/library"
	"go.pinniped.dev/test/library/browsertest"
)

func TestCLIGetKubeconfigStaticToken(t *testing.T) {
	env := library.IntegrationEnv(t).WithCapability(library.ClusterSigningKeyIsAvailable)

	// Create a test webhook configuration to use with the CLI.
	ctx, cancelFunc := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancelFunc()

	authenticator := library.CreateTestWebhookAuthenticator(ctx, t)

	// Build pinniped CLI.
	pinnipedExe := library.PinnipedCLIPath(t)

	for _, tt := range []struct {
		name         string
		args         []string
		expectStderr string
	}{
		{
			name: "deprecated command",
			args: []string{
				"get-kubeconfig",
				"--token", env.TestUser.Token,
				"--pinniped-namespace", env.ConciergeNamespace,
				"--authenticator-type", "webhook",
				"--authenticator-name", authenticator.Name,
				"--api-group-suffix", env.APIGroupSuffix,
			},
			expectStderr: "Command \"get-kubeconfig\" is deprecated, Please use `pinniped get kubeconfig` instead.\n",
		},
		{
			name: "newer command, but still using static parameters",
			args: []string{
				"get", "kubeconfig",
				"--static-token", env.TestUser.Token,
				"--concierge-api-group-suffix", env.APIGroupSuffix,
				"--concierge-namespace", env.ConciergeNamespace,
				"--concierge-authenticator-type", "webhook",
				"--concierge-authenticator-name", authenticator.Name,
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr := runPinnipedCLI(t, pinnipedExe, tt.args...)
			require.Equal(t, tt.expectStderr, stderr)

			// Even the deprecated command should now generate a kubeconfig with the new "pinniped login static" command.
			restConfig := library.NewRestConfigFromKubeconfig(t, stdout)
			require.NotNil(t, restConfig.ExecProvider)
			require.Equal(t, []string{"login", "static"}, restConfig.ExecProvider.Args[:2])

			// In addition to the client-go based testing below, also try the kubeconfig
			// with kubectl to validate that it works.
			t.Run(
				"access as user with kubectl",
				library.AccessAsUserWithKubectlTest(stdout, env.TestUser.ExpectedUsername, env.ConciergeNamespace),
			)
			for _, group := range env.TestUser.ExpectedGroups {
				group := group
				t.Run(
					"access as group "+group+" with kubectl",
					library.AccessAsGroupWithKubectlTest(stdout, group, env.ConciergeNamespace),
				)
			}

			// Create Kubernetes client with kubeconfig from pinniped CLI.
			kubeClient := library.NewClientsetForKubeConfig(t, stdout)

			// Validate that we can auth to the API via our user.
			t.Run("access as user with client-go", library.AccessAsUserTest(ctx, env.TestUser.ExpectedUsername, kubeClient))
			for _, group := range env.TestUser.ExpectedGroups {
				group := group
				t.Run("access as group "+group+" with client-go", library.AccessAsGroupTest(ctx, group, kubeClient))
			}
		})
	}
}

func runPinnipedCLI(t *testing.T, pinnipedExe string, args ...string) (string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(pinnipedExe, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	require.NoErrorf(t, cmd.Run(), "stderr:\n%s\n\nstdout:\n%s\n\n", stderr.String(), stdout.String())
	return stdout.String(), stderr.String()
}

func TestCLILoginOIDC(t *testing.T) {
	env := library.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Build pinniped CLI.
	pinnipedExe := library.PinnipedCLIPath(t)

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
	jws, err := jose.ParseSigned(credOutput.Status.Token)
	require.NoError(t, err)
	claims := map[string]interface{}{}
	require.NoError(t, json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claims))
	require.Equal(t, env.CLITestUpstream.Issuer, claims["iss"])
	require.Equal(t, env.CLITestUpstream.ClientID, claims["aud"])
	require.Equal(t, env.CLITestUpstream.Username, claims["email"])
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

	// Overwrite the cache entry to remove the access and ID tokens.
	t.Logf("overwriting cache to remove valid ID token")
	cache := filesession.New(sessionCachePath)
	cacheKey := oidcclient.SessionCacheKey{
		Issuer:      env.CLITestUpstream.Issuer,
		ClientID:    env.CLITestUpstream.ClientID,
		Scopes:      []string{"email", "offline_access", "openid", "profile"},
		RedirectURI: strings.ReplaceAll(env.CLITestUpstream.CallbackURL, "127.0.0.1", "localhost"),
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
}

func runPinnipedLoginOIDC(
	ctx context.Context,
	t *testing.T,
	pinnipedExe string,
) (clientauthenticationv1beta1.ExecCredential, string) {
	t.Helper()

	env := library.IntegrationEnv(t)

	// Make a temp directory to hold the session cache for this test.
	sessionCachePath := testutil.TempDir(t) + "/sessions.yaml"

	// Start the browser driver.
	page := browsertest.Open(t)

	// Start the CLI running the "login oidc [...]" command with stdout/stderr connected to pipes.
	cmd := oidcLoginCommand(ctx, t, pinnipedExe, sessionCachePath)
	stderr, err := cmd.StderrPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	t.Logf("starting CLI subprocess")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		err := cmd.Wait()
		t.Logf("CLI subprocess exited with code %d", cmd.ProcessState.ExitCode())
		require.NoErrorf(t, err, "CLI process did not exit cleanly")
	})

	// Start a background goroutine to read stderr from the CLI and parse out the login URL.
	loginURLChan := make(chan string)
	spawnTestGoroutine(t, func() (err error) {
		defer func() {
			closeErr := stderr.Close()
			if closeErr == nil || errors.Is(closeErr, os.ErrClosed) {
				return
			}
			if err == nil {
				err = fmt.Errorf("stderr stream closed with error: %w", closeErr)
			}
		}()

		reader := bufio.NewReader(library.NewLoggerReader(t, "stderr", stderr))
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

	// Start a background goroutine to read stdout from the CLI and parse out an ExecCredential.
	credOutputChan := make(chan clientauthenticationv1beta1.ExecCredential)
	spawnTestGoroutine(t, func() (err error) {
		defer func() {
			closeErr := stdout.Close()
			if closeErr == nil || errors.Is(closeErr, os.ErrClosed) {
				return
			}
			if err == nil {
				err = fmt.Errorf("stdout stream closed with error: %w", closeErr)
			}
		}()
		reader := bufio.NewReader(library.NewLoggerReader(t, "stdout", stdout))
		var out clientauthenticationv1beta1.ExecCredential
		if err := json.NewDecoder(reader).Decode(&out); err != nil {
			return fmt.Errorf("could not read ExecCredential from stdout: %w", err)
		}
		credOutputChan <- out
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
	require.NoError(t, page.Navigate(loginURL))

	// Expect to be redirected to the upstream provider and log in.
	browsertest.LoginToUpstream(t, page, env.CLITestUpstream)

	// Expect to be redirected to the localhost callback.
	t.Logf("waiting for redirect to callback")
	callbackURLPattern := regexp.MustCompile(`\A` + regexp.QuoteMeta(env.CLITestUpstream.CallbackURL) + `\?.+\z`)
	browsertest.WaitForURL(t, page, callbackURLPattern)

	// Wait for the "pre" element that gets rendered for a `text/plain` page, and
	// assert that it contains the success message.
	t.Logf("verifying success page")
	browsertest.WaitForVisibleElements(t, page, "pre")
	msg, err := page.First("pre").Text()
	require.NoError(t, err)
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

func spawnTestGoroutine(t *testing.T, f func() error) {
	t.Helper()
	var eg errgroup.Group
	t.Cleanup(func() {
		require.NoError(t, eg.Wait(), "background goroutine failed")
	})
	eg.Go(f)
}

func oidcLoginCommand(ctx context.Context, t *testing.T, pinnipedExe string, sessionCachePath string) *exec.Cmd {
	env := library.IntegrationEnv(t)
	callbackURL, err := url.Parse(env.CLITestUpstream.CallbackURL)
	require.NoError(t, err)
	cmd := exec.CommandContext(ctx, pinnipedExe, "login", "oidc",
		"--issuer", env.CLITestUpstream.Issuer,
		"--client-id", env.CLITestUpstream.ClientID,
		"--scopes", "offline_access,openid,email,profile",
		"--listen-port", callbackURL.Port(),
		"--session-cache", sessionCachePath,
		"--skip-browser",
	)

	// If there is a custom CA bundle, pass it via --ca-bundle and a temporary file.
	if env.CLITestUpstream.CABundle != "" {
		path := filepath.Join(testutil.TempDir(t), "test-ca.pem")
		require.NoError(t, ioutil.WriteFile(path, []byte(env.CLITestUpstream.CABundle), 0600))
		cmd.Args = append(cmd.Args, "--ca-bundle", path)
	}

	// If there is a custom proxy, set it using standard environment variables.
	cmd.Env = append(os.Environ(), env.ProxyEnv()...)
	return cmd
}
