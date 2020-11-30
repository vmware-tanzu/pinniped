// Copyright 2020 the Pinniped contributors. All Rights Reserved.
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

	"github.com/sclevine/agouti"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gopkg.in/square/go-jose.v2"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/filesession"
	"go.pinniped.dev/test/library"
)

func TestCLIGetKubeconfig(t *testing.T) {
	env := library.IntegrationEnv(t).WithCapability(library.ClusterSigningKeyIsAvailable)

	// Create a test webhook configuration to use with the CLI.
	ctx, cancelFunc := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancelFunc()

	authenticator := library.CreateTestWebhookAuthenticator(ctx, t)

	// Build pinniped CLI.
	pinnipedExe := buildPinnipedCLI(t)

	// Run pinniped CLI to get kubeconfig.
	kubeConfigYAML := runPinnipedCLIGetKubeconfig(t, pinnipedExe, env.TestUser.Token, env.ConciergeNamespace, "webhook", authenticator.Name)

	// In addition to the client-go based testing below, also try the kubeconfig
	// with kubectl to validate that it works.
	adminClient := library.NewClientset(t)
	t.Run(
		"access as user with kubectl",
		library.AccessAsUserWithKubectlTest(ctx, adminClient, kubeConfigYAML, env.TestUser.ExpectedUsername, env.ConciergeNamespace),
	)
	for _, group := range env.TestUser.ExpectedGroups {
		group := group
		t.Run(
			"access as group "+group+" with kubectl",
			library.AccessAsGroupWithKubectlTest(ctx, adminClient, kubeConfigYAML, group, env.ConciergeNamespace),
		)
	}

	// Create Kubernetes client with kubeconfig from pinniped CLI.
	kubeClient := library.NewClientsetForKubeConfig(t, kubeConfigYAML)

	// Validate that we can auth to the API via our user.
	t.Run("access as user with client-go", library.AccessAsUserTest(ctx, adminClient, env.TestUser.ExpectedUsername, kubeClient))
	for _, group := range env.TestUser.ExpectedGroups {
		group := group
		t.Run("access as group "+group+" with client-go", library.AccessAsGroupTest(ctx, adminClient, group, kubeClient))
	}
}

func buildPinnipedCLI(t *testing.T) string {
	t.Helper()

	pinnipedExeDir, err := ioutil.TempDir("", "pinniped-cli-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(pinnipedExeDir)) })

	pinnipedExe := filepath.Join(pinnipedExeDir, "pinniped")
	output, err := exec.Command(
		"go",
		"build",
		"-o",
		pinnipedExe,
		"go.pinniped.dev/cmd/pinniped",
	).CombinedOutput()
	require.NoError(t, err, string(output))
	return pinnipedExe
}

func runPinnipedCLIGetKubeconfig(t *testing.T, pinnipedExe, token, namespaceName, authenticatorType, authenticatorName string) string {
	t.Helper()

	output, err := exec.Command(
		pinnipedExe,
		"get-kubeconfig",
		"--token", token,
		"--pinniped-namespace", namespaceName,
		"--authenticator-type", authenticatorType,
		"--authenticator-name", authenticatorName,
	).CombinedOutput()
	require.NoError(t, err, string(output))

	return string(output)
}

type loginProviderPatterns struct {
	Name                string
	IssuerPattern       *regexp.Regexp
	LoginPagePattern    *regexp.Regexp
	UsernameSelector    string
	PasswordSelector    string
	LoginButtonSelector string
}

func getLoginProvider(t *testing.T) *loginProviderPatterns {
	t.Helper()
	issuer := library.IntegrationEnv(t).CLITestUpstream.Issuer
	for _, p := range []loginProviderPatterns{
		{
			Name:                "Okta",
			IssuerPattern:       regexp.MustCompile(`\Ahttps://.+\.okta\.com/.+\z`),
			LoginPagePattern:    regexp.MustCompile(`\Ahttps://.+\.okta\.com/.+\z`),
			UsernameSelector:    "input#okta-signin-username",
			PasswordSelector:    "input#okta-signin-password",
			LoginButtonSelector: "input#okta-signin-submit",
		},
		{
			Name:                "Dex",
			IssuerPattern:       regexp.MustCompile(`\Ahttps://dex\.dex\.svc\.cluster\.local/dex.*\z`),
			LoginPagePattern:    regexp.MustCompile(`\Ahttps://dex\.dex\.svc\.cluster\.local/dex/auth/local.+\z`),
			UsernameSelector:    "input#login",
			PasswordSelector:    "input#password",
			LoginButtonSelector: "button#submit-login",
		},
	} {
		if p.IssuerPattern.MatchString(issuer) {
			return &p
		}
	}
	require.Failf(t, "could not find login provider for issuer %q", issuer)
	return nil
}

func TestCLILoginOIDC(t *testing.T) {
	env := library.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Find the login CSS selectors for the test issuer, or fail fast.
	loginProvider := getLoginProvider(t)

	// Start the browser driver.
	t.Logf("opening browser driver")
	caps := agouti.NewCapabilities()
	if env.Proxy != "" {
		t.Logf("configuring Chrome to use proxy %q", env.Proxy)
		caps = caps.Proxy(agouti.ProxyConfig{
			ProxyType: "manual",
			HTTPProxy: env.Proxy,
			SSLProxy:  env.Proxy,
			NoProxy:   "127.0.0.1",
		})
	}
	agoutiDriver := agouti.ChromeDriver(
		agouti.Desired(caps),
		agouti.ChromeOptions("args", []string{
			"--no-sandbox",
			"--ignore-certificate-errors",
			"--headless", // Comment out this line to see the tests happen in a visible browser window.
		}),
		// Uncomment this to see stdout/stderr from chromedriver.
		// agouti.Debug,
	)
	require.NoError(t, agoutiDriver.Start())
	t.Cleanup(func() { require.NoError(t, agoutiDriver.Stop()) })
	page, err := agoutiDriver.NewPage(agouti.Browser("chrome"))
	require.NoError(t, err)
	require.NoError(t, page.Reset())

	// Build pinniped CLI.
	t.Logf("building CLI binary")
	pinnipedExe := buildPinnipedCLI(t)

	// Make a temp directory to hold the session cache for this test.
	sessionCachePath := testutil.TempDir(t) + "/sessions.yaml"

	// Start the CLI running the "alpha login oidc [...]" command with stdout/stderr connected to pipes.
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
			closeErr := stderr.Close()
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

	// Expect to be redirected to the login page.
	t.Logf("waiting for redirect to %s login page", loginProvider.Name)
	waitForURL(t, page, loginProvider.LoginPagePattern)

	// Wait for the login page to be rendered.
	waitForVisibleElements(t, page, loginProvider.UsernameSelector, loginProvider.PasswordSelector, loginProvider.LoginButtonSelector)

	// Fill in the username and password and click "submit".
	t.Logf("logging into %s", loginProvider.Name)
	require.NoError(t, page.First(loginProvider.UsernameSelector).Fill(env.CLITestUpstream.Username))
	require.NoError(t, page.First(loginProvider.PasswordSelector).Fill(env.CLITestUpstream.Password))
	require.NoError(t, page.First(loginProvider.LoginButtonSelector).Click())

	// Wait for the login to happen and us be redirected back to a localhost callback.
	t.Logf("waiting for redirect to localhost callback")
	callbackURLPattern := regexp.MustCompile(`\A` + regexp.QuoteMeta(env.CLITestUpstream.CallbackURL) + `\?.+\z`)
	waitForURL(t, page, callbackURLPattern)

	// Wait for the "pre" element that gets rendered for a `text/plain` page, and
	// assert that it contains the success message.
	t.Logf("verifying success page")
	waitForVisibleElements(t, page, "pre")
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

func waitForVisibleElements(t *testing.T, page *agouti.Page, selectors ...string) {
	t.Helper()
	require.Eventually(t,
		func() bool {
			for _, sel := range selectors {
				vis, err := page.First(sel).Visible()
				if !(err == nil && vis) {
					return false
				}
			}
			return true
		},
		10*time.Second,
		100*time.Millisecond,
	)
}

func waitForURL(t *testing.T, page *agouti.Page, pat *regexp.Regexp) {
	var lastURL string
	require.Eventuallyf(t,
		func() bool {
			url, err := page.URL()
			if err == nil && pat.MatchString(url) {
				return true
			}
			if url != lastURL {
				t.Logf("saw URL %s", url)
				lastURL = url
			}
			return false
		},
		10*time.Second,
		100*time.Millisecond,
		"expected to browse to %s, but never got there",
		pat,
	)
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
	if env.Proxy != "" {
		cmd.Env = append(os.Environ(),
			"http_proxy="+env.Proxy,
			"https_proxy="+env.Proxy,
			"no_proxy=127.0.0.1",
		)
	}
	return cmd
}
