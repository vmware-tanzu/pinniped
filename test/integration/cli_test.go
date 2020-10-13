// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sclevine/agouti"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"go.pinniped.dev/test/library"
)

func TestCLIGetKubeconfig(t *testing.T) {
	env := library.IntegrationEnv(t).WithCapability(library.ClusterSigningKeyIsAvailable)

	// Create a test webhook configuration to use with the CLI.
	ctx, cancelFunc := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancelFunc()

	idp := library.CreateTestWebhookIDP(ctx, t)

	// Build pinniped CLI.
	pinnipedExe := buildPinnipedCLI(t)

	// Run pinniped CLI to get kubeconfig.
	kubeConfigYAML := runPinnipedCLIGetKubeconfig(t, pinnipedExe, env.TestUser.Token, env.ConciergeNamespace, "webhook", idp.Name)

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

func runPinnipedCLIGetKubeconfig(t *testing.T, pinnipedExe, token, namespaceName, idpType, idpName string) string {
	t.Helper()

	output, err := exec.Command(
		pinnipedExe,
		"get-kubeconfig",
		"--token", token,
		"--pinniped-namespace", namespaceName,
		"--idp-type", idpType,
		"--idp-name", idpName,
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
	issuer := library.IntegrationEnv(t).OIDCUpstream.Issuer
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
			IssuerPattern:       regexp.MustCompile(`\Ahttp://127\.0\.0\.1.+/dex.*\z`),
			LoginPagePattern:    regexp.MustCompile(`\Ahttp://127\.0\.0\.1.+/dex/auth/local.+\z`),
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

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Find the login CSS selectors for the test issuer, or fail fast.
	loginProvider := getLoginProvider(t)

	// Build pinniped CLI.
	t.Logf("building CLI binary")
	pinnipedExe := buildPinnipedCLI(t)

	cmd := exec.CommandContext(ctx, pinnipedExe, "alpha", "login", "oidc",
		"--issuer", env.OIDCUpstream.Issuer,
		"--client-id", env.OIDCUpstream.ClientID,
		"--listen-port", strconv.Itoa(env.OIDCUpstream.LocalhostPort),
		"--skip-browser",
	)

	// Create a WaitGroup that will wait for all child goroutines to finish, so they can assert errors.
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)

	// Start a background goroutine to read stderr from the CLI and parse out the login URL.
	loginURLChan := make(chan string)
	stderr, err := cmd.StderrPipe()
	require.NoError(t, err)
	wg.Add(1)
	go func() {
		defer wg.Done()
		r := bufio.NewReader(stderr)
		line, err := r.ReadString('\n')
		require.NoError(t, err)
		const prompt = "Please log in: "
		require.Truef(t, strings.HasPrefix(line, prompt), "expected %q to have prefix %q", line, prompt)
		loginURLChan <- strings.TrimPrefix(line, prompt)
		_, err = io.Copy(ioutil.Discard, r)

		t.Logf("stderr stream closed")
		require.NoError(t, err)
	}()

	// Start a background goroutine to read stdout from the CLI and parse out an ExecCredential.
	credOutputChan := make(chan clientauthenticationv1beta1.ExecCredential)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	wg.Add(1)
	go func() {
		defer wg.Done()
		r := bufio.NewReader(stdout)

		var out clientauthenticationv1beta1.ExecCredential
		require.NoError(t, json.NewDecoder(r).Decode(&out))
		credOutputChan <- out

		_, err = io.Copy(ioutil.Discard, r)
		t.Logf("stdout stream closed")
		require.NoError(t, err)
	}()

	t.Logf("starting CLI subprocess")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		err := cmd.Wait()
		t.Logf("CLI subprocess exited")
		require.NoError(t, err)
	})

	// Start the browser driver.
	t.Logf("opening browser driver")
	agoutiDriver := agouti.ChromeDriver(
		// Comment out this line to see the tests happen in a visible browser window.
		agouti.ChromeOptions("args", []string{"--headless"}),
	)
	require.NoError(t, agoutiDriver.Start())
	t.Cleanup(func() { require.NoError(t, agoutiDriver.Stop()) })
	page, err := agoutiDriver.NewPage(agouti.Browser("chrome"))
	require.NoError(t, err)

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
	require.NoError(t, page.First(loginProvider.UsernameSelector).Fill(env.OIDCUpstream.Username))
	require.NoError(t, page.First(loginProvider.PasswordSelector).Fill(env.OIDCUpstream.Password))
	require.NoError(t, page.First(loginProvider.LoginButtonSelector).Click())

	// Wait for the login to happen and us be redirected back to a localhost callback.
	t.Logf("waiting for redirect to localhost callback")
	callbackURLPattern := regexp.MustCompile(`\Ahttp://127.0.0.1:` + strconv.Itoa(env.OIDCUpstream.LocalhostPort) + `/.+\z`)
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
	require.Equal(t, env.OIDCUpstream.Issuer, claims["iss"])
	require.Equal(t, env.OIDCUpstream.ClientID, claims["aud"])
	require.Equal(t, env.OIDCUpstream.Username, claims["email"])
	require.NotEmpty(t, claims["nonce"])
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
	require.Eventually(t, func() bool {
		url, err := page.URL()
		return err == nil && pat.MatchString(url)
	}, 10*time.Second, 100*time.Millisecond)
}
