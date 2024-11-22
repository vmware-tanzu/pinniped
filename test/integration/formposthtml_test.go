// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"hash"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/hmac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/federationdomain/formposthtml"
	"go.pinniped.dev/internal/httputil/securityheader"
	"go.pinniped.dev/test/testlib"
	"go.pinniped.dev/test/testlib/browsertest"
)

// safe to run in parallel with serial tests since it only interacts with a test local server, see main_test.go.
func TestFormPostHTML_Browser_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t)

	// Run a mock callback handler, simulating the one running in the CLI.
	callbackURL, expectCallback := formpostCallbackServer(t)

	t.Run("success", func(t *testing.T) {
		browser := browsertest.OpenBrowser(t)

		// Serve the form_post template with successful parameters.
		responseParams := formpostRandomParams(t)
		formpostInitiate(t, browser, formpostTemplateServer(t, callbackURL, responseParams))

		// Now we handle the callback and assert that we got what we expected. This should transition
		// the UI into the success state.
		expectCallback(t, responseParams)
		formpostExpectSuccessState(t, browser)
	})

	t.Run("callback server error", func(t *testing.T) {
		browser := browsertest.OpenBrowser(t)

		// Serve the form_post template with a redirect URI that will return an HTTP 400 response.
		responseParams := formpostRandomParams(t)
		formpostInitiate(t, browser, formpostTemplateServer(t, callbackURL+"?fail=400", responseParams))

		// Now we handle the callback and assert that we got what we expected.
		expectCallback(t, responseParams)

		// This failure should cause the UI to enter the "error" state.
		formpostExpectErrorState(t, browser)
	})

	t.Run("network failure", func(t *testing.T) {
		browser := browsertest.OpenBrowser(t)

		// Serve the form_post template with a redirect URI that will return a network error.
		responseParams := formpostRandomParams(t)
		formpostInitiate(t, browser, formpostTemplateServer(t, callbackURL+"?fail=close", responseParams))

		// Now we handle the callback and assert that we got what we expected.
		// This will trigger the callback server to close the client connection abruptly because
		// of the `?fail=close` parameter above.
		expectCallback(t, responseParams)

		// This failure should cause the UI to enter the "manual" state.
		actualCode := formpostExpectManualState(t, browser)
		require.Equal(t, responseParams.Get("code"), actualCode)
	})

	t.Run("timeout followed by eventual success", func(t *testing.T) {
		browser := browsertest.OpenBrowser(t)

		// Serve the form_post template with successful parameters.
		responseParams := formpostRandomParams(t)
		formpostInitiate(t, browser, formpostTemplateServer(t, callbackURL, responseParams))

		// Sleep for longer than the two-second timeout hardcoded in form_post.js.
		// During this sleep we are blocking the callback from returning because we
		// have not yet called expectCallback().
		time.Sleep(3 * time.Second)

		// Assert that the timeout fires and we see the manual instructions.
		actualCode := formpostExpectManualState(t, browser)
		require.Equal(t, responseParams.Get("code"), actualCode)

		// Now simulate the callback finally succeeding, in which case
		// the manual instructions should disappear, and we should see the success
		// div instead.
		expectCallback(t, responseParams)
		formpostExpectSuccessState(t, browser)
	})
}

// formpostCallbackServer runs a test server that simulates the CLI's callback handler.
// It returns the URL of the running test server and a function for fetching the next
// received form POST parameters.
//
// The test server supports special `?fail=close` and `?fail=400` to force error cases.
func formpostCallbackServer(t *testing.T) (string, func(*testing.T, url.Values)) {
	t.Helper()
	results := make(chan url.Values)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 404 for any other requests aside from POSTs. We do not need to support CORS preflight OPTIONS
		// requests for this test because both the web page and the callback are on 127.0.0.1 (same origin).
		if r.Method != http.MethodPost {
			t.Logf("test callback server got unexpeted request method")
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Allow CORS requests.
		w.Header().Set("Access-Control-Allow-Origin", "*")

		assert.NoError(t, r.ParseForm())

		// Extract only the POST parameters (r.Form also contains URL query parameters).
		postParams := url.Values{}
		for k := range r.Form {
			if v := r.PostFormValue(k); v != "" {
				postParams.Set(k, v)
			}
		}

		// Send the form parameters back on the results channel, blocking until the test calls
		// the function returned by formpostCallbackServer() to read this message, but also
		// giving up if the request context is cancelled (such as if the client disconnects).
		select {
		case results <- postParams:
		case <-r.Context().Done():
			return
		}

		switch r.URL.Query().Get("fail") {
		case "close": // If "fail=close" is passed, close the connection immediately.
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}
			return
		case "400": // If "fail=400" is passed, return a 400 error.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("this is the text of the bad request error response"))
			return
		}
	}))
	t.Cleanup(func() {
		close(results)
		server.Close()
	})
	return server.URL, func(t *testing.T, expected url.Values) {
		t.Logf("expecting to get a POST callback...")
		select {
		case actual := <-results:
			require.Equal(t, expected, actual, "did not receive expected callback")
		case <-time.After(3 * time.Second):
			t.Errorf("failed to receive expected callback %v", expected)
			t.FailNow()
		}
	}
}

// formpostTemplateServer runs a test server that serves formposthtml.Template() rendered with test parameters.
func formpostTemplateServer(t *testing.T, redirectURI string, responseParams url.Values) string {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fosite.WriteAuthorizeFormPostResponse(redirectURI, responseParams, formposthtml.Template(), w)
	})
	server := httptest.NewServer(securityheader.WrapWithCustomCSP(
		handler,
		formposthtml.ContentSecurityPolicy(),
	))
	t.Cleanup(server.Close)
	return server.URL
}

type testHMACStrategyConfigurator struct {
	secret  []byte
	entropy int
}

func newTestHMACStrategyConfigurator(secret []byte, entropy int) hmac.HMACStrategyConfigurator {
	return &testHMACStrategyConfigurator{
		secret:  secret,
		entropy: entropy,
	}
}

func (t *testHMACStrategyConfigurator) GetTokenEntropy(_ context.Context) int {
	return t.entropy
}

func (t *testHMACStrategyConfigurator) GetGlobalSecret(_ context.Context) ([]byte, error) {
	return t.secret, nil
}

func (t *testHMACStrategyConfigurator) GetRotatedGlobalSecrets(_ context.Context) ([][]byte, error) {
	return nil, nil
}

func (t *testHMACStrategyConfigurator) GetHMACHasher(_ context.Context) func() hash.Hash {
	return nil // nil will cause fosite to use a default hasher
}

// formpostRandomParams is a helper to generate random OAuth2 response parameters for testing.
func formpostRandomParams(t *testing.T) url.Values {
	t.Helper()
	generator := &hmac.HMACStrategy{Config: newTestHMACStrategyConfigurator(testlib.RandBytes(t, 32), 32)}
	authCode, _, err := generator.Generate(context.Background())
	require.NoError(t, err)
	return url.Values{
		"code":  []string{authCode},
		"scope": []string{"openid offline_access pinniped:request-audience"},
		"state": []string{testlib.RandHex(t, 16)},
	}
}

// formpostExpectFavicon asserts that the page has the expected SVG/emoji favicon.
func formpostExpectFavicon(t *testing.T, b *browsertest.Browser, expected string) {
	t.Helper()
	iconURL := b.AttrValueOfFirstMatch(t, "#favicon", "href")
	require.True(t, strings.HasPrefix(iconURL, "data:image/svg+xml,<svg"))
	require.Contains(t, iconURL, expected)
}

// formpostInitiate navigates to the template server endpoint and expects the
// loading animation to be shown.
func formpostInitiate(t *testing.T, b *browsertest.Browser, url string) {
	t.Helper()

	t.Logf("navigating to mock form_post template URL %s...", url)
	navigationStartTime := time.Now()
	b.Navigate(t, url)

	// There is a race here, because the JS code will only show this loading animation
	// for two seconds, and then will automatically hide it and instead show the manual
	// copy/paste UI. So if this test runs on a very busy/slow machine that takes more
	// than two seconds to start waiting for the loading div after opening the page,
	// then it would fail. This is rare but does happen occasionally, so just skip these
	// assertions in that case.
	if time.Since(navigationStartTime) > 1500*time.Millisecond {
		// Took too long to navigate to the page to be able to consistently see the
		// loading animation, which is only supposed to last for 2 seconds.
		t.Logf("skipping loading animation assertions because test was too slow...")
		return
	}

	t.Logf("expecting to see loading animation...")
	b.WaitForVisibleElements(t, "div#loading")
	require.Equal(t, "Logging in...", b.Title(t))
	formpostExpectFavicon(t, b, "⏳")
}

// formpostExpectSuccessState asserts that the page is in the "success" state.
func formpostExpectSuccessState(t *testing.T, b *browsertest.Browser) {
	t.Helper()
	t.Logf("expecting to see success message become visible...")
	b.WaitForVisibleElements(t, "div#success")
	successDivText := b.TextOfFirstMatch(t, "div#success")
	require.Contains(t, successDivText, "Login succeeded")
	require.Contains(t, successDivText, "You have successfully logged in. You may now close this tab.")
	require.Equal(t, "Login succeeded", b.Title(t))
	formpostExpectFavicon(t, b, "✅")
}

// formpostExpectErrorState asserts that the page is in the "error" state.
func formpostExpectErrorState(t *testing.T, b *browsertest.Browser) {
	t.Helper()
	t.Logf("expecting to see error message become visible...")
	b.WaitForVisibleElements(t, "div#error")
	errorDivText := b.TextOfFirstMatch(t, "div#error")
	require.Contains(t, errorDivText, "Error during login")
	require.Contains(t, errorDivText, "400: this is the text of the bad request error response")
	require.Contains(t, errorDivText, "Please try again.")
	require.Equal(t, "Error during login", b.Title(t))
	formpostExpectFavicon(t, b, "⛔")
}

// formpostExpectManualState asserts that the page is in the "manual" state and returns the auth code.
func formpostExpectManualState(t *testing.T, b *browsertest.Browser) string {
	t.Helper()
	t.Logf("expecting to see manual message become visible...")
	b.WaitForVisibleElements(t, "div#manual")
	manualDivText := b.TextOfFirstMatch(t, "div#manual")
	require.Contains(t, manualDivText, "Finish your login")
	require.Contains(t, manualDivText, "To finish logging in, paste this authorization code into your command-line session:")
	require.Equal(t, "Finish your login", b.Title(t))
	formpostExpectFavicon(t, b, "⌛")

	// Click the copy button and expect that the code is copied to the clipboard. Unfortunately,
	// headless Chrome does not have a real clipboard we can check, so we rely on  checking a
	// console.log() statement that happens at the same time.
	t.Logf("clicking the 'copy' button and expecting the clipboard event to fire...")
	b.ClickFirstMatch(t, "#manual-copy-button")

	var authCode string
	consoleLogPattern := regexp.MustCompile(`code (.+) to clipboard`)
	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		matchingText, found := b.FindConsoleEventWithTextMatching("info", consoleLogPattern)
		requireEventually.True(found)
		if captureMatches := consoleLogPattern.FindStringSubmatch(matchingText); captureMatches != nil {
			authCode = captureMatches[1]
			return
		}
		requireEventually.FailNow("expected console log was not found")
	}, 10*time.Second, 100*time.Millisecond)
	return authCode
}
