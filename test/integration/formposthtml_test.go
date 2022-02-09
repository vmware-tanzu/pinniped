// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/hmac"
	"github.com/sclevine/agouti"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/httputil/securityheader"
	"go.pinniped.dev/internal/oidc/provider/formposthtml"
	"go.pinniped.dev/test/testlib"
	"go.pinniped.dev/test/testlib/browsertest"
)

// safe to run in parallel with serial tests since it only interacts with a test local server, see main_test.go.
func TestFormPostHTML_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t)

	// Run a mock callback handler, simulating the one running in the CLI.
	callbackURL, expectCallback := formpostCallbackServer(t)

	// Open a single browser for all subtests to use (in sequence).
	page := browsertest.Open(t)

	t.Run("success", func(t *testing.T) {
		// Serve the form_post template with successful parameters.
		responseParams := formpostRandomParams(t)
		formpostInitiate(t, page, formpostTemplateServer(t, callbackURL, responseParams))

		// Now we handle the callback and assert that we got what we expected. This should transition
		// the UI into the success state.
		expectCallback(t, responseParams)
		formpostExpectSuccessState(t, page)
	})

	t.Run("callback server error", func(t *testing.T) {
		// Serve the form_post template with a redirect URI that will return an HTTP 500 response.
		responseParams := formpostRandomParams(t)
		formpostInitiate(t, page, formpostTemplateServer(t, callbackURL+"?fail=500", responseParams))

		// Now we handle the callback and assert that we got what we expected.
		expectCallback(t, responseParams)

		// This is not 100% the behavior we'd like, but because our JS is making
		// a cross-origin fetch() without CORS, we don't get to know anything
		// about the response (even whether it is 200 vs. 500), so this case
		// is the same as the success case.
		//
		// This case is fairly unlikely in practice, and if the CLI encounters
		// an error it can also expose it via stderr anyway.
		//
		// In the future, we could change the Javascript code to use mode 'cors'
		// because we have upgraded our CLI callback endpoint to handle CORS,
		// and then we could change this to formpostExpectManualState().
		formpostExpectSuccessState(t, page)
	})

	t.Run("network failure", func(t *testing.T) {
		// Serve the form_post template with a redirect URI that will return a network error.
		responseParams := formpostRandomParams(t)
		formpostInitiate(t, page, formpostTemplateServer(t, callbackURL+"?fail=close", responseParams))

		// Now we handle the callback and assert that we got what we expected.
		// This will trigger the callback server to close the client connection abruptly because
		// of the `?fail=close` parameter above.
		expectCallback(t, responseParams)

		// This failure should cause the UI to enter the "manual" state.
		actualCode := formpostExpectManualState(t, page)
		require.Equal(t, responseParams.Get("code"), actualCode)
	})

	t.Run("timeout", func(t *testing.T) {
		// Serve the form_post template with successful parameters.
		responseParams := formpostRandomParams(t)
		formpostInitiate(t, page, formpostTemplateServer(t, callbackURL, responseParams))

		// Sleep for longer than the two second timeout.
		// During this sleep we are blocking the callback from returning.
		time.Sleep(3 * time.Second)

		// Assert that the timeout fires and we see the manual instructions.
		actualCode := formpostExpectManualState(t, page)
		require.Equal(t, responseParams.Get("code"), actualCode)

		// Now simulate the callback finally succeeding, in which case
		// the manual instructions should disappear and we should see the success
		// div instead.
		expectCallback(t, responseParams)
		formpostExpectSuccessState(t, page)
	})
}

// formpostCallbackServer runs a test server that simulates the CLI's callback handler.
// It returns the URL of the running test server and a function for fetching the next
// received form POST parameters.
//
// The test server supports special `?fail=close` and `?fail=500` to force error cases.
func formpostCallbackServer(t *testing.T) (string, func(*testing.T, url.Values)) {
	results := make(chan url.Values)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 404 for any other requests aside from POSTs. We do not need to support CORS preflight OPTIONS
		// requests for this test because both the web page and the callback are on 127.0.0.1 (same origin).
		if r.Method != http.MethodPost {
			t.Logf("test callback server got unexpeted request method")
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Allow CORS requests. This will be needed for this test in the future if we change
		// the Javascript code from using mode 'no-cors' to instead use mode 'cors'. At the
		// moment it should be ignored by the browser.
		w.Header().Set("Access-Control-Allow-Origin", "*")

		assert.NoError(t, r.ParseForm())

		// Extract only the POST parameters (r.Form also contains URL query parameters).
		postParams := url.Values{}
		for k := range r.Form {
			if v := r.PostFormValue(k); v != "" {
				postParams.Set(k, v)
			}
		}

		// Send the form parameters back on the results channel, giving up if the
		// request context is cancelled (such as if the client disconnects).
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
		case "500": // If "fail=500" is passed, return a 500 error.
			w.WriteHeader(http.StatusInternalServerError)
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

// formpostRandomParams is a helper to generate random OAuth2 response parameters for testing.
func formpostRandomParams(t *testing.T) url.Values {
	generator := &hmac.HMACStrategy{GlobalSecret: testlib.RandBytes(t, 32), TokenEntropy: 32}
	authCode, _, err := generator.Generate()
	require.NoError(t, err)
	return url.Values{
		"code":  []string{authCode},
		"scope": []string{"openid offline_access pinniped:request-audience"},
		"state": []string{testlib.RandHex(t, 16)},
	}
}

// formpostExpectTitle asserts that the page has the expected title.
func formpostExpectTitle(t *testing.T, page *agouti.Page, expected string) {
	actual, err := page.Title()
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

// formpostExpectTitle asserts that the page has the expected SVG/emoji favicon.
func formpostExpectFavicon(t *testing.T, page *agouti.Page, expected string) {
	iconURL, err := page.First("#favicon").Attribute("href")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(iconURL, "data:image/svg+xml,<svg"))

	// For some reason chromedriver on Linux returns this attribute urlencoded, but on macOS it contains the
	// original emoji bytes (unescaped). To check correctly in both cases we allow either version here.
	expectedEscaped := url.QueryEscape(expected)
	require.Truef(t,
		strings.Contains(iconURL, expected) || strings.Contains(iconURL, expectedEscaped),
		"expected %q to contain %q or %q", iconURL, expected, expectedEscaped,
	)
}

// formpostInitiate navigates to the template server endpoint and expects the
// loading animation to be shown.
func formpostInitiate(t *testing.T, page *agouti.Page, url string) {
	require.NoError(t, page.Reset())
	t.Logf("navigating to mock form_post template URL %s...", url)
	require.NoError(t, page.Navigate(url))

	t.Logf("expecting to see loading animation...")
	browsertest.WaitForVisibleElements(t, page, "#loading")
	formpostExpectTitle(t, page, "Logging in...")
	formpostExpectFavicon(t, page, "⏳")
}

// formpostExpectSuccessState asserts that the page is in the "success" state.
func formpostExpectSuccessState(t *testing.T, page *agouti.Page) {
	t.Logf("expecting to see success message become visible...")
	browsertest.WaitForVisibleElements(t, page, "#success")
	successDivText, err := page.First("#success").Text()
	require.NoError(t, err)
	require.Contains(t, successDivText, "Login succeeded")
	require.Contains(t, successDivText, "You have successfully logged in. You may now close this tab.")
	formpostExpectTitle(t, page, "Login succeeded")
	formpostExpectFavicon(t, page, "✅")
}

// formpostExpectManualState asserts that the page is in the "manual" state and returns the auth code.
func formpostExpectManualState(t *testing.T, page *agouti.Page) string {
	t.Logf("expecting to see manual message become visible...")
	browsertest.WaitForVisibleElements(t, page, "#manual")
	manualDivText, err := page.First("#manual").Text()
	require.NoError(t, err)
	require.Contains(t, manualDivText, "Finish your login")
	require.Contains(t, manualDivText, "To finish logging in, paste this authorization code into your command-line session:")
	formpostExpectTitle(t, page, "Finish your login")
	formpostExpectFavicon(t, page, "⌛")

	// Click the copy button and expect that the code is copied to the clipboard. Unfortunately,
	// headless Chrome does not have a real clipboard we can check, so we rely on  checking a
	// console.log() statement that happens at the same time.
	t.Logf("clicking the 'copy' button and expecting the clipboard event to fire...")
	require.NoError(t, page.First("#manual-copy-button").Click())

	var authCode string
	consoleLogPattern := regexp.MustCompile(`code (.+) to clipboard`)
	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		logs, err := page.ReadNewLogs("browser")
		requireEventually.NoError(err)

		for _, log := range logs {
			if match := consoleLogPattern.FindStringSubmatch(log.Message); match != nil {
				authCode = match[1]
				return
			}
		}
		requireEventually.FailNow("expected console log was not found")
	}, 3*time.Second, 100*time.Millisecond)
	return authCode
}
