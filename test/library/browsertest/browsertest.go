// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package browsertest provides integration test helpers for our browser-based tests.
package browsertest

import (
	"regexp"
	"testing"
	"time"

	"github.com/sclevine/agouti"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/test/library"
)

const (
	operationTimeout         = 10 * time.Second
	operationPollingInterval = 100 * time.Millisecond
)

// Open a webdriver-driven browser and returns an *agouti.Page to control it. The browser  will be automatically
// closed at the end of the current test. It is configured for test purposes with the correct HTTP proxy and
// in a mode that ignore certificate errors.
func Open(t *testing.T) *agouti.Page {
	t.Logf("opening browser driver")
	env := library.IntegrationEnv(t)
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
	return page
}

// WaitForVisibleElements expects the page to contain all the the elements specified by the selectors. It waits for this
// to occur and times out, failing the test, if they never appear.
func WaitForVisibleElements(t *testing.T, page *agouti.Page, selectors ...string) {
	t.Helper()

	require.Eventuallyf(t,
		func() bool {
			for _, sel := range selectors {
				vis, err := page.First(sel).Visible()
				if !(err == nil && vis) {
					return false
				}
			}
			return true
		},
		operationTimeout,
		operationPollingInterval,
		"expected to have a page with selectors %v, but it never loaded",
		selectors,
	)
}

// WaitForURL expects the page to eventually navigate to a URL matching the specified pattern. It waits for this
// to occur and times out, failing the test, if it never does.
func WaitForURL(t *testing.T, page *agouti.Page, pat *regexp.Regexp) {
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
		operationTimeout,
		operationPollingInterval,
		"expected to browse to %s, but never got there",
		pat,
	)
}

// LoginToUpstream expects the page to be redirected to one of several known upstream IDPs.
// It knows how to enter the test username/password and submit the upstream login form.
func LoginToUpstream(t *testing.T, page *agouti.Page, upstream library.TestOIDCUpstream) {
	t.Helper()

	type config struct {
		Name                string
		IssuerPattern       *regexp.Regexp
		LoginPagePattern    *regexp.Regexp
		UsernameSelector    string
		PasswordSelector    string
		LoginButtonSelector string
	}

	// Lookup the provider by matching on the issuer URL.
	var cfg *config
	for _, p := range []*config{
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
		if p.IssuerPattern.MatchString(upstream.Issuer) {
			cfg = p
			break
		}
	}
	if cfg == nil {
		require.Failf(t, "could not find login provider for issuer %q", upstream.Issuer)
		return
	}

	// Expect to be redirected to the login page.
	t.Logf("waiting for redirect to %s login page", cfg.Name)
	WaitForURL(t, page, cfg.LoginPagePattern)

	// Wait for the login page to be rendered.
	WaitForVisibleElements(t, page, cfg.UsernameSelector, cfg.PasswordSelector, cfg.LoginButtonSelector)

	// Fill in the username and password and click "submit".
	t.Logf("logging into %s", cfg.Name)
	require.NoError(t, page.First(cfg.UsernameSelector).Fill(upstream.Username))
	require.NoError(t, page.First(cfg.PasswordSelector).Fill(upstream.Password))
	require.NoError(t, page.First(cfg.LoginButtonSelector).Click())
}
