// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package browsertest provides integration test helpers for our browser-based tests.
package browsertest

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	chromedpbrowser "github.com/chromedp/cdproto/browser"
	chromedpruntime "github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/test/testlib"
)

// Browser abstracts the specific browser driver library that we use and provides an interface
// for integration tests to interact with the browser.
type Browser struct {
	chromeCtx       context.Context
	consoleEvents   []consoleEvent
	exceptionEvents []string
	lock            sync.RWMutex
}

// consoleEvent tracks calls to the browser's console functions, like console.log().
type consoleEvent struct {
	api  string
	args []string
}

// OpenBrowser opens a web browser as a subprocess and returns a Browser which allows
// further interactions with the browser. The subprocess will be cleaned up at the end
// of the test. Each call to OpenBrowser creates a new browser which does not share any
// cookies with other browsers from other calls.
func OpenBrowser(t *testing.T) *Browser {
	t.Helper()

	// Make it trivial to run all browser based tests via:
	// go test -v -race -count 1 -timeout 0 ./test/integration -run '/_Browser'
	require.Contains(t, rootTestName(t), "_Browser", "browser based tests must contain the string _Browser in their name")

	t.Logf("opening browser driver")
	env := testlib.IntegrationEnv(t)

	// Configure the browser.
	options := append(
		// Start with the defaults.
		chromedp.DefaultExecAllocatorOptions[:],
		// Add "ignore-certificate-errors" Chrome flag.
		chromedp.IgnoreCertErrors,
		// Uncomment this to watch the browser while the test runs.
		// chromedp.Flag("headless", false), chromedp.Flag("hide-scrollbars", false), chromedp.Flag("mute-audio", false),
	)

	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		// When running on linux, assume that we are running inside a container for CI.
		// Need to pass an extra flag in this case to avoid getting an error while launching Chrome.
		options = append(options, chromedp.NoSandbox)
	}

	// Add the proxy flag when needed.
	if env.Proxy != "" {
		t.Logf("configuring Chrome to use proxy %q", env.Proxy)
		options = append(options, chromedp.ProxyServer(env.Proxy))
	}

	// Build the context using the above options.
	configCtx, configCancelFunc := chromedp.NewExecAllocator(context.Background(), options...)
	t.Cleanup(configCancelFunc)

	// Create a browser context.
	chromeCtx, chromeCancelFunc := chromedp.NewContext(configCtx,
		// Uncomment to show Chrome debug logging.
		// This can be an overwhelming amount of text, but can help to debug things.
		// chromedp.WithDebugf(log.Printf),
		chromedp.WithLogf(log.Printf),
		chromedp.WithErrorf(log.Printf),
	)
	t.Cleanup(chromeCancelFunc)

	// Create the return value.
	b := &Browser{chromeCtx: chromeCtx}

	// Subscribe to console events and exceptions to make them available later.
	chromedp.ListenTarget(chromeCtx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *chromedpruntime.EventConsoleAPICalled:
			args := make([]string, len(ev.Args))
			for i, arg := range ev.Args {
				// Could also pay attention to arg.Type here, but choosing to keep it simple for now.
				args[i] = fmt.Sprintf("%s", arg.Value) //nolint:gosimple // this is an acceptable way to get a string
			}
			b.lock.Lock()
			defer b.lock.Unlock()
			b.consoleEvents = append(b.consoleEvents, consoleEvent{
				api:  ev.Type.String(),
				args: args,
			})
		case *chromedpruntime.EventExceptionThrown:
			b.lock.Lock()
			defer b.lock.Unlock()
			b.exceptionEvents = append(b.exceptionEvents, ev.ExceptionDetails.Error())
		}
	})

	// Start the web browser subprocess. Do not use a timeout here or else the browser will close after that timeout.
	// The subprocess will be cleaned up at the end of the test when the browser context is cancelled.
	require.NoError(t, chromedp.Run(chromeCtx))

	// Grant permission to write to the clipboard because the Pinniped formpost UI has a button to copy the
	// authcode to the clipboard, and we want to be able to use that button in tests.
	require.NoError(t, chromedp.Run(chromeCtx,
		chromedpbrowser.GrantPermissions(
			[]chromedpbrowser.PermissionType{chromedpbrowser.PermissionTypeClipboardSanitizedWrite},
		),
	))

	// To aid in debugging test failures, print the events received from the browser at the end of the test.
	t.Cleanup(func() {
		b.lock.RLock()
		defer b.lock.RUnlock()

		consoleEventCount := len(b.consoleEvents)
		exceptionEventCount := len(b.exceptionEvents)

		if consoleEventCount > 0 {
			t.Logf("Printing %d browser console events at end of test...", consoleEventCount)
		}
		for _, e := range b.consoleEvents {
			args := make([]string, len(e.args))
			for i, arg := range e.args {
				args[i] = fmt.Sprintf("%q", testlib.MaskTokens(arg))
			}
			t.Logf("console.%s with args: [%s]", e.api, strings.Join(args, ", "))
		}

		if exceptionEventCount > 0 {
			t.Logf("Printing %d browser exception events at end of test...", exceptionEventCount)
		}
		for _, e := range b.exceptionEvents {
			t.Logf("exception: %s", e)
		}
	})

	// Done. The browser is ready to be driven by the test.
	return b
}

func (b *Browser) timeout() time.Duration {
	return 30 * time.Second
}

func (b *Browser) runWithTimeout(t *testing.T, timeout time.Duration, actions ...chromedp.Action) {
	t.Helper()
	timeoutCtx, cancel := context.WithTimeout(b.chromeCtx, timeout)
	t.Cleanup(cancel)

	err := chromedp.Run(timeoutCtx, actions...)
	if err != nil && err == context.Canceled || err == context.DeadlineExceeded {
		require.NoError(t, err, "the browser operation took longer than the allowed timeout")
	}
	require.NoError(t, err, "the browser operation failed")
}

func (b *Browser) Navigate(t *testing.T, url string) {
	t.Helper()
	b.runWithTimeout(t, b.timeout(), chromedp.Navigate(url))
}

func (b *Browser) Title(t *testing.T) string {
	t.Helper()
	var title string
	b.runWithTimeout(t, b.timeout(), chromedp.Title(&title))
	return title
}

func (b *Browser) WaitForVisibleElements(t *testing.T, selectors ...string) {
	t.Helper()
	for _, s := range selectors {
		b.runWithTimeout(t, b.timeout(), chromedp.WaitVisible(s))
	}
}

func (b *Browser) TextOfFirstMatch(t *testing.T, selector string) string {
	t.Helper()
	var text string
	b.runWithTimeout(t, b.timeout(), chromedp.Text(selector, &text, chromedp.NodeVisible))
	return text
}

func (b *Browser) AttrValueOfFirstMatch(t *testing.T, selector string, attributeName string) string {
	t.Helper()
	var value string
	var ok bool
	b.runWithTimeout(t, b.timeout(), chromedp.AttributeValue(selector, attributeName, &value, &ok))
	require.Truef(t, ok, "did not find attribute named %q on first element returned by selector %q", attributeName, selector)
	return value
}

func (b *Browser) SendKeysToFirstMatch(t *testing.T, selector string, runesToType string) {
	t.Helper()
	b.runWithTimeout(t, b.timeout(), chromedp.SendKeys(selector, runesToType, chromedp.NodeVisible, chromedp.NodeEnabled))
}

func (b *Browser) ClickFirstMatch(t *testing.T, selector string) string {
	t.Helper()
	var text string
	b.runWithTimeout(t, b.timeout(), chromedp.Click(selector, chromedp.NodeVisible, chromedp.NodeEnabled))
	return text
}

// WaitForURL expects the page to eventually navigate to a URL matching the specified pattern. It waits for this
// to occur and times out, failing the test, if it never does.
func (b *Browser) WaitForURL(t *testing.T, regex *regexp.Regexp) {
	var lastURL string
	testlib.RequireEventuallyf(t,
		func(requireEventually *require.Assertions) {
			var url string
			requireEventually.NoError(chromedp.Run(b.chromeCtx, chromedp.Location(&url)))
			if url != lastURL {
				t.Logf("saw URL %s", testlib.MaskTokens(url))
				lastURL = url
			}
			requireEventually.Regexp(regex, url)
		},
		30*time.Second,
		100*time.Millisecond,
		"expected to browse to %s, but never got there",
		regex,
	)
}

// FindConsoleEventWithTextMatching searches the browser's console that have been observed so far
// to find an event with an argument (converted to a string) that matches the provided regexp.
// consoleEventAPIType could be any of the console.funcName() names, e.g. "log", "info", "error", etc.
// It returns the first matching event argument value. It doesn't worry about optimizing the search
// speed because there should not be too many console events and because this just is a test helper.
func (b *Browser) FindConsoleEventWithTextMatching(consoleEventAPIType string, re *regexp.Regexp) (string, bool) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	for _, e := range b.consoleEvents {
		if e.api == consoleEventAPIType {
			for _, arg := range e.args {
				if re.Match([]byte(arg)) {
					return arg, true
				}
			}
		}
	}

	return "", false
}

func rootTestName(t *testing.T) string {
	switch names := strings.SplitN(t.Name(), "/", 3); len(names) {
	case 0:
		panic("impossible")

	case 1:
		return names[0]

	case 2, 3:
		if strings.HasPrefix(names[0], "TestIntegration") {
			return names[1]
		}
		return names[0]

	default:
		panic("impossible")
	}
}

// LoginToUpstreamOIDC expects the page to be redirected to one of several known upstream IDPs.
// It knows how to enter the test username/password and submit the upstream login form.
func LoginToUpstreamOIDC(t *testing.T, b *Browser, upstream testlib.TestOIDCUpstream) {
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
			LoginPagePattern:    regexp.MustCompile(`\Ahttps://.+\.okta\.com/.*\z`),
			UsernameSelector:    "input#okta-signin-username",
			PasswordSelector:    "input#okta-signin-password",
			LoginButtonSelector: "input#okta-signin-submit",
		},
		{
			Name:                "Dex",
			IssuerPattern:       regexp.MustCompile(`\Ahttps://dex\.tools\.svc\.cluster\.local/dex.*\z`),
			LoginPagePattern:    regexp.MustCompile(`\Ahttps://dex\.tools\.svc\.cluster\.local/dex/auth/local.+\z`),
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
	b.WaitForURL(t, cfg.LoginPagePattern)

	// Wait for the login page to be rendered.
	b.WaitForVisibleElements(t, cfg.UsernameSelector, cfg.PasswordSelector, cfg.LoginButtonSelector)

	// Fill in the username and password and click "submit".
	t.Logf("logging into %s", cfg.Name)
	b.SendKeysToFirstMatch(t, cfg.UsernameSelector, upstream.Username)
	b.SendKeysToFirstMatch(t, cfg.PasswordSelector, upstream.Password)

	// The Okta login page has a lot of Javascript on it. Give it a second to catch up after typing the
	// username and password. Hoping that this might help with the test flake where the Okta login page
	// never continues to the next page after trying to click the login button below.
	time.Sleep(1 * time.Second)

	b.ClickFirstMatch(t, cfg.LoginButtonSelector)
}

// LoginToUpstreamLDAP expects the page to be redirected to the Supervisor's login UI for an LDAP/AD IDP.
// It knows how to enter the test username/password and submit the upstream login form.
func LoginToUpstreamLDAP(t *testing.T, b *Browser, issuer, username, password string) {
	t.Helper()

	loginURLRegexp, err := regexp.Compile(`\A` + regexp.QuoteMeta(issuer+"/login") + `\?state=.+\z`)
	require.NoError(t, err)

	// Expect to be redirected to the login page.
	t.Logf("waiting for redirect to %s/login page", issuer)
	b.WaitForURL(t, loginURLRegexp)

	// Wait for the login page to be rendered.
	b.WaitForVisibleElements(t, "#username", "#password", "#submit")

	// Fill in the username and password and click "submit".
	SubmitUpstreamLDAPLoginForm(t, b, username, password)
}

func SubmitUpstreamLDAPLoginForm(t *testing.T, b *Browser, username string, password string) {
	t.Helper()

	// Fill in the username and password and click "submit".
	t.Logf("logging in via Supervisor's upstream LDAP/AD login UI page")
	b.SendKeysToFirstMatch(t, "#username", username)
	b.SendKeysToFirstMatch(t, "#password", password)
	b.ClickFirstMatch(t, "#submit")
}

func WaitForUpstreamLDAPLoginPageWithError(t *testing.T, b *Browser, issuer string) {
	t.Helper()

	// Wait for redirect back to the login page again with an error.
	t.Logf("waiting for redirect to back to login page with error message")
	loginURLRegexp, err := regexp.Compile(`\A` + regexp.QuoteMeta(issuer+"/login") + `\?err=login_error&state=.+\z`)
	require.NoError(t, err)
	b.WaitForURL(t, loginURLRegexp)

	// Wait for the login page to be rendered again, this time also with an error message.
	b.WaitForVisibleElements(t, "#username", "#password", "#submit", "#alert")
}
