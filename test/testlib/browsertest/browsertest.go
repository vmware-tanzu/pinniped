// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package browsertest provides integration test helpers for our browser-based tests.
package browsertest

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	chromedpbrowser "github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/dom"
	chromedpruntime "github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/testutil/totp"
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

		// Uncomment this to automatically open the devtools window when the browser opens. Helpful when not headless.
		// chromedp.Flag("auto-open-devtools-for-tabs", true),

		// Uncomment one of these lines (and update path if needed) to use
		// Google Chrome Beta (download from https://www.google.com/chrome/beta/)
		// when running integration tests on your local machine.
		// These are the default paths for macOS and Linux, respectively.
		// chromedp.ExecPath("/Applications/Google Chrome Beta.app/Contents/MacOS/Google Chrome Beta"),
		// chromedp.ExecPath("/usr/bin/google-chrome-beta"),
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
	chromedp.ListenTarget(chromeCtx, func(ev any) {
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

		// If the test failed, dump helpful debugging info from the browser's final page.
		if t.Failed() {
			b.dumpPage(t)
		}
	})

	// Done. The browser is ready to be driven by the test.
	return b
}

func (b *Browser) dumpPage(t *testing.T) {
	// Log the URL of the current page.
	var url string
	b.runWithTimeout(t, b.timeout(), chromedp.Location(&url))
	t.Logf("Browser URL from end of test %q: %s", t.Name(), url)

	// Log the title of the current page.
	t.Logf("Browser page title from end of test %q: %q", t.Name(), b.Title(t))

	// Log a screenshot of the current page.
	var screenBuf []byte
	b.runWithTimeout(t, b.timeout(), chromedp.FullScreenshot(&screenBuf, 10)) // low quality to make it smaller
	t.Logf("Browser screenshot (base64 encoded jpeg format) from end of test %q:\n%s\n",
		t.Name(), base64.StdEncoding.EncodeToString(screenBuf))

	// Log the HTML of the current page.
	var html string
	b.runWithTimeout(t, b.timeout(), chromedp.ActionFunc(func(ctx context.Context) error {
		node, err := dom.GetDocument().Do(ctx)
		if err != nil {
			return err
		}
		html, err = dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)
		return err
	}))
	var htmlBuf bytes.Buffer
	gz := gzip.NewWriter(&htmlBuf)
	_, err := gz.Write([]byte(html))
	require.NoError(t, err)
	err = gz.Close()
	require.NoError(t, err)
	t.Logf("Browser html (gzip and base64 encoded) from end of test %q:\n%s\n",
		t.Name(), base64.StdEncoding.EncodeToString(htmlBuf.Bytes()))
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

func (b *Browser) WaitForVisibleElements(t *testing.T, cssSelectors ...string) {
	t.Helper()
	for _, s := range cssSelectors {
		b.runWithTimeout(t, b.timeout(), chromedp.WaitVisible(s, chromedp.ByQuery))
	}
}

func (b *Browser) TextOfFirstMatch(t *testing.T, cssSelector string) string {
	t.Helper()
	var text string
	b.runWithTimeout(t, b.timeout(), chromedp.Text(cssSelector, &text, chromedp.NodeVisible, chromedp.ByQuery))
	return text
}

func (b *Browser) AttrValueOfFirstMatch(t *testing.T, cssSelector string, attributeName string) string {
	t.Helper()
	var value string
	var ok bool
	b.runWithTimeout(t, b.timeout(), chromedp.AttributeValue(cssSelector, attributeName, &value, &ok, chromedp.ByQuery))
	require.Truef(t, ok, "did not find attribute named %q on first element returned by selector %q", attributeName, cssSelector)
	return value
}

func (b *Browser) SendKeysToFirstMatch(t *testing.T, cssSelector string, runesToType string) {
	t.Helper()
	b.runWithTimeout(t, b.timeout(), chromedp.SendKeys(cssSelector, runesToType, chromedp.NodeVisible, chromedp.NodeEnabled, chromedp.ByQuery))
}

func (b *Browser) ClickFirstMatch(t *testing.T, cssSelector string) string {
	t.Helper()
	var text string
	b.runWithTimeout(t, b.timeout(), chromedp.Click(cssSelector, chromedp.NodeVisible, chromedp.NodeEnabled, chromedp.ByQuery))
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
			IssuerPattern:       regexp.MustCompile(`\Ahttps://.*/dex.*\z`),
			LoginPagePattern:    regexp.MustCompile(`\Ahttps://.*/dex/auth/local.+\z`),
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
		require.Failf(t, "failure message goes here", "could not find login provider for issuer %q", upstream.Issuer)
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

	// The Okta login page has a lot of Javascript on it. Give it a second to catch up after typing the
	// username. Hoping that this might help with the test flake that started in Chrome v134 where the
	// username and password fields are not filled in correctly.
	time.Sleep(1 * time.Second)

	b.SendKeysToFirstMatch(t, cfg.PasswordSelector, upstream.Password)

	// The Okta login page has a lot of Javascript on it. Give it a second to catch up after typing the
	// password. Hoping that this might help with the test flake where the Okta login page
	// never continues to the next page after trying to click the login button below.
	time.Sleep(1 * time.Second)

	b.ClickFirstMatch(t, cfg.LoginButtonSelector)
}

// LoginToUpstreamGitHub expects the page to be redirected to GitHub.
// It knows how to enter the test username/password and submit the upstream login form.
func LoginToUpstreamGitHub(t *testing.T, b *Browser, upstream testlib.TestGithubUpstream) {
	t.Helper()

	// Expect to be redirected to the login page.
	t.Logf("waiting for redirect to GitHub login page")
	b.WaitForURL(t, regexp.MustCompile(`\Ahttps://github\.com/login.+\z`))

	usernameSelector := "input#login_field"
	passwordSelector := "input#password"
	loginButtonSelector := "input[type=submit]"

	// Wait for the login page to be rendered.
	b.WaitForVisibleElements(t, usernameSelector, passwordSelector, loginButtonSelector)

	// Fill in the username and password and click "submit".
	t.Logf("logging into GitHub")
	b.SendKeysToFirstMatch(t, usernameSelector, upstream.TestUserUsername)
	b.SendKeysToFirstMatch(t, passwordSelector, upstream.TestUserPassword)
	b.ClickFirstMatch(t, loginButtonSelector)

	handleGithubOTPLoginPage(t, b, upstream)

	// Keep looping until we get to a page that we do not know how to handle. Then return to allow the test to move on.
	for handleOccasionalGithubLoginPage(t, b, upstream) {
		continue
	}
}

func handleGithubOTPLoginPage(t *testing.T, b *Browser, upstream testlib.TestGithubUpstream) {
	// Next, GitHub should go to a new page and prompt for the six digit MFA/OTP code.
	otpSelector := "input#app_totp"

	// Wait for the MFA page to be rendered.
	t.Logf("waiting for GitHub MFA page")
	b.WaitForVisibleElements(t, otpSelector)

	// Sleep for a bit to make it less likely that we use the same OTP code twice when multiple tests are run in serial.
	// GitHub gets upset when the same OTP code gets reused.
	// GitHub seems to also get upset when any OTP codes are used often, like when all our GitHub tests run sequentially,
	// because sometimes auth will go to a GitHub page that says: "We were unable to authenticate your request because too
	// many codes have been submitted. Please wait a few minutes and contact support if you continue to have problems."
	otpSleepSeconds := 60
	t.Logf("sleeping %d seconds before generating a GitHub OTP code", otpSleepSeconds)
	time.Sleep(time.Duration(otpSleepSeconds) * time.Second)

	code, codeRemainingLifetimeSeconds := totp.GenerateOTPCode(t, upstream.TestUserOTPSecret, time.Now())
	if codeRemainingLifetimeSeconds < 2 {
		t.Log("sleeping for 2 seconds before generating another OTP code")
		time.Sleep(2 * time.Second)
		code, _ = totp.GenerateOTPCode(t, upstream.TestUserOTPSecret, time.Now())
	}

	// Fill in the OTP code. We do not need to click "verify" because entering the code automatically submits the page.
	t.Logf("entering GitHub OTP code")
	b.SendKeysToFirstMatch(t, otpSelector, code)
}

// handleOccasionalGithubLoginPage handles the interstitial pages which GitHub might show during a login flow.
// None of these will always happen.
func handleOccasionalGithubLoginPage(t *testing.T, b *Browser, upstream testlib.TestGithubUpstream) bool {
	t.Helper()

	t.Log("sleeping for 2 seconds before looking at page title")
	time.Sleep(2 * time.Second)
	pageTitle := b.Title(t)
	t.Logf("saw page title %q", pageTitle)
	lowercaseTitle := strings.ToLower(pageTitle)

	switch {
	case strings.HasPrefix(lowercaseTitle, "authorize "): // the title is "Authorize <App Name>"
		// Next GitHub might go to another page asking if you authorize the GitHub App to act on your behalf,
		// if this user has never authorized this app.
		// Wait for the authorize app page to be rendered.
		t.Logf("waiting for GitHub authorize button")
		// There are unfortunately two very similar buttons on this page:
		// <button name="authorize" value="0" type="submit" data-view-component="true" class="ws-normal btn width-full mr-2">Cancel
		// <button name="authorize" value="1" type="submit" data-view-component="true" class="js-oauth-authorize-btn ws-normal btn-primary btn width-full">Authorize
		submitAuthorizeAppButtonSelector := "button.btn-primary"
		b.WaitForVisibleElements(t, submitAuthorizeAppButtonSelector)
		t.Logf("clicking authorize button")
		b.ClickFirstMatch(t, submitAuthorizeAppButtonSelector)
		return true

	case strings.HasPrefix(lowercaseTitle, "confirm your account recovery settings"):
		// Next GitHub might occasionally as you to confirm your recovery settings.
		// Wait for the page to be rendered.
		t.Logf("waiting for GitHub confirm button")
		// There are several buttons and links. We want to click this confirm button to confirm our settings:
		// <button type="submit" name="type" value="confirmed" class="btn btn-block btn-primary ml-3">Confirm</button>
		submitConfirmButtonSelector := "button.btn-primary"
		b.WaitForVisibleElements(t, submitConfirmButtonSelector)
		t.Logf("clicking confirm button")
		b.ClickFirstMatch(t, submitConfirmButtonSelector)
		return true

	case strings.HasPrefix(lowercaseTitle, "verify two-factor authentication"):
		// Next GitHub might occasionally as you to confirm your MFA settings.
		// Wait for the page to be rendered.
		t.Logf("waiting for GitHub skip link")
		// There are several buttons and links. We want to click this link to "skip 2FA verification":
		// <button type="submit" data-view-component="true" class="Button--link Button--medium Button">
		submitSkipButtonSelector := "button.Button--link[type=submit]"
		b.WaitForVisibleElements(t, submitSkipButtonSelector)
		t.Logf("clicking skip link")
		b.ClickFirstMatch(t, submitSkipButtonSelector)
		return true

	case strings.HasPrefix(lowercaseTitle, "configure passwordless authentication"):
		// Next GitHub might occasionally ask if we want to configure a passkey for auth.
		// The URL bar shows https://github.com/sessions/trusted-device for this page.
		// The link that we want to click looks like this:
		// <input class="btn-link" type="submit" value="Don't ask again for this browser">
		dontAskAgainLinkSelector := `input[value="Don't ask again for this browser"]`
		// Wait for the passkey page to be rendered.
		t.Logf("waiting for GitHub's don't ask again button")
		b.WaitForVisibleElements(t, dontAskAgainLinkSelector)
		// Tell it that we do not want to use a passkey.
		t.Logf("clicking don't ask again button")
		b.ClickFirstMatch(t, dontAskAgainLinkSelector)
		return true

	case strings.HasPrefix(lowercaseTitle, "two-factor authentication"):
		// Sometimes this happens after the OTP page when we try to use the same OTP code again too quickly.
		// GitHub stays on the same page and shows an error banner saying that we used the same code again.
		// Sleep for a long time to try to avoid this error from GitHub, which seems to be some type of rate limiting on OTP codes:
		// "We were unable to authenticate your request because too many codes have been submitted".
		otpSleepSeconds := 60
		t.Logf("sleeping %d seconds before generating another GitHub OTP code after a previous code failed", otpSleepSeconds)
		time.Sleep(time.Duration(otpSleepSeconds) * time.Second)
		handleGithubOTPLoginPage(t, b, upstream)
		return true

	case strings.HasPrefix(lowercaseTitle, "server error"):
		// Sometimes this happens after the OTP page. Not sure why. The page has a cute cartoon, but no helpful information.
		// The URL bar shows https://github.com/sessions/trusted-device for this error page, which is the URL that usually
		// asks if you want to configure passwordless authentication (aka passkey).
		t.Fatal("Got GitHub server internal error page during login flow. This is not expected, but is unfortunately unrecoverable.")
		return false // we recognized the title, but we don't know how to handle this page because it has no buttons or other way forward

	default:
		// We did not know how to handle the page given its title.
		// Maybe we successfully got through all the interstitial pages and finished the login.
		return false
	}
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
	loginURLRegexp, err := regexp.Compile(`\A` + regexp.QuoteMeta(issuer+"/login") + `\?err=incorrect_username_or_password&state=.+\z`)
	require.NoError(t, err)
	b.WaitForURL(t, loginURLRegexp)

	// Wait for the login page to be rendered again, this time also with an error message.
	b.WaitForVisibleElements(t, "#username", "#password", "#submit", "#alert")
}
