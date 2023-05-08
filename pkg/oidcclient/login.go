// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package oidcclient implements a CLI OIDC login flow.
package oidcclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
	"golang.org/x/term"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/strings/slices"

	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/httputil/securityheader"
	"go.pinniped.dev/internal/net/phttp"
	"go.pinniped.dev/internal/oidc/provider/upstreamprovider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/upstreamoidc"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	"go.pinniped.dev/pkg/oidcclient/pkce"
	"go.pinniped.dev/pkg/oidcclient/state"
)

const (
	// minIDTokenValidity is the minimum amount of time that a cached ID token must be still be valid to be considered.
	// This is non-zero to ensure that most of the time, your ID token won't expire in the middle of a multi-step k8s
	// API operation.
	minIDTokenValidity = 10 * time.Minute

	// httpRequestTimeout is the timeout for operations that involve one (or a few) non-interactive HTTPS requests.
	// Since these don't involve any user interaction, they should always be roughly as fast as network latency.
	httpRequestTimeout = 60 * time.Second

	// overallTimeout is the overall time that a login is allowed to take. This includes several user interactions, so
	// we set this to be relatively long.
	overallTimeout = 90 * time.Minute

	defaultLDAPUsernamePrompt = "Username: "
	defaultLDAPPasswordPrompt = "Password: "

	// For CLI-based auth, such as with LDAP upstream identity providers, the user may use these environment variables
	// to avoid getting interactively prompted for username and password.
	defaultUsernameEnvVarName = "PINNIPED_USERNAME"
	defaultPasswordEnvVarName = "PINNIPED_PASSWORD" //nolint:gosec // this is not a credential

	httpLocationHeaderName = "Location"
)

// stdin returns the file descriptor for stdin as an int.
func stdin() int { return int(os.Stdin.Fd()) }

type handlerState struct {
	// Basic parameters.
	ctx      context.Context
	logger   logr.Logger
	issuer   string
	clientID string
	scopes   []string
	cache    SessionCache

	upstreamIdentityProviderName string
	upstreamIdentityProviderType string
	cliToSendCredentials         bool

	requestedAudience string

	httpClient *http.Client

	// Parameters of the localhost listener.
	listenAddr   string
	callbackPath string

	// Generated parameters of a login flow.
	provider     *coreosoidc.Provider
	oauth2Config *oauth2.Config
	useFormPost  bool
	state        state.State
	nonce        nonce.Nonce
	pkce         pkce.Code

	// External calls for things.
	generateState   func() (state.State, error)
	generatePKCE    func() (pkce.Code, error)
	generateNonce   func() (nonce.Nonce, error)
	openURL         func(string) error
	getEnv          func(key string) string
	listen          func(string, string) (net.Listener, error)
	isTTY           func(int) bool
	getProvider     func(*oauth2.Config, *coreosoidc.Provider, *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI
	validateIDToken func(ctx context.Context, provider *coreosoidc.Provider, audience string, token string) (*coreosoidc.IDToken, error)
	promptForValue  func(ctx context.Context, promptLabel string) (string, error)
	promptForSecret func(promptLabel string) (string, error)

	callbacks chan callbackResult
}

type callbackResult struct {
	token *oidctypes.Token
	err   error
}

// Option is an optional configuration for Login().
type Option func(*handlerState) error

// WithContext specifies a specific context.Context under which to perform the login. If this option is not specified,
// login happens under context.Background().
func WithContext(ctx context.Context) Option {
	return func(h *handlerState) error {
		h.ctx = ctx
		return nil
	}
}

// WithLogger specifies a PLogger to use with the login.
// If not specified this will default to a new logger.
func WithLogger(logger logr.Logger) Option {
	return func(h *handlerState) error {
		h.logger = logger
		return nil
	}
}

// WithListenPort specifies a TCP listen port on localhost, which will be used for the redirect_uri and to handle the
// authorization code callback. By default, a random high port will be chosen which requires the authorization server
// to support wildcard port numbers as described by https://tools.ietf.org/html/rfc8252#section-7.3:
//
// The authorization server MUST allow any port to be specified at the
// time of the request for loopback IP redirect URIs, to accommodate
// clients that obtain an available ephemeral port from the operating
// system at the time of the request.
func WithListenPort(port uint16) Option {
	return func(h *handlerState) error {
		h.listenAddr = net.JoinHostPort("localhost", fmt.Sprint(port))
		return nil
	}
}

// WithScopes sets the OAuth2 scopes to request during login. If not specified, it defaults to
// "offline_access openid email profile".
func WithScopes(scopes []string) Option {
	return func(h *handlerState) error {
		h.scopes = scopes
		return nil
	}
}

// WithBrowserOpen overrides the default "open browser" functionality with a custom callback. If not specified,
// an implementation using https://github.com/pkg/browser will be used by default.
//
// Deprecated: this option will be removed in a future version of Pinniped. See the
// WithSkipBrowserOpen() option instead.
func WithBrowserOpen(openURL func(url string) error) Option {
	return func(h *handlerState) error {
		h.openURL = openURL
		return nil
	}
}

// WithSkipBrowserOpen causes the login to only print the authorize URL, but skips attempting to
// open the user's default web browser.
func WithSkipBrowserOpen() Option {
	return func(h *handlerState) error {
		h.openURL = func(_ string) error { return nil }
		return nil
	}
}

// WithSkipListen causes the login skip starting the localhost listener, forcing the manual copy/paste login flow.
func WithSkipListen() Option {
	return func(h *handlerState) error {
		h.listen = func(string, string) (net.Listener, error) { return nil, nil }
		return nil
	}
}

// SessionCacheKey contains the data used to select a valid session cache entry.
type SessionCacheKey struct {
	Issuer               string   `json:"issuer"`
	ClientID             string   `json:"clientID"`
	Scopes               []string `json:"scopes"`
	RedirectURI          string   `json:"redirect_uri"`
	UpstreamProviderName string   `json:"upstream_provider_name,omitempty"`
}

type SessionCache interface {
	GetToken(SessionCacheKey) *oidctypes.Token
	PutToken(SessionCacheKey, *oidctypes.Token)
}

// WithSessionCache sets the session cache backend for storing and retrieving previously-issued ID tokens and refresh tokens.
func WithSessionCache(cache SessionCache) Option {
	return func(h *handlerState) error {
		h.cache = cache
		return nil
	}
}

// WithClient sets the HTTP client used to make CLI-to-provider requests.
func WithClient(httpClient *http.Client) Option {
	return func(h *handlerState) error {
		h.httpClient = httpClient
		return nil
	}
}

// WithRequestAudience causes the login flow to perform an additional token exchange using the RFC8693 flow.
func WithRequestAudience(audience string) Option {
	return func(h *handlerState) error {
		h.requestedAudience = audience
		return nil
	}
}

// WithCLISendingCredentials causes the login flow to use CLI-based prompts for username and password and causes the
// call to the Issuer's authorize endpoint to be made directly (no web browser) with the username and password on custom
// HTTP headers. This is only intended to be used when the issuer is a Pinniped Supervisor and the upstream identity
// provider type supports this style of authentication. Currently, this is supported by LDAPIdentityProviders, ActiveDirectoryIdentityProviders,
// and by OIDCIdentityProviders which optionally enable the resource owner password credentials grant flow.
// This should never be used with non-Supervisor issuers because it will send the user's password to the authorization
// endpoint as a custom header, which would be ignored but could potentially get logged somewhere by the issuer.
func WithCLISendingCredentials() Option {
	return func(h *handlerState) error {
		h.cliToSendCredentials = true
		return nil
	}
}

// WithUpstreamIdentityProvider causes the specified name and type to be sent as custom query parameters to the
// issuer's authorize endpoint. This is only intended to be used when the issuer is a Pinniped Supervisor, in which
// case it provides a mechanism to choose among several upstream identity providers.
// Other issuers will ignore these custom query parameters.
func WithUpstreamIdentityProvider(upstreamName, upstreamType string) Option {
	return func(h *handlerState) error {
		h.upstreamIdentityProviderName = upstreamName
		h.upstreamIdentityProviderType = upstreamType
		return nil
	}
}

// nopCache is a SessionCache that doesn't actually do anything.
type nopCache struct{}

func (*nopCache) GetToken(SessionCacheKey) *oidctypes.Token  { return nil }
func (*nopCache) PutToken(SessionCacheKey, *oidctypes.Token) {}

// Login performs an OAuth2/OIDC authorization code login using a localhost listener.
func Login(issuer string, clientID string, opts ...Option) (*oidctypes.Token, error) {
	h := handlerState{
		issuer:       issuer,
		clientID:     clientID,
		listenAddr:   "localhost:0",
		scopes:       []string{oidcapi.ScopeOfflineAccess, oidcapi.ScopeOpenID, oidcapi.ScopeEmail, oidcapi.ScopeProfile},
		cache:        &nopCache{},
		callbackPath: "/callback",
		ctx:          context.Background(),
		logger:       logr.Discard(), // discard logs unless a logger is specified
		callbacks:    make(chan callbackResult, 2),
		httpClient:   phttp.Default(nil),

		// Default implementations of external dependencies (to be mocked in tests).
		generateState: state.Generate,
		generateNonce: nonce.Generate,
		generatePKCE:  pkce.Generate,
		openURL:       browser.OpenURL,
		getEnv:        os.Getenv,
		listen:        net.Listen,
		isTTY:         term.IsTerminal,
		getProvider:   upstreamoidc.New,
		validateIDToken: func(ctx context.Context, provider *coreosoidc.Provider, audience string, token string) (*coreosoidc.IDToken, error) {
			return provider.Verifier(&coreosoidc.Config{ClientID: audience}).Verify(ctx, token)
		},
		promptForValue:  promptForValue,
		promptForSecret: promptForSecret,
	}
	for _, opt := range opts {
		if err := opt(&h); err != nil {
			return nil, err
		}
	}

	// Copy the configured HTTP client to set a request timeout (the Go default client has no timeout configured).
	httpClientWithTimeout := *h.httpClient
	httpClientWithTimeout.Timeout = httpRequestTimeout
	h.httpClient = &httpClientWithTimeout

	// Always set a long, but non-infinite timeout for this operation.
	ctx, cancel := context.WithTimeout(h.ctx, overallTimeout)
	defer cancel()
	ctx = coreosoidc.ClientContext(ctx, h.httpClient)
	h.ctx = ctx

	// Initialize login parameters.
	var err error
	h.state, err = h.generateState()
	if err != nil {
		return nil, err
	}
	h.nonce, err = h.generateNonce()
	if err != nil {
		return nil, err
	}
	h.pkce, err = h.generatePKCE()
	if err != nil {
		return nil, err
	}

	// Do the basic login to get an access and ID token issued to our main client ID.
	baseToken, err := h.baseLogin()
	if err != nil {
		return nil, err
	}

	// If there is no requested audience, or the requested audience matches the one we got, we're done.
	if h.requestedAudience == "" || (baseToken.IDToken != nil && h.requestedAudience == baseToken.IDToken.Claims["aud"]) {
		return baseToken, err
	}

	// Perform the RFC8693 token exchange.
	exchangedToken, err := h.tokenExchangeRFC8693(baseToken)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}
	return exchangedToken, nil
}

func (h *handlerState) baseLogin() (*oidctypes.Token, error) {
	// Check the cache for a previous session issued with the same parameters.
	sort.Strings(h.scopes)
	cacheKey := SessionCacheKey{
		Issuer:      h.issuer,
		ClientID:    h.clientID,
		Scopes:      h.scopes,
		RedirectURI: (&url.URL{Scheme: "http", Host: h.listenAddr, Path: h.callbackPath}).String(),
		// When using a Supervisor with multiple IDPs, the cache keys need to be different for each IDP
		// so a user can have multiple sessions going for each IDP at the same time.
		// When using a non-Supervisor OIDC provider, then this value will be blank, so it won't be part of the key.
		UpstreamProviderName: h.upstreamIdentityProviderName,
	}

	// If the ID token is still valid for a bit, return it immediately and skip the rest of the flow.
	cached := h.cache.GetToken(cacheKey)
	if cached != nil && cached.IDToken != nil && time.Until(cached.IDToken.Expiry.Time) > minIDTokenValidity {
		h.logger.V(plog.KlogLevelDebug).Info("Pinniped: Found unexpired cached token.")
		return cached, nil
	}

	// Perform OIDC discovery.
	if err := h.initOIDCDiscovery(); err != nil {
		return nil, err
	}

	// If there was a cached refresh token, attempt to use the refresh flow instead of a fresh login.
	if cached != nil && cached.RefreshToken != nil && cached.RefreshToken.Token != "" {
		freshToken, err := h.handleRefresh(h.ctx, cached.RefreshToken)
		if err != nil {
			return nil, err
		}
		// If we got a fresh token, we can update the cache and return it. Otherwise we fall through to the full refresh flow.
		if freshToken != nil {
			h.cache.PutToken(cacheKey, freshToken)
			return freshToken, nil
		}
	}

	// Prepare the common options for the authorization URL. We don't have the redirect URL yet though.
	authorizeOptions := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		h.nonce.Param(),
		h.pkce.Challenge(),
		h.pkce.Method(),
	}
	if h.upstreamIdentityProviderName != "" {
		authorizeOptions = append(authorizeOptions,
			oauth2.SetAuthURLParam(oidcapi.AuthorizeUpstreamIDPNameParamName, h.upstreamIdentityProviderName),
		)
		authorizeOptions = append(authorizeOptions,
			oauth2.SetAuthURLParam(oidcapi.AuthorizeUpstreamIDPTypeParamName, h.upstreamIdentityProviderType),
		)
	}

	// Choose the appropriate authorization and authcode exchange strategy.
	var authFunc = h.webBrowserBasedAuth
	if h.cliToSendCredentials {
		authFunc = h.cliBasedAuth
	}

	// Perform the authorize request and authcode exchange to get back OIDC tokens.
	token, err := authFunc(&authorizeOptions)

	// If we got tokens, put them in the cache.
	if err == nil {
		h.cache.PutToken(cacheKey, token)
	}

	return token, err
}

// Make a direct call to the authorize endpoint, including the user's username and password on custom http headers,
// and parse the authcode from the response. Exchange the authcode for tokens. Return the tokens or an error.
func (h *handlerState) cliBasedAuth(authorizeOptions *[]oauth2.AuthCodeOption) (*oidctypes.Token, error) {
	// Ask the user for their username and password, or get them from env vars.
	username, password, err := h.getUsernameAndPassword()
	if err != nil {
		return nil, err
	}

	// Make a callback URL even though we won't be listening on this port, because providing a redirect URL is
	// required for OIDC authorize endpoints, and it must match the allowed redirect URL of the OIDC client
	// registered on the server. The Supervisor oauth client does not have "localhost" in the allowed redirect
	// URI list, so use 127.0.0.1.
	localhostAddr := strings.ReplaceAll(h.listenAddr, "localhost", "127.0.0.1")
	h.oauth2Config.RedirectURL = (&url.URL{
		Scheme: "http",
		Host:   localhostAddr,
		Path:   h.callbackPath,
	}).String()

	// Now that we have a redirect URL, we can build the authorize URL.
	authorizeURL := h.oauth2Config.AuthCodeURL(h.state.String(), *authorizeOptions...)

	// Don't follow redirects automatically because we want to handle redirects here.
	var sawRedirect bool
	h.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		sawRedirect = true
		return http.ErrUseLastResponse
	}

	// Send an authorize request.
	authCtx, authorizeCtxCancelFunc := context.WithTimeout(h.ctx, httpRequestTimeout)
	defer authorizeCtxCancelFunc()
	authReq, err := http.NewRequestWithContext(authCtx, http.MethodGet, authorizeURL, nil)
	if err != nil {
		return nil, fmt.Errorf("could not build authorize request: %w", err)
	}
	authReq.Header.Set(oidcapi.AuthorizeUsernameHeaderName, username)
	authReq.Header.Set(oidcapi.AuthorizePasswordHeaderName, password)
	authRes, err := h.httpClient.Do(authReq)
	if err != nil {
		return nil, fmt.Errorf("authorization response error: %w", err)
	}
	_ = authRes.Body.Close() // don't need the response body, and okay if it fails to close

	// A successful authorization always results in a redirect (we are flexible on the exact status code).
	if !sawRedirect {
		return nil, fmt.Errorf(
			"error getting authorization: expected to be redirected, but response status was %s", authRes.Status)
	}
	rawLocation := authRes.Header.Get(httpLocationHeaderName)
	location, err := url.Parse(rawLocation)
	if err != nil {
		// This shouldn't be possible in practice because httpClient.Do() already parses the Location header.
		return nil, fmt.Errorf("error getting authorization: could not parse redirect location: %w", err)
	}

	// Check that the redirect was to the expected location.
	if location.Scheme != "http" || location.Host != localhostAddr || location.Path != h.callbackPath {
		return nil, fmt.Errorf("error getting authorization: redirected to the wrong location: %s", rawLocation)
	}

	// Validate OAuth2 state and fail if it's incorrect (to block CSRF).
	if err := h.state.Validate(location.Query().Get("state")); err != nil {
		return nil, fmt.Errorf("missing or invalid state parameter in authorization response: %s", rawLocation)
	}

	// Get the auth code or return the error from the server.
	authCode := location.Query().Get("code")
	if authCode == "" {
		// Check for error response parameters. See https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
		requiredErrorCode := location.Query().Get("error")
		optionalErrorDescription := location.Query().Get("error_description")
		if optionalErrorDescription == "" {
			return nil, fmt.Errorf("login failed with code %q", requiredErrorCode)
		}
		return nil, fmt.Errorf("login failed with code %q: %s", requiredErrorCode, optionalErrorDescription)
	}

	// Exchange the authorization code for access, ID, and refresh tokens and perform required
	// validations on the returned ID token.
	tokenCtx, tokenCtxCancelFunc := context.WithTimeout(h.ctx, httpRequestTimeout)
	defer tokenCtxCancelFunc()
	token, err := h.getProvider(h.oauth2Config, h.provider, h.httpClient).
		ExchangeAuthcodeAndValidateTokens(
			tokenCtx,
			authCode,
			h.pkce,
			h.nonce,
			h.oauth2Config.RedirectURL,
		)
	if err != nil {
		return nil, fmt.Errorf("error during authorization code exchange: %w", err)
	}

	return token, nil
}

// Prompt for the user's username and password, or read them from env vars if they are available.
func (h *handlerState) getUsernameAndPassword() (string, string, error) {
	var err error

	username := h.getEnv(defaultUsernameEnvVarName)
	if username == "" {
		username, err = h.promptForValue(h.ctx, defaultLDAPUsernamePrompt)
		if err != nil {
			return "", "", fmt.Errorf("error prompting for username: %w", err)
		}
	} else {
		h.logger.V(plog.KlogLevelDebug).Info("Pinniped: Read username from environment variable", "name", defaultUsernameEnvVarName)
	}

	password := h.getEnv(defaultPasswordEnvVarName)
	if password == "" {
		password, err = h.promptForSecret(defaultLDAPPasswordPrompt)
		if err != nil {
			return "", "", fmt.Errorf("error prompting for password: %w", err)
		}
	} else {
		h.logger.V(plog.KlogLevelDebug).Info("Pinniped: Read password from environment variable", "name", defaultPasswordEnvVarName)
	}

	return username, password, nil
}

// Open a web browser, or ask the user to open a web browser, to visit the authorize endpoint.
// Create a localhost callback listener which exchanges the authcode for tokens. Return the tokens or an error.
func (h *handlerState) webBrowserBasedAuth(authorizeOptions *[]oauth2.AuthCodeOption) (*oidctypes.Token, error) {
	// Attempt to open a local TCP listener, logging but otherwise ignoring any error.
	listener, err := h.listen("tcp", h.listenAddr)
	if err != nil {
		h.logger.V(plog.KlogLevelDebug).Error(err, "could not open callback listener")
	}

	// If the listener failed to start and stdin is not a TTY, then we have no hope of succeeding,
	// since we won't be able to receive the web callback and we can't prompt for the manual auth code.
	if listener == nil && !h.isTTY(stdin()) {
		return nil, fmt.Errorf("login failed: must have either a localhost listener or stdin must be a TTY")
	}

	// Update the OAuth2 redirect_uri to match the actual listener address (if there is one), or just use
	// a fake ":0" port if there is no listener running.
	redirectURI := url.URL{Scheme: "http", Path: h.callbackPath}
	if listener == nil {
		redirectURI.Host = "127.0.0.1:0"
	} else {
		redirectURI.Host = listener.Addr().String()
	}
	h.oauth2Config.RedirectURL = redirectURI.String()

	// If the server supports it, request response_mode=form_post.
	authParams := *authorizeOptions
	if h.useFormPost {
		authParams = append(authParams, oauth2.SetAuthURLParam("response_mode", "form_post"))
	}

	// Now that we have a redirect URL with the listener port, we can build the authorize URL.
	authorizeURL := h.oauth2Config.AuthCodeURL(h.state.String(), authParams...)

	// If there is a listener running, start serving the callback handler in a background goroutine.
	if listener != nil {
		shutdown := h.serve(listener)
		defer shutdown()
	}

	// Open the authorize URL in the users browser, logging but otherwise ignoring any error.
	if err := h.openURL(authorizeURL); err != nil {
		h.logger.V(plog.KlogLevelDebug).Error(err, "could not open browser")
	}

	// Prompt the user to visit the authorize URL, and to paste a manually-copied auth code (if possible).
	ctx, cancel := context.WithCancel(h.ctx)
	cleanupPrompt := h.promptForWebLogin(ctx, authorizeURL, os.Stderr)
	defer func() {
		cancel()
		cleanupPrompt()
	}()

	// Wait for either the web callback, a pasted auth code, or a timeout.
	select {
	case <-h.ctx.Done():
		return nil, fmt.Errorf("timed out waiting for token callback: %w", h.ctx.Err())
	case callback := <-h.callbacks:
		if callback.err != nil {
			return nil, fmt.Errorf("error handling callback: %w", callback.err)
		}
		return callback.token, nil
	}
}

func (h *handlerState) promptForWebLogin(ctx context.Context, authorizeURL string, out io.Writer) func() {
	_, _ = fmt.Fprintf(out, "Log in by visiting this link:\n\n    %s\n\n", authorizeURL)

	// If stdin is not a TTY, print the URL but don't prompt for the manual paste,
	// since we have no way of reading it.
	if !h.isTTY(stdin()) {
		return func() {}
	}

	// If the server didn't support response_mode=form_post, don't bother prompting for the manual
	// code because the user isn't going to have any easy way to manually copy it anyway.
	if !h.useFormPost {
		return func() {}
	}

	// Launch the manual auth code prompt in a background goroutine, which will be cancelled
	// if the parent context is cancelled (when the login succeeds or times out).
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer func() {
			// Always emit a newline so the kubectl output is visually separated from the login prompts.
			_, _ = fmt.Fprintln(os.Stderr)

			wg.Done()
		}()
		code, err := h.promptForValue(ctx, "    Optionally, paste your authorization code: ")
		if err != nil {
			// Print a visual marker to show the the prompt is no longer waiting for user input, plus a trailing
			// newline that simulates the user having pressed "enter".
			_, _ = fmt.Fprint(os.Stderr, "[...]\n")

			h.callbacks <- callbackResult{err: fmt.Errorf("failed to prompt for manual authorization code: %v", err)}
			return
		}

		// When a code is pasted, redeem it for a token and return that result on the callbacks channel.
		token, err := h.redeemAuthCode(ctx, code)
		h.callbacks <- callbackResult{token: token, err: err}
	}()
	return wg.Wait
}

func promptForValue(ctx context.Context, promptLabel string) (string, error) {
	if !term.IsTerminal(stdin()) {
		return "", errors.New("stdin is not connected to a terminal")
	}
	_, err := fmt.Fprint(os.Stderr, promptLabel)
	if err != nil {
		return "", fmt.Errorf("could not print prompt to stderr: %w", err)
	}

	type readResult struct {
		text string
		err  error
	}
	readResults := make(chan readResult)
	go func() {
		text, err := bufio.NewReader(os.Stdin).ReadString('\n')
		readResults <- readResult{text, err}
		close(readResults)
	}()

	// If the context is canceled, return immediately. The ReadString() operation will stay hung in the background
	// goroutine indefinitely.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-readResults:
		return strings.TrimSpace(r.text), r.err
	}
}

func promptForSecret(promptLabel string) (string, error) {
	if !term.IsTerminal(stdin()) {
		return "", errors.New("stdin is not connected to a terminal")
	}
	_, err := fmt.Fprint(os.Stderr, promptLabel)
	if err != nil {
		return "", fmt.Errorf("could not print prompt to stderr: %w", err)
	}
	password, err := term.ReadPassword(stdin())
	if err != nil {
		return "", fmt.Errorf("could not read password: %w", err)
	}
	// term.ReadPassword swallows the newline that was typed by the user, so to
	// avoid the next line of output from happening on same line as the password
	// prompt, we need to print a newline.
	_, err = fmt.Fprint(os.Stderr, "\n")
	if err != nil {
		return "", fmt.Errorf("could not print newline to stderr: %w", err)
	}
	return string(password), err
}

func (h *handlerState) initOIDCDiscovery() error {
	// Make this method idempotent so it can be called in multiple cases with no extra network requests.
	if h.provider != nil {
		return nil
	}

	// Validate that the issuer URL uses https, or else we cannot trust its discovery endpoint to get the other URLs.
	if err := validateURLUsesHTTPS(h.issuer, "issuer"); err != nil {
		return err
	}

	h.logger.V(plog.KlogLevelDebug).Info("Pinniped: Performing OIDC discovery", "issuer", h.issuer)
	var err error
	h.provider, err = coreosoidc.NewProvider(h.ctx, h.issuer)
	if err != nil {
		return fmt.Errorf("could not perform OIDC discovery for %q: %w", h.issuer, err)
	}

	// Build an OAuth2 configuration based on the OIDC discovery data and our callback endpoint.
	h.oauth2Config = &oauth2.Config{
		ClientID: h.clientID,
		Endpoint: h.provider.Endpoint(),
		Scopes:   h.scopes,
	}

	// Validate that the discovered auth and token URLs use https. The OIDC spec for the authcode flow says:
	// "Communication with the Authorization Endpoint MUST utilize TLS"
	// (see https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint), and
	// "Communication with the Token Endpoint MUST utilize TLS"
	// (see https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint).
	if err := validateURLUsesHTTPS(h.provider.Endpoint().AuthURL, "discovered authorize URL from issuer"); err != nil {
		return err
	}
	if err := validateURLUsesHTTPS(h.provider.Endpoint().TokenURL, "discovered token URL from issuer"); err != nil {
		return err
	}

	// Use response_mode=form_post if the provider supports it.
	var discoveryClaims struct {
		ResponseModesSupported []string `json:"response_modes_supported"`
	}
	if err := h.provider.Claims(&discoveryClaims); err != nil {
		return fmt.Errorf("could not decode response_modes_supported in OIDC discovery from %q: %w", h.issuer, err)
	}
	h.useFormPost = slices.Contains(discoveryClaims.ResponseModesSupported, "form_post")
	return nil
}

func validateURLUsesHTTPS(uri string, uriName string) error {
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", uriName, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("%s must be an https URL, but had scheme %q instead", uriName, parsed.Scheme)
	}
	return nil
}

func (h *handlerState) tokenExchangeRFC8693(baseToken *oidctypes.Token) (*oidctypes.Token, error) {
	h.logger.V(plog.KlogLevelDebug).Info("Pinniped: Performing RFC8693 token exchange", "requestedAudience", h.requestedAudience)
	// Perform OIDC discovery. This may have already been performed if there was not a cached base token.
	if err := h.initOIDCDiscovery(); err != nil {
		return nil, err
	}

	// Form the HTTP POST request with the parameters specified by RFC8693.
	reqBody := strings.NewReader(url.Values{
		"client_id":            []string{h.clientID},
		"grant_type":           []string{oidcapi.GrantTypeTokenExchange},
		"audience":             []string{h.requestedAudience},
		"subject_token":        []string{baseToken.AccessToken.Token},
		"subject_token_type":   []string{"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": []string{"urn:ietf:params:oauth:token-type:jwt"},
	}.Encode())
	req, err := http.NewRequestWithContext(h.ctx, http.MethodPost, h.oauth2Config.Endpoint.TokenURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("could not build RFC8693 request: %w", err)
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")

	// Perform the request.
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Expect an HTTP 200 response with "application/json" content type.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("content-type"))
	if err != nil {
		return nil, fmt.Errorf("failed to decode content-type header: %w", err)
	}
	if mediaType != "application/json" {
		return nil, fmt.Errorf("unexpected HTTP response content type %q", mediaType)
	}

	// Decode the JSON response body.
	var respBody struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Expect the token_type and issued_token_type response parameters to have some known values.
	if respBody.TokenType != "N_A" {
		return nil, fmt.Errorf("got unexpected token_type %q", respBody.TokenType)
	}
	if respBody.IssuedTokenType != "urn:ietf:params:oauth:token-type:jwt" {
		return nil, fmt.Errorf("got unexpected issued_token_type %q", respBody.IssuedTokenType)
	}

	// Validate the returned JWT to make sure we got the audience we wanted and extract the expiration time.
	stsToken, err := h.validateIDToken(h.ctx, h.provider, h.requestedAudience, respBody.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("received invalid JWT: %w", err)
	}

	return &oidctypes.Token{IDToken: &oidctypes.IDToken{
		Token:  respBody.AccessToken,
		Expiry: metav1.NewTime(stsToken.Expiry),
	}}, nil
}

func (h *handlerState) handleRefresh(ctx context.Context, refreshToken *oidctypes.RefreshToken) (*oidctypes.Token, error) {
	h.logger.V(plog.KlogLevelDebug).Info("Pinniped: Refreshing cached token.")
	upstreamOIDCIdentityProvider := h.getProvider(h.oauth2Config, h.provider, h.httpClient)

	refreshed, err := upstreamOIDCIdentityProvider.PerformRefresh(ctx, refreshToken.Token)
	if err != nil {
		// Ignore errors during refresh, but return nil which will trigger the full login flow.
		h.logger.V(plog.KlogLevelDebug).Info("Pinniped: Refresh failed.", "error", err.Error())
		return nil, nil
	}

	// The spec is not 100% clear about whether an ID token from the refresh flow should include a nonce, and at least
	// some providers do not include one, so we skip the nonce validation here (but not other validations).
	return upstreamOIDCIdentityProvider.ValidateTokenAndMergeWithUserInfo(ctx, refreshed, "", true, false)
}

func (h *handlerState) handleAuthCodeCallback(w http.ResponseWriter, r *http.Request) (err error) {
	// If we return an error, also report it back over the channel to the main CLI thread.
	defer func() {
		if err != nil {
			h.callbacks <- callbackResult{err: err}
		}
	}()

	var params url.Values
	if h.useFormPost { //nolint:nestif
		// Return HTTP 405 for anything that's not a POST or an OPTIONS request.
		if r.Method != http.MethodPost && r.Method != http.MethodOptions {
			h.logger.V(plog.KlogLevelDebug).Info("Pinniped: Got unexpected request on callback listener", "method", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return nil // keep listening for more requests
		}

		// For POST and OPTIONS requests, calculate the allowed origin for CORS.
		issuerURL, parseErr := url.Parse(h.issuer)
		if parseErr != nil {
			return httperr.Wrap(http.StatusInternalServerError, "invalid issuer url", parseErr)
		}
		allowOrigin := issuerURL.Scheme + "://" + issuerURL.Host

		if r.Method == http.MethodOptions {
			// Google Chrome decided that it should do CORS preflight checks for this Javascript form submission POST request.
			// See https://developer.chrome.com/blog/private-network-access-preflight/
			origin := r.Header.Get("Origin")
			if origin == "" {
				// The CORS preflight request should have an origin.
				h.logger.V(plog.KlogLevelDebug).Info("Pinniped: Got OPTIONS request without origin header")
				w.WriteHeader(http.StatusBadRequest)
				return nil // keep listening for more requests
			}
			h.logger.V(plog.KlogLevelDebug).Info("Pinniped: Got CORS preflight request from browser", "origin", origin)
			// To tell the browser that it is okay to make the real POST request, return the following response.
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			w.Header().Set("Vary", "*") // supposed to use Vary when Access-Control-Allow-Origin is a specific host
			w.Header().Set("Access-Control-Allow-Credentials", "false")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Private-Network", "true")
			// If the browser would like to send some headers on the real request, allow them. Chrome doesn't
			// currently send this header at the moment. This is in case some browser in the future decides to
			// request to be allowed to send specific headers by using Access-Control-Request-Headers.
			requestedHeaders := r.Header.Get("Access-Control-Request-Headers")
			if requestedHeaders != "" {
				w.Header().Set("Access-Control-Allow-Headers", requestedHeaders)
			}
			w.WriteHeader(http.StatusNoContent)
			return nil // keep listening for more requests
		} // Otherwise, this is a POST request...

		// Parse and pull the response parameters from an application/x-www-form-urlencoded request body.
		if err := r.ParseForm(); err != nil {
			return httperr.Wrap(http.StatusBadRequest, "invalid form", err)
		}
		params = r.Form

		// Allow CORS requests for POST so in the future our Javascript code can be updated to use the fetch API's
		// mode "cors", and still be compatible with older CLI versions starting with those that have this code
		// for CORS headers. Updating to use CORS would allow our Javascript code (form_post.js) to see the true
		// http response status from this endpoint. Note that the POST response does not need to set as many CORS
		// headers as the OPTIONS preflight response.
		w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		w.Header().Set("Vary", "*") // supposed to use Vary when Access-Control-Allow-Origin is a specific host
	} else {
		// Return HTTP 405 for anything that's not a GET.
		if r.Method != http.MethodGet {
			h.logger.V(plog.KlogLevelDebug).Info("Pinniped: Got unexpected request on callback listener", "method", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return nil // keep listening for more requests
		}

		// Pull response parameters from the URL query string.
		params = r.URL.Query()
	}

	// Validate OAuth2 state and fail if it's incorrect (to block CSRF).
	if err := h.state.Validate(params.Get("state")); err != nil {
		return httperr.New(http.StatusForbidden, "missing or invalid state parameter")
	}

	// Check for error response parameters. See https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	if errorParam := params.Get("error"); errorParam != "" {
		if errorDescParam := params.Get("error_description"); errorDescParam != "" {
			return httperr.Newf(http.StatusBadRequest, "login failed with code %q: %s", errorParam, errorDescParam)
		}
		return httperr.Newf(http.StatusBadRequest, "login failed with code %q", errorParam)
	}

	// Exchange the authorization code for access, ID, and refresh tokens and perform required
	// validations on the returned ID token.
	token, err := h.redeemAuthCode(r.Context(), params.Get("code"))
	if err != nil {
		return httperr.Wrap(http.StatusBadRequest, "could not complete code exchange", err)
	}

	h.callbacks <- callbackResult{token: token}
	_, _ = w.Write([]byte("you have been logged in and may now close this tab"))
	return nil
}

func (h *handlerState) redeemAuthCode(ctx context.Context, code string) (*oidctypes.Token, error) {
	return h.getProvider(h.oauth2Config, h.provider, h.httpClient).
		ExchangeAuthcodeAndValidateTokens(
			ctx,
			code,
			h.pkce,
			h.nonce,
			h.oauth2Config.RedirectURL,
		)
}

func (h *handlerState) serve(listener net.Listener) func() {
	mux := http.NewServeMux()
	mux.Handle(h.callbackPath, httperr.HandlerFunc(h.handleAuthCodeCallback))
	srv := http.Server{
		Handler:           securityheader.Wrap(mux),
		BaseContext:       func(_ net.Listener) context.Context { return h.ctx },
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.Serve(listener) }()
	return func() {
		// Gracefully shut down the server, allowing up to 100ms for
		// clients to receive any in-flight responses.
		shutdownCtx, cancel := context.WithTimeout(h.ctx, 100*time.Millisecond)
		_ = srv.Shutdown(shutdownCtx)
		cancel()
	}
}
