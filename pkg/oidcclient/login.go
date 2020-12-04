// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package oidcclient implements a CLI OIDC login flow.
package oidcclient

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/httputil/securityheader"
	"go.pinniped.dev/internal/oidc/provider"
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

	// 	refreshTimeout is the amount of time allotted for OAuth2 refresh operations. Since these don't involve any
	// 	user interaction, they should always be roughly as fast as network latency.
	refreshTimeout = 30 * time.Second
)

type handlerState struct {
	// Basic parameters.
	ctx      context.Context
	issuer   string
	clientID string
	scopes   []string
	cache    SessionCache

	httpClient *http.Client

	// Parameters of the localhost listener.
	listenAddr   string
	callbackPath string

	// Generated parameters of a login flow.
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	state        state.State
	nonce        nonce.Nonce
	pkce         pkce.Code

	// External calls for things.
	generateState func() (state.State, error)
	generatePKCE  func() (pkce.Code, error)
	generateNonce func() (nonce.Nonce, error)
	openURL       func(string) error
	getProvider   func(*oauth2.Config, *oidc.Provider, *http.Client) provider.UpstreamOIDCIdentityProviderI

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

// WithListenPort specifies a TCP listen port on localhost, which will be used for the redirect_uri and to handle the
// authorization code callback. By default, a random high port will be chosen which requires the authorization server
// to support wildcard port numbers as described by https://tools.ietf.org/html/rfc8252:
//
// The authorization server MUST allow any port to be specified at the
// time of the request for loopback IP redirect URIs, to accommodate
// clients that obtain an available ephemeral port from the operating
// system at the time of the request.
func WithListenPort(port uint16) Option {
	return func(h *handlerState) error {
		h.listenAddr = fmt.Sprintf("localhost:%d", port)
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
func WithBrowserOpen(openURL func(url string) error) Option {
	return func(h *handlerState) error {
		h.openURL = openURL
		return nil
	}
}

// SessionCacheKey contains the data used to select a valid session cache entry.
type SessionCacheKey struct {
	Issuer      string   `json:"issuer"`
	ClientID    string   `json:"clientID"`
	Scopes      []string `json:"scopes"`
	RedirectURI string   `json:"redirect_uri"`
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
		scopes:       []string{"offline_access", "openid", "email", "profile"},
		cache:        &nopCache{},
		callbackPath: "/callback",
		ctx:          context.Background(),
		callbacks:    make(chan callbackResult),
		httpClient:   http.DefaultClient,

		// Default implementations of external dependencies (to be mocked in tests).
		generateState: state.Generate,
		generateNonce: nonce.Generate,
		generatePKCE:  pkce.Generate,
		openURL:       browser.OpenURL,
		getProvider:   upstreamoidc.New,
	}
	for _, opt := range opts {
		if err := opt(&h); err != nil {
			return nil, err
		}
	}

	// Always set a long, but non-infinite timeout for this operation.
	ctx, cancel := context.WithTimeout(h.ctx, 10*time.Minute)
	defer cancel()
	ctx = oidc.ClientContext(ctx, h.httpClient)
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

	// Check the cache for a previous session issued with the same parameters.
	sort.Strings(h.scopes)
	cacheKey := SessionCacheKey{
		Issuer:      h.issuer,
		ClientID:    h.clientID,
		Scopes:      h.scopes,
		RedirectURI: (&url.URL{Scheme: "http", Host: h.listenAddr, Path: h.callbackPath}).String(),
	}

	// If the ID token is still valid for a bit, return it immediately and skip the rest of the flow.
	cached := h.cache.GetToken(cacheKey)
	if cached != nil && cached.IDToken != nil && time.Until(cached.IDToken.Expiry.Time) > minIDTokenValidity {
		return cached, nil
	}

	// Perform OIDC discovery.
	h.provider, err = oidc.NewProvider(h.ctx, h.issuer)
	if err != nil {
		return nil, fmt.Errorf("could not perform OIDC discovery for %q: %w", h.issuer, err)
	}

	// Build an OAuth2 configuration based on the OIDC discovery data and our callback endpoint.
	h.oauth2Config = &oauth2.Config{
		ClientID: h.clientID,
		Endpoint: h.provider.Endpoint(),
		Scopes:   h.scopes,
	}

	// If there was a cached refresh token, attempt to use the refresh flow instead of a fresh login.
	if cached != nil && cached.RefreshToken != nil && cached.RefreshToken.Token != "" {
		freshToken, err := h.handleRefresh(ctx, cached.RefreshToken)
		if err != nil {
			return nil, err
		}
		// If we got a fresh token, we can update the cache and return it. Otherwise we fall through to the full refresh flow.
		if freshToken != nil {
			h.cache.PutToken(cacheKey, freshToken)
			return freshToken, nil
		}
	}

	// Open a TCP listener and update the OAuth2 redirect_uri to match (in case we are using an ephemeral port number).
	listener, err := net.Listen("tcp", h.listenAddr)
	if err != nil {
		return nil, fmt.Errorf("could not open callback listener: %w", err)
	}
	h.oauth2Config.RedirectURL = (&url.URL{
		Scheme: "http",
		Host:   listener.Addr().String(),
		Path:   h.callbackPath,
	}).String()

	// Start a callback server in a background goroutine.
	shutdown := h.serve(listener)
	defer shutdown()

	// Open the authorize URL in the users browser.
	authorizeURL := h.oauth2Config.AuthCodeURL(
		h.state.String(),
		oauth2.AccessTypeOffline,
		h.nonce.Param(),
		h.pkce.Challenge(),
		h.pkce.Method(),
	)
	if err := h.openURL(authorizeURL); err != nil {
		return nil, fmt.Errorf("could not open browser: %w", err)
	}

	// Wait for either the callback or a timeout.
	select {
	case <-h.ctx.Done():
		return nil, fmt.Errorf("timed out waiting for token callback: %w", h.ctx.Err())
	case callback := <-h.callbacks:
		if callback.err != nil {
			return nil, fmt.Errorf("error handling callback: %w", callback.err)
		}
		h.cache.PutToken(cacheKey, callback.token)
		return callback.token, nil
	}
}

func (h *handlerState) handleRefresh(ctx context.Context, refreshToken *oidctypes.RefreshToken) (*oidctypes.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()
	refreshSource := h.oauth2Config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken.Token})

	refreshed, err := refreshSource.Token()
	if err != nil {
		// Ignore errors during refresh, but return nil which will trigger the full login flow.
		return nil, nil
	}

	// The spec is not 100% clear about whether an ID token from the refresh flow should include a nonce, and at least
	// some providers do not include one, so we skip the nonce validation here (but not other validations).
	return h.getProvider(h.oauth2Config, h.provider, h.httpClient).ValidateToken(ctx, refreshed, "")
}

func (h *handlerState) handleAuthCodeCallback(w http.ResponseWriter, r *http.Request) (err error) {
	// If we return an error, also report it back over the channel to the main CLI thread.
	defer func() {
		if err != nil {
			h.callbacks <- callbackResult{err: err}
		}
	}()

	// Return HTTP 405 for anything that's not a GET.
	if r.Method != http.MethodGet {
		return httperr.Newf(http.StatusMethodNotAllowed, "wanted GET")
	}

	// Validate OAuth2 state and fail if it's incorrect (to block CSRF).
	params := r.URL.Query()
	if err := h.state.Validate(params.Get("state")); err != nil {
		return httperr.New(http.StatusForbidden, "missing or invalid state parameter")
	}

	// Check for error response parameters.
	if errorParam := params.Get("error"); errorParam != "" {
		return httperr.Newf(http.StatusBadRequest, "login failed with code %q", errorParam)
	}

	// Exchange the authorization code for access, ID, and refresh tokens and perform required
	// validations on the returned ID token.
	token, err := h.getProvider(h.oauth2Config, h.provider, h.httpClient).
		ExchangeAuthcodeAndValidateTokens(
			r.Context(),
			params.Get("code"),
			h.pkce,
			h.nonce,
			h.oauth2Config.RedirectURL,
		)
	if err != nil {
		return httperr.Wrap(http.StatusBadRequest, "could not complete code exchange", err)
	}

	h.callbacks <- callbackResult{token: token}
	_, _ = w.Write([]byte("you have been logged in and may now close this tab"))
	return nil
}

func (h *handlerState) serve(listener net.Listener) func() {
	mux := http.NewServeMux()
	mux.Handle(h.callbackPath, httperr.HandlerFunc(h.handleAuthCodeCallback))
	srv := http.Server{
		Handler:     securityheader.Wrap(mux),
		BaseContext: func(_ net.Listener) context.Context { return h.ctx },
	}
	go func() { _ = srv.Serve(listener) }()
	return func() {
		// Gracefully shut down the server, allowing up to 5 seconds for
		// clients to receive any in-flight responses.
		shutdownCtx, cancel := context.WithTimeout(h.ctx, 1*time.Second)
		_ = srv.Shutdown(shutdownCtx)
		cancel()
	}
}
