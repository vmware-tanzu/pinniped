// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
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
	"slices"
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

	idpdiscoveryv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/httputil/securityheader"
	"go.pinniped.dev/internal/net/phttp"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/upstreamoidc"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	"go.pinniped.dev/pkg/oidcclient/pkce"
	"go.pinniped.dev/pkg/oidcclient/state"
)

const (
	// minIDTokenValidity is the minimum amount of time that a cached ID token must be still be valid to be considered.
	// This is non-zero to ensure that most of the time, your ID token won't expire in the middle of a multistep k8s
	// API operation.
	minIDTokenValidity = 10 * time.Minute

	// minAccessTokenValidity is the minimum amount of time that a cached access token must be still be valid
	// to be considered.
	// This is non-zero to ensure that most of the time, your access token won't expire before we submit it for
	// RFC8693 token exchange.
	minAccessTokenValidity = 10 * time.Second

	// httpRequestTimeout is the timeout for operations that involve one (or a few) non-interactive HTTPS requests.
	// Since these don't involve any user interaction, they should always be roughly as fast as network latency.
	httpRequestTimeout = 60 * time.Second

	// overallTimeout is the overall time that a login is allowed to take. This includes several user interactions, so
	// we set this to be relatively long.
	overallTimeout = 90 * time.Minute

	usernamePrompt = "Username: "
	passwordPrompt = "Password: "

	// For CLI-based auth, such as with LDAP upstream identity providers, the user may use these environment variables
	// to avoid getting interactively prompted for username and password.
	defaultUsernameEnvVarName = "PINNIPED_USERNAME"
	defaultPasswordEnvVarName = "PINNIPED_PASSWORD" //nolint:gosec // this is not a credential

	httpLocationHeaderName = "Location"
)

// stdin returns the file descriptor for stdin as an int.
func stdin() int { return int(os.Stdin.Fd()) } //nolint:gosec // this is an int, cast to uintptr, cast back to int

type handlerState struct {
	// Basic parameters.
	ctx      context.Context
	logger   Logger
	issuer   string
	clientID string
	scopes   []string
	cache    SessionCache
	out      io.Writer // this is stderr except in unit tests

	loggerOptionsCount int

	// Tracking the usage of some other functional options.
	upstreamIdentityProviderName string
	upstreamIdentityProviderType idpdiscoveryv1alpha1.IDPType
	cliToSendCredentials         bool
	loginFlow                    idpdiscoveryv1alpha1.IDPFlow
	skipBrowser                  bool
	skipPrintLoginURL            bool
	requestedAudience            string
	httpClient                   *http.Client

	// Parameters of the localhost listener.
	listenAddr   string
	callbackPath string

	// Generated parameters of a login flow.
	provider     *coreosoidc.Provider
	idpDiscovery *idpdiscoveryv1alpha1.IDPDiscoveryResponse
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
	stdinIsTTY      func() bool
	getProvider     func(*oauth2.Config, *coreosoidc.Provider, *http.Client) upstreamprovider.UpstreamOIDCIdentityProviderI
	validateIDToken func(ctx context.Context, provider *coreosoidc.Provider, audience string, token string) (*coreosoidc.IDToken, error)
	promptForValue  func(ctx context.Context, promptLabel string, out io.Writer) (string, error)
	promptForSecret func(promptLabel string, out io.Writer) (string, error)

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

type Logger interface {
	Error(msg string, err error, keysAndValues ...any)
	Info(msg string, keysAndValues ...any)
}

type logrLoggerWrapper struct {
	logger logr.Logger
}

var _ Logger = (*logrLoggerWrapper)(nil)

func (l *logrLoggerWrapper) Error(msg string, err error, keysAndValues ...any) {
	l.logger.V(plog.KlogLevelDebug).Error(err, msg, keysAndValues...)
}

func (l *logrLoggerWrapper) Info(msg string, keysAndValues ...any) {
	l.logger.V(plog.KlogLevelDebug).Info(msg, keysAndValues...)
}

type emptyLogger struct{}

var _ Logger = (*emptyLogger)(nil)

func (e emptyLogger) Error(_ string, _ error, _ ...any) {
	// NOOP
}

func (e emptyLogger) Info(_ string, _ ...any) {
	// NOOP
}

// WithLogger specifies a PLogger to use with the login.
// If not specified this will default to a no-op logger.
//
// Deprecated: Use WithLoginLogger instead.
// This option will be removed in a future version of Pinniped.
// If this option is used along with WithLoginLogger, it will cause an error.
func WithLogger(logger logr.Logger) Option {
	return func(h *handlerState) error {
		h.logger = &logrLoggerWrapper{logger: logger}
		h.loggerOptionsCount++
		return nil
	}
}

// WithLoginLogger specifies a Logger to use.
// If not specified this will default to a no-op logger.
func WithLoginLogger(logger Logger) Option {
	return func(h *handlerState) error {
		h.logger = logger
		h.loggerOptionsCount++
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

// WithSkipBrowserOpen causes the login to only print the authorize URL, but skips attempting to
// open the user's default web browser.
func WithSkipBrowserOpen() Option {
	return func(h *handlerState) error {
		h.skipBrowser = true
		return nil
	}
}

// WithSkipListen causes the login to skip starting the localhost listener, forcing the manual copy/paste login flow.
func WithSkipListen() Option {
	return func(h *handlerState) error {
		h.listen = func(string, string) (net.Listener, error) { return nil, nil }
		return nil
	}
}

// WithSkipPrintLoginURL causes the login to skip printing the login URL when the browser opens to that URL.
func WithSkipPrintLoginURL() Option {
	return func(h *handlerState) error {
		h.skipPrintLoginURL = true
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
//
// Deprecated: this option will be removed in a future version of Pinniped. See the WithLoginFlow() option instead.
// If this option is used along with the WithLoginFlow() option, it will cause an error.
func WithCLISendingCredentials() Option {
	return func(h *handlerState) error {
		h.cliToSendCredentials = true
		return nil
	}
}

// WithLoginFlow chooses the login flow.
// When the argument is equal to idpdiscoveryv1alpha1.IDPFlowCLIPassword, it causes the login flow to use CLI-based
// prompts for username and password and causes the call to the Issuer's authorize endpoint to be made directly (no web
// browser) with the username and password on custom HTTP headers. This is only intended to be used when the issuer is a
// Pinniped Supervisor and the upstream identity provider type supports this style of authentication. Currently, this is
// supported by LDAPIdentityProviders, ActiveDirectoryIdentityProviders, and by OIDCIdentityProviders which optionally
// enable the resource owner password credentials grant flow. This should never be used with non-Supervisor issuers
// because it will send the user's password to the authorization endpoint as a custom header, which would be ignored but
// could potentially get logged somewhere by the issuer.
// When the argument is equal to idpdiscoveryv1alpha1.IDPFlowBrowserAuthcode, it will attempt to open a web browser
// and perform the OIDC authcode flow.
// When not used, the default when the issuer is a Pinniped Supervisor will be determined automatically,
// and the default for non-Supervisor issuers will be the browser authcode flow.
func WithLoginFlow(loginFlow idpdiscoveryv1alpha1.IDPFlow, flowSource string) Option {
	return func(h *handlerState) error {
		switch loginFlow {
		case idpdiscoveryv1alpha1.IDPFlowCLIPassword,
			idpdiscoveryv1alpha1.IDPFlowBrowserAuthcode:
		default:
			return fmt.Errorf(
				"WithLoginFlow error: loginFlow '%s' from '%s' must be '%s' or '%s'",
				loginFlow,
				flowSource,
				idpdiscoveryv1alpha1.IDPFlowCLIPassword,
				idpdiscoveryv1alpha1.IDPFlowBrowserAuthcode,
			)
		}
		h.loginFlow = loginFlow
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

		// Do not perform validation on this cast.
		// If possible, dynamic validation against a Pinniped Supervisor's supported IDP types will be performed.
		h.upstreamIdentityProviderType = idpdiscoveryv1alpha1.IDPType(upstreamType)
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
		logger:       &emptyLogger{},
		callbacks:    make(chan callbackResult, 2),
		httpClient:   phttp.Default(nil),

		// Default implementations of external dependencies (to be mocked in tests).
		generateState: state.Generate,
		generateNonce: nonce.Generate,
		generatePKCE:  pkce.Generate,
		openURL:       browser.OpenURL,
		getEnv:        os.Getenv,
		listen:        net.Listen,
		stdinIsTTY:    func() bool { return term.IsTerminal(stdin()) },
		getProvider:   upstreamoidc.New,
		validateIDToken: func(ctx context.Context, provider *coreosoidc.Provider, audience string, token string) (*coreosoidc.IDToken, error) {
			return provider.Verifier(&coreosoidc.Config{ClientID: audience}).Verify(ctx, token)
		},
		promptForValue:  promptForValue,
		promptForSecret: promptForSecret,
		out:             os.Stderr,
	}
	for _, opt := range opts {
		if err := opt(&h); err != nil {
			return nil, err
		}
	}

	if h.cliToSendCredentials {
		if h.loginFlow != "" {
			return nil, fmt.Errorf("do not use deprecated option WithCLISendingCredentials when using option WithLoginFlow")
		}
		h.loginFlow = idpdiscoveryv1alpha1.IDPFlowCLIPassword
	}

	if h.loggerOptionsCount > 1 {
		return nil, fmt.Errorf("please use only one mechanism to specify the logger")
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
	token, err := h.baseLogin()
	if err != nil {
		return nil, err
	}

	// Perform the RFC8693 token exchange, if needed. Note that the new ID token returned by this exchange
	// does not need to be cached because the new ID token is intended to be a very short-lived token.
	if h.needRFC8693TokenExchange(token) {
		token, err = h.tokenExchangeRFC8693(token)
		if err != nil {
			return nil, fmt.Errorf("failed to exchange token: %w", err)
		}
	}

	return token, nil
}

func (h *handlerState) needRFC8693TokenExchange(token *oidctypes.Token) bool {
	// Need a new ID token if there is a requested audience value and any of the following are true...
	return h.requestedAudience != "" &&
		// we don't have an ID token (maybe it expired or was otherwise removed from the session cache)
		(token.IDToken == nil ||
			// or, our current ID token has a different audience
			h.requestedAudience != token.IDToken.Claims["aud"])
}

func (h *handlerState) tokenValidForNearFuture(token *oidctypes.Token) (bool, string) {
	if token == nil {
		return false, ""
	}
	// If we plan to do an RFC8693 token exchange, then we need an access token that will still be valid when we do the
	// exchange (which will happen momentarily). Otherwise, we need an ID token that will be valid for a little while
	// (long enough for multistep k8s API operations).
	if h.needRFC8693TokenExchange(token) {
		return !accessTokenExpiredOrCloseToExpiring(token.AccessToken), "access_token"
	}
	return !idTokenExpiredOrCloseToExpiring(token.IDToken), "id_token"
}

func accessTokenExpiredOrCloseToExpiring(accessToken *oidctypes.AccessToken) bool {
	return accessToken == nil || time.Until(accessToken.Expiry.Time) <= minAccessTokenValidity
}

func idTokenExpiredOrCloseToExpiring(idToken *oidctypes.IDToken) bool {
	return idToken == nil || time.Until(idToken.Expiry.Time) <= minIDTokenValidity
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

	// If the cached tokens include the token type that we need, and that token is still valid for a bit,
	// return the cached tokens immediately and skip the rest of the flow.
	cached := h.cache.GetToken(cacheKey)
	if valid, whichTokenWasValid := h.tokenValidForNearFuture(cached); valid {
		h.logger.Info("Pinniped: Found unexpired cached token.", "type", whichTokenWasValid)
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
		// If we got a fresh token, update the cache and return it. Otherwise, fall through to the full login flow.
		if freshToken != nil {
			h.cache.PutToken(cacheKey, freshToken)
			return freshToken, nil
		}
	}

	// We couldn't refresh, so now we need to perform a fresh login attempt.
	// Prepare the common options for the authorization URL. We don't have the redirect URL yet though.
	authorizeOptions := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		h.nonce.Param(),
		h.pkce.Challenge(),
		h.pkce.Method(),
	}

	loginFlow, pinnipedSupervisorOptions, err := h.maybePerformPinnipedSupervisorValidations()
	if err != nil {
		return nil, err
	}
	h.loginFlow = loginFlow
	authorizeOptions = slices.Concat(authorizeOptions, pinnipedSupervisorOptions)

	// Preserve the legacy behavior where browser-based auth is preferred
	authFunc := h.webBrowserBasedAuth

	// Choose the appropriate authorization and authcode exchange strategy.
	// Use a switch so that lint will make sure we have full coverage.
	switch h.loginFlow {
	case idpdiscoveryv1alpha1.IDPFlowCLIPassword:
		authFunc = h.cliBasedAuth
	case idpdiscoveryv1alpha1.IDPFlowBrowserAuthcode:
		// NOOP
	}

	// Perform the authorize request and authcode exchange to get back OIDC tokens.
	token, err := authFunc(&authorizeOptions)

	// If we got tokens, put them in the cache.
	if err == nil {
		h.cache.PutToken(cacheKey, token)
	}

	return token, err
}

// maybePerformPinnipedSupervisorValidations will return the flow and some authorization options.
// When the IDP name is unset, it will assume that the server is not a Pinniped Supervisor, and will return immediately.
// Otherwise, when the flow is unset, it will infer the flow from the server, or when the flow is set, it will return that flow unchanged.
// It will also perform additional validations if the issuer is a Pinniped Supervisor.
func (h *handlerState) maybePerformPinnipedSupervisorValidations() (idpdiscoveryv1alpha1.IDPFlow, []oauth2.AuthCodeOption, error) {
	loginFlow := h.loginFlow

	if h.upstreamIdentityProviderName == "" {
		return loginFlow, nil, nil
	}

	if h.idpDiscovery == nil {
		return "", nil, fmt.Errorf("upstream identity provider name %q was specified, but OIDC issuer %q does not "+
			"offer Pinniped-style IDP discovery, so it does not appear to be a Pinniped Supervisor; "+
			"specifying an upstream identity provider name is only meant to be used with Pinniped Supervisors",
			h.upstreamIdentityProviderName, h.issuer)
	}

	// Legacy Pinniped Supervisors do not provide this information. Only run this validation when the information was provided.
	if len(h.idpDiscovery.PinnipedSupportedIDPTypes) > 0 {
		var supportedIDPTypes []idpdiscoveryv1alpha1.IDPType
		for _, idpType := range h.idpDiscovery.PinnipedSupportedIDPTypes {
			supportedIDPTypes = append(supportedIDPTypes, idpType.Type)
		}

		// Sort by name for repeatability
		slices.Sort(supportedIDPTypes)

		if !slices.Contains(supportedIDPTypes, h.upstreamIdentityProviderType) {
			convertIDPListToQuotedStringList := func() []string {
				var temp []string
				for _, idpType := range supportedIDPTypes {
					temp = append(temp, fmt.Sprintf("%q", idpType))
				}
				return temp
			}
			return "", nil, fmt.Errorf("unable to find upstream identity provider with type %q, this Pinniped Supervisor supports IDP types [%s]",
				h.upstreamIdentityProviderType,
				strings.Join(convertIDPListToQuotedStringList(), ", "))
		}
	}

	// Find the IDP from discovery by the specified name, type, and maybe flow.
	foundIDPIndex := slices.IndexFunc(h.idpDiscovery.PinnipedIDPs, func(idp idpdiscoveryv1alpha1.PinnipedIDP) bool {
		return idp.Name == h.upstreamIdentityProviderName &&
			idp.Type == h.upstreamIdentityProviderType &&
			(loginFlow == "" || slices.Contains(idp.Flows, loginFlow))
	})

	// If the IDP was not found...
	if foundIDPIndex < 0 {
		pinnipedIDPsString, err := json.Marshal(h.idpDiscovery.PinnipedIDPs)
		if err != nil {
			// This should never happen. Not unit tested.
			return "", nil, fmt.Errorf("error marshalling IDP discovery response: %w", err)
		}
		if loginFlow == "" {
			return "", nil, fmt.Errorf(
				"unable to find upstream identity provider with name %q and type %q. Found these providers: %s",
				h.upstreamIdentityProviderName,
				h.upstreamIdentityProviderType,
				pinnipedIDPsString,
			)
		}
		return "", nil, fmt.Errorf(
			"unable to find upstream identity provider with name %q and type %q and flow %q. Found these providers: %s",
			h.upstreamIdentityProviderName,
			h.upstreamIdentityProviderType,
			loginFlow,
			pinnipedIDPsString,
		)
	}

	// If the caller has not requested a specific flow, but has requested a specific IDP, infer the authentication flow
	// from the found IDP's discovery information.
	if loginFlow == "" {
		foundIDP := h.idpDiscovery.PinnipedIDPs[foundIDPIndex]
		if len(foundIDP.Flows) == 0 {
			// Note that this should not really happen because the Supervisor's IDP discovery endpoint has always listed flows.
			return "", nil, fmt.Errorf("unable to infer flow for upstream identity provider with name %q and type %q "+
				"because there were no flows discovered for that provider",
				h.upstreamIdentityProviderName,
				h.upstreamIdentityProviderType,
			)
		}
		// The order of the flows returned by the server indicates the server's flow preference,
		// so always use the first flow for that IDP from the discovery response.
		loginFlow = foundIDP.Flows[0]
	}

	var authorizeOptions []oauth2.AuthCodeOption

	authorizeOptions = append(authorizeOptions,
		oauth2.SetAuthURLParam(oidcapi.AuthorizeUpstreamIDPNameParamName, h.upstreamIdentityProviderName),
	)
	authorizeOptions = append(authorizeOptions,
		oauth2.SetAuthURLParam(oidcapi.AuthorizeUpstreamIDPTypeParamName, string(h.upstreamIdentityProviderType)),
	)

	return loginFlow, authorizeOptions, nil
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
	h.httpClient.CheckRedirect = func(_ *http.Request, _via []*http.Request) error {
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
	token, err := h.redeemAuthCode(tokenCtx, authCode)
	if err != nil {
		return nil, fmt.Errorf("could not complete authorization code exchange: %w", err)
	}

	return token, nil
}

// Prompt for the user's username and password, or read them from env vars if they are available.
func (h *handlerState) getUsernameAndPassword() (string, string, error) {
	var err error

	if h.upstreamIdentityProviderName != "" {
		_, _ = fmt.Fprintf(h.out, "\nLog in to %s\n\n", h.upstreamIdentityProviderName)
	}

	username := h.getEnv(defaultUsernameEnvVarName)
	if username == "" {
		username, err = h.promptForValue(h.ctx, usernamePrompt, h.out)
		if err != nil {
			return "", "", fmt.Errorf("error prompting for username: %w", err)
		}
	} else {
		h.logger.Info("Pinniped: Read username from environment variable", "name", defaultUsernameEnvVarName)
	}

	password := h.getEnv(defaultPasswordEnvVarName)
	if password == "" {
		password, err = h.promptForSecret(passwordPrompt, h.out)
		if err != nil {
			return "", "", fmt.Errorf("error prompting for password: %w", err)
		}
	} else {
		h.logger.Info("Pinniped: Read password from environment variable", "name", defaultPasswordEnvVarName)
	}

	return username, password, nil
}

// Open a web browser, or ask the user to open a web browser, to visit the authorize endpoint.
// Create a localhost callback listener which exchanges the authcode for tokens. Return the tokens or an error.
func (h *handlerState) webBrowserBasedAuth(authorizeOptions *[]oauth2.AuthCodeOption) (*oidctypes.Token, error) {
	// Attempt to open a local TCP listener, logging but otherwise ignoring any error.
	listener, err := h.listen("tcp", h.listenAddr)
	if err != nil {
		h.logger.Error("could not open callback listener", err)
	}

	// If the listener failed to start and stdin is not a TTY, then we have no hope of succeeding,
	// since we won't be able to receive the web callback and we can't prompt for the manual auth code.
	if listener == nil && !h.stdinIsTTY() {
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
	// Keep track of whether the browser was opened.
	openedBrowser := false
	if !h.skipBrowser {
		if err := h.openURL(authorizeURL); err != nil {
			h.logger.Error("could not open browser", err)
		} else {
			openedBrowser = true
		}
	}

	// Allow optionally skipping printing the login URL, for example because printing it may confuse
	// a console-based UI program like k9s which invoked this. If the browser was opened, the browser
	// already has the URL. If the browser did not open, then the user has no way to login without the URL,
	// so print it anyway, even though it may confuse apps like k9s.
	printAuthorizeURL := !openedBrowser || !h.skipPrintLoginURL

	// Prompt the user to visit the authorize URL, and to paste a manually-copied auth code (if possible).
	ctx, cancel := context.WithCancel(h.ctx)
	cleanupPrompt := h.promptForWebLogin(ctx, authorizeURL, printAuthorizeURL)
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

// promptForWebLogin prints a login URL to the screen, if needed. It will also print the "paste yor authorization code"
// prompt to the screen and wait for user input, if needed. It can be cancelled by the context provided.
// It returns a function which should be invoked by the caller to perform some cleanup.
func (h *handlerState) promptForWebLogin(ctx context.Context, authorizeURL string, printAuthorizeURL bool) func() {
	if !printAuthorizeURL {
		return func() {}
	}
	_, _ = fmt.Fprintf(h.out, "Log in by visiting this link:\n\n    %s\n\n", authorizeURL)

	// If stdin is not a TTY, don't prompt for the manual paste, since we have no way of reading it.
	if !h.stdinIsTTY() {
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
			_, _ = fmt.Fprintln(h.out)

			wg.Done()
		}()
		code, err := h.promptForValue(ctx, "    Optionally, paste your authorization code: ", h.out)
		if err != nil {
			// Print a visual marker to show the the prompt is no longer waiting for user input, plus a trailing
			// newline that simulates the user having pressed "enter".
			_, _ = fmt.Fprint(h.out, "[...]\n")

			h.callbacks <- callbackResult{err: fmt.Errorf("failed to prompt for manual authorization code: %v", err)}
			return
		}

		// When a code is pasted, redeem it for a token and return the results on the callback channel.
		token, err := h.redeemAuthCode(ctx, code)
		h.callbacks <- callbackResult{token: token, err: err}
	}()
	return wg.Wait
}

// promptForValue interactively prompts the user for a plaintext value and reads their input.
// If the context is canceled, it will return an error immediately.
// This can be replaced by a mock implementation for unit tests.
func promptForValue(ctx context.Context, promptLabel string, out io.Writer) (string, error) {
	if !term.IsTerminal(stdin()) {
		return "", errors.New("stdin is not connected to a terminal")
	}
	_, err := fmt.Fprint(out, promptLabel)
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

// promptForSecret interactively prompts the user for a secret value, obscuring their input while reading it.
// This can be replaced by a mock implementation for unit tests.
func promptForSecret(promptLabel string, out io.Writer) (string, error) {
	if !term.IsTerminal(stdin()) {
		return "", errors.New("stdin is not connected to a terminal")
	}
	_, err := fmt.Fprint(out, promptLabel)
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
	_, err = fmt.Fprint(out, "\n")
	if err != nil {
		return "", fmt.Errorf("could not print newline to stderr: %w", err)
	}
	return string(password), err
}

func (h *handlerState) initOIDCDiscovery() error {
	// Make this method idempotent, so it can be called in multiple cases with no extra network requests.
	if h.provider != nil {
		return nil
	}

	// Validate that the issuer URL uses https, or else we cannot trust its discovery endpoint to get the other URLs.
	if err := validateURLUsesHTTPS(h.issuer, "issuer"); err != nil {
		return err
	}

	h.logger.Info("Pinniped: Performing OIDC discovery", "issuer", h.issuer)
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

	return h.maybePerformPinnipedSupervisorIDPDiscovery()
}

func (h *handlerState) maybePerformPinnipedSupervisorIDPDiscovery() error {
	// If this OIDC IDP is a Pinniped Supervisor, it will have a reference to the IDP discovery document.
	// Go to that document and retrieve the IDPs.
	var pinnipedSupervisorClaims idpdiscoveryv1alpha1.OIDCDiscoveryResponse
	if err := h.provider.Claims(&pinnipedSupervisorClaims); err != nil {
		return fmt.Errorf("could not decode the Pinniped IDP discovery document URL in OIDC discovery from %q: %w", h.issuer, err)
	}

	// This is not an error - it just means that this issuer is not a Pinniped Supervisor.
	// Note that this package can be used with OIDC IDPs other than Pinniped Supervisor.
	if pinnipedSupervisorClaims.SupervisorDiscovery.PinnipedIDPsEndpoint == "" {
		return nil
	}
	// This check confirms that the issuer is hosting the IDP discovery document, which would always be the case for
	// Pinniped Supervisor. Since there are checks above to confirm that the issuer uses HTTPS, IDP discovery will
	// always use HTTPS.
	if !strings.HasPrefix(pinnipedSupervisorClaims.SupervisorDiscovery.PinnipedIDPsEndpoint, h.issuer) {
		return fmt.Errorf("the Pinniped IDP discovery document must always be hosted by the issuer: %q", h.issuer)
	}

	idpDiscoveryCtx, idpDiscoveryCtxCancelFunc := context.WithTimeout(h.ctx, httpRequestTimeout)
	defer idpDiscoveryCtxCancelFunc()
	idpDiscoveryReq, err := http.NewRequestWithContext(idpDiscoveryCtx, http.MethodGet, pinnipedSupervisorClaims.SupervisorDiscovery.PinnipedIDPsEndpoint, nil)
	if err != nil { // untested
		return fmt.Errorf("could not build IDP Discovery request: %w", err)
	}
	idpDiscoveryRes, err := h.httpClient.Do(idpDiscoveryReq)
	if err != nil {
		return fmt.Errorf("IDP Discovery response error: %w", err)
	}
	defer func() {
		_ = idpDiscoveryRes.Body.Close() // We can't do anything if this fails to close
	}()

	if idpDiscoveryRes.StatusCode != http.StatusOK {
		return fmt.Errorf("unable to fetch IDP discovery data from issuer: unexpected http response status: %s", idpDiscoveryRes.Status)
	}

	rawBody, err := io.ReadAll(idpDiscoveryRes.Body)
	if err != nil { // untested
		return fmt.Errorf("unable to fetch IDP discovery data from issuer: could not read response body: %w", err)
	}

	var body idpdiscoveryv1alpha1.IDPDiscoveryResponse
	err = json.Unmarshal(rawBody, &body)
	if err != nil {
		return fmt.Errorf("unable to fetch the Pinniped IDP discovery document: could not parse response JSON: %w", err)
	}

	h.idpDiscovery = &body
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
	h.logger.Info("Pinniped: Performing RFC8693 token exchange", "requestedAudience", h.requestedAudience)
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
	h.logger.Info("Pinniped: Refreshing cached tokens.")
	upstreamOIDCIdentityProvider := h.getProvider(h.oauth2Config, h.provider, h.httpClient)

	refreshed, err := upstreamOIDCIdentityProvider.PerformRefresh(ctx, refreshToken.Token)
	if err != nil {
		// Ignore errors during refresh, but return nil which will trigger the full login flow.
		h.logger.Info("Pinniped: Refresh failed.", "error", err.Error())
		return nil, nil
	}

	// The spec is not 100% clear about whether an ID token from the refresh flow should include a nonce, and at least
	// some providers do not include one, so we skip the nonce validation here (but not other validations).
	return upstreamOIDCIdentityProvider.ValidateTokenAndMergeWithUserInfo(ctx, refreshed, "", true, false)
}

// handleAuthCodeCallback is used as an http handler, so it does not run in the CLI's main goroutine.
// Upon a callback redirect request from an identity provider, it uses a callback channel to communicate
// its results back to the main thread of the CLI. The result can contain either some tokens from the
// identity provider's token endpoint, or the result can contain an error. When the result is an error,
// the CLI's main goroutine is responsible for printing that error to the terminal. At the same time,
// this function serves a web response, and that web response is rendered in the user's browser. So the
// user has two places to look for error messages: in their browser and in the CLI's terminal. Ideally,
// these messages would be the same. Note that using httperr.Wrap will cause the details of the wrapped
// err to be printed by the CLI, but not printed in the browser due to the way that the httperr package
// works, so avoid using httperr.Wrap in this function.
func (h *handlerState) handleAuthCodeCallback(w http.ResponseWriter, r *http.Request) (returnedErr error) {
	defer func() {
		// If we returned an error, then also report it back over the channel to the main CLI goroutine.
		// Because returnedErr is the named return value, inside this defer returnedErr will hold the value
		// returned by any explicit return statement.
		if returnedErr != nil {
			h.callbacks <- callbackResult{err: returnedErr}
		}
	}()

	// Calculate the allowed origin for CORS.
	issuerURL, err := url.Parse(h.issuer)
	if err != nil {
		// This shouldn't happen in practice because the URL is normally validated before this function is called.
		// Avoid using httperr.Wrap because that would hide the details of err from the browser output.
		return httperr.Newf(http.StatusInternalServerError, "invalid issuer url: %s", err.Error())
	}
	allowOrigin := issuerURL.Scheme + "://" + issuerURL.Host

	var params url.Values

	switch r.Method {
	case http.MethodOptions:
		// Google Chrome decided that it should do CORS preflight checks for this Javascript form submission POST request.
		// See https://developer.chrome.com/blog/private-network-access-preflight/
		// It seems like Chrome will likely soon also add CORS preflight checks for GET requests on redirects.
		// See https://chromestatus.com/feature/4869685172764672
		origin := r.Header.Get("Origin")
		if origin == "" {
			// The CORS preflight request should have an origin.
			h.logger.Info("Pinniped: Got OPTIONS request without origin header")
			w.WriteHeader(http.StatusBadRequest)
			return nil // keep listening for more requests
		}
		h.logger.Info("Pinniped: Got CORS preflight request from browser", "origin", origin)
		// To tell the browser that it is okay to make the real POST or GET request, return the following response.
		w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		w.Header().Set("Vary", "*") // supposed to use Vary when Access-Control-Allow-Origin is a specific host
		w.Header().Set("Access-Control-Allow-Credentials", "false")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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

	case http.MethodPost:
		// Parse and pull the response parameters from an application/x-www-form-urlencoded request body.
		if err = r.ParseForm(); err != nil {
			// Avoid using httperr.Wrap because that would hide the details of err from the browser output.
			return httperr.Newf(http.StatusBadRequest, "invalid form: %s", err.Error())
		}
		params = r.Form // grab the params and continue handling this request below

	case http.MethodGet:
		// Pull response parameters from the URL query string.
		params = r.URL.Query() // grab the params and continue handling this request below

	default:
		// Return HTTP 405 for anything that's not a POST, GET, or an OPTIONS request.
		h.logger.Info("Pinniped: Got unexpected request on callback listener", "method", r.Method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil // keep listening for more requests
	}

	// Allow CORS requests for POST so our Javascript code can use the fetch API's mode "cors" (see form_post.js)
	// to allow the JS code see the true http response status from this endpoint. Note that the POST response
	// does not need to set as many CORS headers as the OPTIONS preflight response.
	w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
	w.Header().Set("Vary", "*") // supposed to use Vary when Access-Control-Allow-Origin is a specific host

	// At this point, it doesn't matter if we got the params from a form_post POST request or a regular GET request.
	// Next, validate the params, and if we got an authcode then try to use it to complete the login.

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
		// Avoid using httperr.Wrap because that would hide the details of err from the browser output.
		return httperr.Newf(http.StatusBadRequest, "could not complete authorization code exchange: %s", err.Error())
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
