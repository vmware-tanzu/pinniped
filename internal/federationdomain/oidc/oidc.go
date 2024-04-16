// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package oidc contains common OIDC functionality needed by FederationDomains to implement
// downstream OIDC functionality.
package oidc

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	errorsx "github.com/pkg/errors"

	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/federationdomain/clientregistry"
	"go.pinniped.dev/internal/federationdomain/csrftoken"
	"go.pinniped.dev/internal/federationdomain/endpoints/jwks"
	"go.pinniped.dev/internal/federationdomain/endpoints/tokenexchange"
	"go.pinniped.dev/internal/federationdomain/formposthtml"
	"go.pinniped.dev/internal/federationdomain/idtokenlifespan"
	"go.pinniped.dev/internal/federationdomain/strategy"
	"go.pinniped.dev/internal/federationdomain/timeouts"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

const (
	WellKnownEndpointPath     = "/.well-known/openid-configuration"
	AuthorizationEndpointPath = "/oauth2/authorize"
	TokenEndpointPath         = "/oauth2/token" //nolint:gosec // ignore lint warning that this is a credential
	CallbackEndpointPath      = "/callback"
	ChooseIDPEndpointPath     = "/choose_identity_provider"
	JWKSEndpointPath          = "/jwks.json"
	PinnipedIDPsPathV1Alpha1  = "/v1alpha1/pinniped_identity_providers"
	PinnipedLoginPath         = "/login"
)

const (
	// UpstreamStateParamFormatVersion exists just in case we need to make a breaking change to the format of the
	// upstream state param, we are including a format version number. This gives the opportunity for a future version
	// of Pinniped to have the consumer of this format decide to reject versions that it doesn't understand.
	//
	// Version 1 was the original version.
	// Version 2 added the UpstreamType field to the UpstreamStateParamData struct.
	UpstreamStateParamFormatVersion = "2"

	// UpstreamStateParamEncodingName is the `name` passed to the encoder for encoding the upstream state param value.
	// This name is short because it will be encoded into the upstream state param value, and we're trying to keep that
	// small.
	UpstreamStateParamEncodingName = "s"

	// CSRFCookieName is the name of the browser cookie which shall hold our CSRF value.
	// The `__Host` prefix has a special meaning. See:
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Cookie_prefixes.
	CSRFCookieName = "__Host-pinniped-csrf"

	// CSRFCookieEncodingName is the `name` passed to the encoder for encoding and decoding the CSRF
	// cookie contents.
	CSRFCookieEncodingName = "csrf"

	// CSRFCookieLifespan is the length of time that the CSRF cookie is valid. After this time, the
	// Supervisor's authorization endpoint should give the browser a new CSRF cookie. We set it to
	// a week so that it is unlikely to expire during a login.
	CSRFCookieLifespan = time.Hour * 24 * 7
)

// Encoder is the encoding side of the securecookie.Codec interface.
type Encoder interface {
	Encode(name string, value interface{}) (string, error)
}

// Decoder is the decoding side of the securecookie.Codec interface.
type Decoder interface {
	Decode(name, value string, into interface{}) error
}

// Codec is both the encoding and decoding sides of the securecookie.Codec interface. It is
// interface'd here so that we properly wrap the securecookie dependency.
type Codec interface {
	Encoder
	Decoder
}

// UpstreamStateParamData is the format of the state parameter that we use when we communicate to an
// upstream OIDC provider.
//
// Keep the JSON to a minimal size because the upstream provider could impose size limitations on
// the state param.
type UpstreamStateParamData struct {
	AuthParams    string              `json:"p"`
	UpstreamName  string              `json:"u"`
	UpstreamType  string              `json:"t"`
	Nonce         nonce.Nonce         `json:"n"`
	CSRFToken     csrftoken.CSRFToken `json:"c"`
	PKCECode      pkce.Code           `json:"k"`
	FormatVersion string              `json:"v"`
}

// DefaultOIDCTimeoutsConfiguration returns the default timeouts for the Supervisor server.
func DefaultOIDCTimeoutsConfiguration() timeouts.Configuration {
	// Note: The maximum time that users can access Kubernetes clusters without
	// needing to do a Supervisor refresh is the sum of the access token lifetime,
	// the ID token lifetime, and the Concierge's mTLS client cert lifetime.
	// This is because a client can exchange the access token just before it expires
	// for a new cluster-scoped ID token, and use that just before it expires to get
	// a new mTLS client cert, which grants access to the cluster until it expires.
	//
	// Note that the Concierge's mTLS client cert lifetime is 5 minutes, which can
	// be seen in its source at credentialrequest/rest.go.
	//
	// This maximum total time is important because it represents the longest possible
	// time that a user could continue to use a cluster based on their original login
	// (or most recent refresh) after an administrator of an external identity provider
	// removes the user, revokes their session, changes their group membership,
	// or otherwise makes any type of change to the user's account in the external
	// identity provider that should be noticed by the Supervisor during an upstream
	// refresh.
	//
	// Given the timeouts specified below:
	// For sessions started using a GitHub PAT, this is 8 + 2 + 5 = 15 minutes.
	// For sessions started any other way, this is 2 + 2 + 5 = 9 minutes.
	//
	// The CLI will use a cached mTLS client cert until it expires. For a session
	// started using a GitHub PAT, when first mTLS client cert has expired, the CLI
	// will be able to fetch a second one without performing a refresh for 3 more minutes.
	// If the client is actively making Kubernetes API requests during this time, this
	// should give at least 10 minutes of cluster access (two mTLS client cert lifetimes).
	// For any other session type, when the first mTLS client cert expires, the CLI will
	// need to perform a refresh before it can get a second client cert.

	// Give a generous amount of time for an authorized client to be able to exchange
	// its authcode for tokens.
	authorizationCodeLifespan := 10 * time.Minute

	// This is intended to give a very short amount of time to allow the client to
	// use the access token to exchange for cluster-scoped ID token(s). After this
	// time runs out, they will need to perform a refresh to get a new tokens,
	// ensuring the Supervisor has a chance to revalidate their session often.
	accessTokenLifespan := 2 * time.Minute

	// The ID token can have the same lifespan as the access token. It does not grant
	// access to anything in a typical Pinniped setup.
	idTokenLifespan := accessTokenLifespan

	// This is just long enough to cover a typical work day, giving the end user an
	// experience of logging in once per day to access all their Kubernetes clusters.
	refreshTokenLifespan := 9 * time.Hour

	// Give a little extra time for some storage lifetimes, to avoid the possibility
	// that the storage be garbage collected in the middle of trying to look up the token.
	storageExtraLifetime := time.Minute

	// This is longer than the 5-minute lifetime of mTLS client certs issued by the Concierge,
	// so this should allow a user to fetch another client cert after the first one expires,
	// without needing to refresh their Supervisor session.
	gitHubPATBasedAccessTokenLifespan := 8 * time.Minute

	// Previous versions of the Pinniped CLI would only skip refresh when there is at least
	// 10 minutes left for the cached ID token, so having a short lifetime here will cause those
	// older CLIs to never skip attempting refresh. Refreshes are not allowed for GitHub PAT-based
	// sessions, so those older CLIs will always get a refresh failure and then automatically start
	// a new session. This is unfortunate because it uses more of a user's GitHub API rate limit
	// per hour, and it uses more Supervisor session storage (more new sessions). However, we don't
	// want to make this lifetime long because this is also the lifetime of cluster-scoped ID tokens,
	// which can grant access to clusters, so we will have to live with this. Users can avoid it by
	// upgrading their CLI because newer CLIs will look at the lifespan of the access token (not the
	// ID token) when deciding if a refresh is needed before requesting a new cluster-scoped ID token.
	gitHubPATBasedIDTokenLifespan := idTokenLifespan

	// Give a little extra time for some storage lifetimes, to avoid the possibility
	// that the storage be garbage collected in the middle of trying to look up the token.
	gitHubPATBasedTokenStorageExtraLife := 5 * time.Second

	return timeouts.Configuration{
		// Give enough time for someone to start an interactive authorization flow, go eat lunch,
		// and then finish the authorization afterward.
		UpstreamStateParamLifespan: 90 * time.Minute,

		AuthorizeCodeLifespan: authorizationCodeLifespan,

		AccessTokenLifespan: accessTokenLifespan,
		OverrideDefaultAccessTokenLifespan: func(accessRequest fosite.AccessRequester) (bool, time.Duration) {
			if isGitHubSessionBasedOnPAT(accessRequest) {
				return true, gitHubPATBasedAccessTokenLifespan
			}
			return false, 0
		},

		IDTokenLifespan: idTokenLifespan,
		OverrideDefaultIDTokenLifespan: func(accessRequest fosite.AccessRequester) (bool, time.Duration) {
			client := accessRequest.GetClient()
			// Don't allow OIDCClients to override the default lifetime for ID tokens returned
			// by RFC8693 token exchange. This is not user configurable for now.
			if !accessRequest.GetGrantTypes().ExactOne(oidcapi.GrantTypeTokenExchange) {
				if castClient, ok := client.(*clientregistry.Client); !ok {
					// All clients returned by our client registry implement clientregistry.Client,
					// so this should be a safe cast in practice.
					plog.Error("could not check if client overrides token lifetimes",
						errors.New("could not cast client to *clientregistry.Client"),
						"clientID", client.GetID(), "clientType", reflect.TypeOf(client))
				} else if castClient.IDTokenLifetimeConfiguration > 0 {
					// An OIDCClient resource has provided an override, so use it.
					return true, castClient.IDTokenLifetimeConfiguration
				}
			}

			if isGitHubSessionBasedOnPAT(accessRequest) {
				return true, gitHubPATBasedIDTokenLifespan
			}
			return false, 0
		},

		RefreshTokenLifespan: refreshTokenLifespan,

		AuthorizationCodeSessionStorageLifetime: func(requester fosite.Requester) time.Duration {
			if isGitHubSessionBasedOnPAT(requester) {
				// When refresh is not available, this only needs to live as long as the access token.
				return gitHubPATBasedAccessTokenLifespan + gitHubPATBasedTokenStorageExtraLife
			}
			return authorizationCodeLifespan + refreshTokenLifespan
		},

		PKCESessionStorageLifetime: func(_requester fosite.Requester) time.Duration {
			return authorizationCodeLifespan + storageExtraLifetime
		},

		OIDCSessionStorageLifetime: func(_requester fosite.Requester) time.Duration {
			return authorizationCodeLifespan + storageExtraLifetime
		},

		AccessTokenSessionStorageLifetime: func(requester fosite.Requester) time.Duration {
			if isGitHubSessionBasedOnPAT(requester) {
				// When refresh is not available, this only needs to live as long as the access token.
				return gitHubPATBasedAccessTokenLifespan + gitHubPATBasedTokenStorageExtraLife
			}
			return refreshTokenLifespan + accessTokenLifespan
		},

		RefreshTokenSessionStorageLifetime: func(requester fosite.Requester) time.Duration {
			if isGitHubSessionBasedOnPAT(requester) {
				// When refresh is not intended to be available, we don't need to keep this around.
				// Keeping it would allow the refresh flow to lookup the session and give a nice error
				// message about how that session's type does not support refreshes, but only
				// the Pinniped CLI is allowed to start sessions of this type, so in practice nobody
				// would see those error messages anyway.
				return gitHubPATBasedTokenStorageExtraLife
			}
			return refreshTokenLifespan + accessTokenLifespan
		},
	}
}

func isGitHubSessionBasedOnPAT(requester fosite.Requester) bool {
	// TODO: only return true for GitHub sessions that were started by the piniped-cli client using a Personal Access Token.
	//  Using LDAP sessions here as a temporary stand-in because GitHub auth is not implemented yet.
	isPinnipedCLIClient := requester.GetClient().GetID() == oidcapi.ClientIDPinnipedCLI
	isLDAPSession := false
	custom := requester.GetSession().(*psession.PinnipedSession).Custom
	if custom != nil {
		isLDAPSession = custom.ProviderType == psession.ProviderTypeLDAP
	}
	return false && isPinnipedCLIClient && isLDAPSession // Always return false since we don't use GitHub yet
}

func FositeOauth2Helper(
	oauthStore interface{},
	issuer string,
	hmacSecretOfLengthAtLeast32Func func() []byte,
	jwksProvider jwks.DynamicJWKSProvider,
	timeoutsConfiguration timeouts.Configuration,
) fosite.OAuth2Provider {
	oauthConfig := &fosite.Config{
		IDTokenIssuer: issuer,

		AuthorizeCodeLifespan: timeoutsConfiguration.AuthorizeCodeLifespan,
		IDTokenLifespan:       timeoutsConfiguration.IDTokenLifespan,
		AccessTokenLifespan:   timeoutsConfiguration.AccessTokenLifespan,
		RefreshTokenLifespan:  timeoutsConfiguration.RefreshTokenLifespan,

		ScopeStrategy: fosite.ExactScopeStrategy,
		EnforcePKCE:   true,

		// "offline_access" as per https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
		RefreshTokenScopes: []string{oidcapi.ScopeOfflineAccess},

		// The default is to support all prompt values from the spec.
		// See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
		AllowedPromptValues: nil,

		// Use the fosite default to make it more likely that off the shelf OIDC clients can work with the supervisor.
		MinParameterEntropy: fosite.MinParameterEntropy,

		// do not allow custom scheme redirects, only https and http (on loopback)
		RedirectSecureChecker: fosite.IsRedirectURISecureStrict,

		// html template for rendering the authorization response when the request has response_mode=form_post
		FormPostHTMLTemplate: formposthtml.Template(),

		// defaults to using BCrypt when nil
		ClientSecretsHasher: nil,
	}

	oAuth2Provider := compose.Compose(
		oauthConfig,
		oauthStore,
		&compose.CommonStrategy{
			// Note that Fosite requires the HMAC secret to be at least 32 bytes.
			CoreStrategy:               strategy.NewDynamicOauth2HMACStrategy(oauthConfig, hmacSecretOfLengthAtLeast32Func),
			OpenIDConnectTokenStrategy: strategy.NewDynamicOpenIDConnectECDSAStrategy(oauthConfig, jwksProvider),
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		// Use a custom factory to allow selective overrides of the ID token lifespan during authcode exchange.
		idtokenlifespan.OpenIDConnectExplicitFactory,
		// Use a custom factory to allow selective overrides of the ID token lifespan during refresh.
		idtokenlifespan.OpenIDConnectRefreshFactory,
		compose.OAuth2PKCEFactory,
		tokenexchange.HandlerFactory, // handle the "urn:ietf:params:oauth:grant-type:token-exchange" grant type
	)

	return oAuth2Provider
}

// FositeErrorForLog generates a list of information about the provided Fosite error that can be
// passed to a plog function (e.g., plog.Info()).
//
// Sample usage:
//
//	err := someFositeLibraryFunction()
//	if err != nil {
//	    plog.Info("some error", FositeErrorForLog(err)...)
//	    ...
//	}
func FositeErrorForLog(err error) []interface{} {
	rfc6749Error := fosite.ErrorToRFC6749Error(err)
	keysAndValues := make([]interface{}, 0)
	keysAndValues = append(keysAndValues, "name")
	keysAndValues = append(keysAndValues, rfc6749Error.Error()) // Error() returns the ErrorField
	keysAndValues = append(keysAndValues, "status")
	keysAndValues = append(keysAndValues, rfc6749Error.Status()) // Status() encodes the CodeField as a string
	keysAndValues = append(keysAndValues, "description")
	keysAndValues = append(keysAndValues, rfc6749Error.GetDescription()) // GetDescription() returns the DescriptionField and the HintField
	keysAndValues = append(keysAndValues, "debug")
	keysAndValues = append(keysAndValues, rfc6749Error.Debug()) // Debug() returns the DebugField
	if cause := rfc6749Error.Cause(); cause != nil {            // Cause() returns the underlying error, or nil
		keysAndValues = append(keysAndValues, "cause")
		keysAndValues = append(keysAndValues, cause.Error())
	}
	return keysAndValues
}

func GrantScopeIfRequested(authorizeRequester fosite.AuthorizeRequester, scopeName string) {
	if ScopeWasRequested(authorizeRequester, scopeName) {
		authorizeRequester.GrantScope(scopeName)
	}
}

func ScopeWasRequested(authorizeRequester fosite.AuthorizeRequester, scopeName string) bool {
	for _, scope := range authorizeRequester.GetRequestedScopes() {
		if scope == scopeName {
			return true
		}
	}
	return false
}

func ReadStateParamAndValidateCSRFCookie(r *http.Request, cookieDecoder Decoder, stateDecoder Decoder) (string, *UpstreamStateParamData, error) {
	csrfValue, err := readCSRFCookie(r, cookieDecoder)
	if err != nil {
		return "", nil, err
	}

	encodedState, decodedState, err := readStateParam(r, stateDecoder)
	if err != nil {
		return "", nil, err
	}

	err = validateCSRFValue(decodedState, csrfValue)
	if err != nil {
		return "", nil, err
	}

	return encodedState, decodedState, nil
}

func readCSRFCookie(r *http.Request, cookieDecoder Decoder) (csrftoken.CSRFToken, error) {
	receivedCSRFCookie, err := r.Cookie(CSRFCookieName)
	if err != nil {
		// Error means that the cookie was not found
		return "", httperr.Wrap(http.StatusForbidden, "CSRF cookie is missing", err)
	}

	var csrfFromCookie csrftoken.CSRFToken
	err = cookieDecoder.Decode(CSRFCookieEncodingName, receivedCSRFCookie.Value, &csrfFromCookie)
	if err != nil {
		return "", httperr.Wrap(http.StatusForbidden, "error reading CSRF cookie", err)
	}

	return csrfFromCookie, nil
}

func readStateParam(r *http.Request, stateDecoder Decoder) (string, *UpstreamStateParamData, error) {
	encodedState := r.FormValue("state")

	if encodedState == "" {
		return "", nil, httperr.New(http.StatusBadRequest, "state param not found")
	}

	var state UpstreamStateParamData
	if err := stateDecoder.Decode(
		UpstreamStateParamEncodingName,
		r.FormValue("state"),
		&state,
	); err != nil {
		return "", nil, httperr.New(http.StatusBadRequest, "error reading state")
	}

	if state.FormatVersion != UpstreamStateParamFormatVersion {
		return "", nil, httperr.New(http.StatusUnprocessableEntity, "state format version is invalid")
	}

	return encodedState, &state, nil
}

func validateCSRFValue(state *UpstreamStateParamData, csrfCookieValue csrftoken.CSRFToken) error {
	if subtle.ConstantTimeCompare([]byte(state.CSRFToken), []byte(csrfCookieValue)) != 1 {
		return httperr.New(http.StatusForbidden, "CSRF value does not match")
	}
	return nil
}

// WriteAuthorizeError writes an authorization error as it should be returned by the authorization endpoint and other
// similar endpoints that are the end of the downstream authcode flow. Errors responses are written in the usual fosite style.
func WriteAuthorizeError(r *http.Request, w http.ResponseWriter, oauthHelper fosite.OAuth2Provider, authorizeRequester fosite.AuthorizeRequester, err error, isBrowserless bool) {
	if plog.Enabled(plog.LevelTrace) {
		// When trace level logging is enabled, include the stack trace in the log message.
		keysAndValues := FositeErrorForLog(err)
		errWithStack := errorsx.WithStack(err)
		keysAndValues = append(keysAndValues, "errWithStack")
		// klog always prints error values using %s, which does not include stack traces,
		// so convert the error to a string which includes the stack trace here.
		keysAndValues = append(keysAndValues, fmt.Sprintf("%+v", errWithStack))
		plog.Trace("authorize response error", keysAndValues...)
	} else {
		plog.Info("authorize response error", FositeErrorForLog(err)...)
	}
	if isBrowserless {
		w = rewriteStatusSeeOtherToStatusFoundForBrowserless(w)
	}
	// Return an error according to OIDC spec 3.1.2.6 (second paragraph).
	oauthHelper.WriteAuthorizeError(r.Context(), w, authorizeRequester, err)
}

// PerformAuthcodeRedirect successfully completes a downstream login by creating a session and
// writing the authcode redirect response as it should be returned by the authorization endpoint and other
// similar endpoints that are the end of the downstream authcode flow.
func PerformAuthcodeRedirect(
	r *http.Request,
	w http.ResponseWriter,
	oauthHelper fosite.OAuth2Provider,
	authorizeRequester fosite.AuthorizeRequester,
	openIDSession *psession.PinnipedSession,
	isBrowserless bool,
) {
	authorizeResponder, err := oauthHelper.NewAuthorizeResponse(r.Context(), authorizeRequester, openIDSession)
	if err != nil {
		plog.WarningErr("error while generating and saving authcode", err, "fositeErr", FositeErrorForLog(err))
		WriteAuthorizeError(r, w, oauthHelper, authorizeRequester, err, isBrowserless)
		return
	}
	if isBrowserless {
		w = rewriteStatusSeeOtherToStatusFoundForBrowserless(w)
	}
	oauthHelper.WriteAuthorizeResponse(r.Context(), w, authorizeRequester, authorizeResponder)
}

func rewriteStatusSeeOtherToStatusFoundForBrowserless(w http.ResponseWriter) http.ResponseWriter {
	// rewrite http.StatusSeeOther to http.StatusFound for backwards compatibility with old pinniped CLIs.
	// we can drop this in a few releases once we feel enough time has passed for users to update.
	//
	// WriteAuthorizeResponse/WriteAuthorizeError calls used to result in http.StatusFound until
	// https://github.com/ory/fosite/pull/636 changed it to http.StatusSeeOther to address
	// https://tools.ietf.org/id/draft-ietf-oauth-security-topics-18.html#section-4.11
	// Safari has the bad behavior in the case of http.StatusFound and not just http.StatusTemporaryRedirect.
	//
	// in the browserless flows, the OAuth client is the pinniped CLI and it already has access to the user's
	// password.  Thus there is no security issue with using http.StatusFound vs. http.StatusSeeOther.
	return httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(delegate httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(code int) {
				if code == http.StatusSeeOther {
					code = http.StatusFound
				}
				delegate(code)
			}
		},
	})
}
