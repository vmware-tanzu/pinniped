// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package oidc contains common OIDC functionality needed by FederationDomains to implement
// downstream OIDC functionality.
package oidc

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	errorsx "github.com/pkg/errors"

	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/federationdomain/csrftoken"
	"go.pinniped.dev/internal/federationdomain/endpoints/jwks"
	"go.pinniped.dev/internal/federationdomain/endpoints/tokenexchange"
	"go.pinniped.dev/internal/federationdomain/formposthtml"
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

// Get the defaults for the Supervisor server.
func DefaultOIDCTimeoutsConfiguration() timeouts.Configuration {
	accessTokenLifespan := 2 * time.Minute
	authorizationCodeLifespan := 10 * time.Minute
	refreshTokenLifespan := 9 * time.Hour

	return timeouts.Configuration{
		UpstreamStateParamLifespan:              90 * time.Minute,
		AuthorizeCodeLifespan:                   authorizationCodeLifespan,
		AccessTokenLifespan:                     accessTokenLifespan,
		IDTokenLifespan:                         accessTokenLifespan,
		RefreshTokenLifespan:                    refreshTokenLifespan,
		AuthorizationCodeSessionStorageLifetime: authorizationCodeLifespan + refreshTokenLifespan,
		PKCESessionStorageLifetime:              authorizationCodeLifespan + (1 * time.Minute),
		OIDCSessionStorageLifetime:              authorizationCodeLifespan + (1 * time.Minute),
		AccessTokenSessionStorageLifetime:       refreshTokenLifespan + accessTokenLifespan,
		RefreshTokenSessionStorageLifetime:      refreshTokenLifespan + accessTokenLifespan,
	}
}

func FositeOauth2Helper(
	oauthStore interface{},
	issuer string,
	hmacSecretOfLengthAtLeast32Func func() []byte,
	jwksProvider jwks.DynamicJWKSProvider,
	timeoutsConfiguration timeouts.Configuration,
) fosite.OAuth2Provider {
	isRedirectURISecureStrict := func(_ context.Context, uri *url.URL) bool {
		return fosite.IsRedirectURISecureStrict(uri)
	}

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
		RedirectSecureChecker: isRedirectURISecureStrict,

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
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectRefreshFactory,
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
