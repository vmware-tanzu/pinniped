// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package auth provides a handler for the OIDC authorization endpoint.
package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"golang.org/x/oauth2"

	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/httputil/securityheader"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/downstreamsession"
	"go.pinniped.dev/internal/oidc/login"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidc/provider/formposthtml"
	"go.pinniped.dev/internal/oidc/provider/upstreamprovider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

const (
	promptParamName = "prompt"
	promptParamNone = "none"
)

func NewHandler(
	downstreamIssuer string,
	idpFinder provider.FederationDomainIdentityProvidersFinderI,
	oauthHelperWithoutStorage fosite.OAuth2Provider,
	oauthHelperWithStorage fosite.OAuth2Provider,
	generateCSRF func() (csrftoken.CSRFToken, error),
	generatePKCE func() (pkce.Code, error),
	generateNonce func() (nonce.Nonce, error),
	upstreamStateEncoder oidc.Encoder,
	cookieCodec oidc.Codec,
) http.Handler {
	handler := httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
			// Authorization Servers MUST support the use of the HTTP GET and POST methods defined in
			// RFC 2616 [RFC2616] at the Authorization Endpoint.
			return httperr.Newf(http.StatusMethodNotAllowed, "%s (try GET or POST)", r.Method)
		}

		// Note that the client might have used oidcapi.AuthorizeUpstreamIDPNameParamName and
		// oidcapi.AuthorizeUpstreamIDPTypeParamName query params to request a certain upstream IDP.
		// The Pinniped CLI has been sending these params since v0.9.0.
		idpNameQueryParamValue := r.URL.Query().Get(oidcapi.AuthorizeUpstreamIDPNameParamName)
		oidcUpstream, ldapUpstream, err := chooseUpstreamIDP(idpNameQueryParamValue, idpFinder)
		if err != nil {
			plog.WarningErr("authorize upstream config", err)
			return err
		}

		if oidcUpstream != nil {
			if len(r.Header.Values(oidcapi.AuthorizeUsernameHeaderName)) > 0 ||
				len(r.Header.Values(oidcapi.AuthorizePasswordHeaderName)) > 0 {
				// The client set a username header, so they are trying to log in with a username/password.
				return handleAuthRequestForOIDCUpstreamPasswordGrant(
					r,
					w,
					oauthHelperWithStorage,
					oidcUpstream.Provider,
					oidcUpstream.Transforms,
					idpNameQueryParamValue,
				)
			}
			return handleAuthRequestForOIDCUpstreamBrowserFlow(r, w,
				oauthHelperWithoutStorage,
				generateCSRF, generateNonce, generatePKCE,
				oidcUpstream,
				downstreamIssuer,
				upstreamStateEncoder,
				cookieCodec,
				idpNameQueryParamValue,
			)
		}

		// We know it's an AD/LDAP upstream.
		if len(r.Header.Values(oidcapi.AuthorizeUsernameHeaderName)) > 0 ||
			len(r.Header.Values(oidcapi.AuthorizePasswordHeaderName)) > 0 {
			// The client set a username header, so they are trying to log in with a username/password.
			return handleAuthRequestForLDAPUpstreamCLIFlow(r, w,
				oauthHelperWithStorage,
				ldapUpstream.Provider,
				ldapUpstream.SessionProviderType,
				ldapUpstream.Transforms,
				idpNameQueryParamValue,
			)
		}
		return handleAuthRequestForLDAPUpstreamBrowserFlow(
			r,
			w,
			oauthHelperWithoutStorage,
			generateCSRF,
			generateNonce,
			generatePKCE,
			ldapUpstream,
			ldapUpstream.SessionProviderType,
			downstreamIssuer,
			upstreamStateEncoder,
			cookieCodec,
			idpNameQueryParamValue,
		)
	})

	// During a response_mode=form_post auth request using the browser flow, the custom form_post html page may
	// be used to post certain errors back to the CLI from this handler's response, so allow the form_post
	// page's CSS and JS to run.
	return securityheader.WrapWithCustomCSP(handler, formposthtml.ContentSecurityPolicy())
}

func handleAuthRequestForLDAPUpstreamCLIFlow(
	r *http.Request,
	w http.ResponseWriter,
	oauthHelper fosite.OAuth2Provider,
	ldapUpstream upstreamprovider.UpstreamLDAPIdentityProviderI,
	idpType psession.ProviderType,
	identityTransforms *idtransform.TransformationPipeline,
	idpNameQueryParamValue string,
) error {
	authorizeRequester, created := newAuthorizeRequest(r, w, oauthHelper, true)
	if !created {
		return nil
	}

	maybeLogDeprecationWarningForMissingIDPParam(idpNameQueryParamValue, authorizeRequester)

	if !requireStaticClientForUsernameAndPasswordHeaders(r, w, oauthHelper, authorizeRequester) {
		return nil
	}

	submittedUsername, submittedPassword, hadUsernamePasswordValues := requireNonEmptyUsernameAndPasswordHeaders(r, w, oauthHelper, authorizeRequester)
	if !hadUsernamePasswordValues {
		return nil
	}

	authenticateResponse, authenticated, err := ldapUpstream.AuthenticateUser(r.Context(), submittedUsername, submittedPassword, authorizeRequester.GetGrantedScopes())
	if err != nil {
		plog.WarningErr("unexpected error during upstream LDAP authentication", err, "upstreamName", ldapUpstream.GetName())
		return httperr.New(http.StatusBadGateway, "unexpected error during upstream authentication")
	}
	if !authenticated {
		oidc.WriteAuthorizeError(r, w, oauthHelper, authorizeRequester,
			fosite.ErrAccessDenied.WithHintf("Username/password not accepted by LDAP provider."), true)
		return nil
	}

	subject := downstreamsession.DownstreamSubjectFromUpstreamLDAP(ldapUpstream, authenticateResponse)
	upstreamUsername := authenticateResponse.User.GetName()
	upstreamGroups := authenticateResponse.User.GetGroups()

	username, groups, err := downstreamsession.ApplyIdentityTransformations(r.Context(), identityTransforms, upstreamUsername, upstreamGroups)
	if err != nil {
		oidc.WriteAuthorizeError(r, w, oauthHelper, authorizeRequester,
			fosite.ErrAccessDenied.WithHintf("Reason: %s.", err.Error()), true,
		)
		return nil
	}

	customSessionData := downstreamsession.MakeDownstreamLDAPOrADCustomSessionData(ldapUpstream, idpType, authenticateResponse, username, upstreamUsername, upstreamGroups)
	openIDSession := downstreamsession.MakeDownstreamSession(subject, username, groups,
		authorizeRequester.GetGrantedScopes(), authorizeRequester.GetClient().GetID(), customSessionData, map[string]interface{}{})
	oidc.PerformAuthcodeRedirect(r, w, oauthHelper, authorizeRequester, openIDSession, true)

	return nil
}

func handleAuthRequestForLDAPUpstreamBrowserFlow(
	r *http.Request,
	w http.ResponseWriter,
	oauthHelper fosite.OAuth2Provider,
	generateCSRF func() (csrftoken.CSRFToken, error),
	generateNonce func() (nonce.Nonce, error),
	generatePKCE func() (pkce.Code, error),
	ldapUpstream *provider.FederationDomainResolvedLDAPIdentityProvider,
	idpType psession.ProviderType,
	downstreamIssuer string,
	upstreamStateEncoder oidc.Encoder,
	cookieCodec oidc.Codec,
	idpNameQueryParamValue string,
) error {
	authRequestState, err := handleBrowserFlowAuthRequest(
		r,
		w,
		oauthHelper,
		generateCSRF,
		generateNonce,
		generatePKCE,
		ldapUpstream.DisplayName,
		idpType,
		cookieCodec,
		upstreamStateEncoder,
		idpNameQueryParamValue,
	)
	if err != nil {
		return err
	}
	if authRequestState == nil {
		// There was an error but handleBrowserFlowAuthRequest() already took care of writing the response for it.
		return nil
	}

	return login.RedirectToLoginPage(r, w, downstreamIssuer, authRequestState.encodedStateParam, login.ShowNoError)
}

func handleAuthRequestForOIDCUpstreamPasswordGrant(
	r *http.Request,
	w http.ResponseWriter,
	oauthHelper fosite.OAuth2Provider,
	oidcUpstream upstreamprovider.UpstreamOIDCIdentityProviderI,
	identityTransforms *idtransform.TransformationPipeline,
	idpNameQueryParamValue string,
) error {
	authorizeRequester, created := newAuthorizeRequest(r, w, oauthHelper, true)
	if !created {
		return nil
	}

	maybeLogDeprecationWarningForMissingIDPParam(idpNameQueryParamValue, authorizeRequester)

	if !requireStaticClientForUsernameAndPasswordHeaders(r, w, oauthHelper, authorizeRequester) {
		return nil
	}

	submittedUsername, submittedPassword, hadUsernamePasswordValues := requireNonEmptyUsernameAndPasswordHeaders(r, w, oauthHelper, authorizeRequester)
	if !hadUsernamePasswordValues {
		return nil
	}

	if !oidcUpstream.AllowsPasswordGrant() {
		// Return a user-friendly error for this case which is entirely within our control.
		oidc.WriteAuthorizeError(r, w, oauthHelper, authorizeRequester,
			fosite.ErrAccessDenied.WithHint(
				"Resource owner password credentials grant is not allowed for this upstream provider according to its configuration."), true)
		return nil
	}

	token, err := oidcUpstream.PasswordCredentialsGrantAndValidateTokens(r.Context(), submittedUsername, submittedPassword)
	if err != nil {
		// Upstream password grant errors can be generic errors (e.g. a network failure) or can be oauth2.RetrieveError errors
		// which represent the http response from the upstream server. These could be a 5XX or some other unexpected error,
		// or could be a 400 with a JSON body as described by https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
		// which notes that wrong resource owner credentials should result in an "invalid_grant" error.
		// However, the exact response is undefined in the sense that there is no such thing as a password grant in
		// the OIDC spec, so we don't try too hard to read the upstream errors in this case. (E.g. Dex departs from the
		// spec and returns something other than an "invalid_grant" error for bad resource owner credentials.)
		oidc.WriteAuthorizeError(r, w, oauthHelper, authorizeRequester,
			fosite.ErrAccessDenied.WithDebug(err.Error()), true) // WithDebug hides the error from the client
		return nil
	}

	subject, upstreamUsername, upstreamGroups, err := downstreamsession.GetDownstreamIdentityFromUpstreamIDToken(oidcUpstream, token.IDToken.Claims)
	if err != nil {
		// Return a user-friendly error for this case which is entirely within our control.
		oidc.WriteAuthorizeError(r, w, oauthHelper, authorizeRequester,
			fosite.ErrAccessDenied.WithHintf("Reason: %s.", err.Error()), true,
		)
		return nil
	}

	username, groups, err := downstreamsession.ApplyIdentityTransformations(r.Context(), identityTransforms, upstreamUsername, upstreamGroups)
	if err != nil {
		oidc.WriteAuthorizeError(r, w, oauthHelper, authorizeRequester,
			fosite.ErrAccessDenied.WithHintf("Reason: %s.", err.Error()), true,
		)
		return nil
	}

	additionalClaims := downstreamsession.MapAdditionalClaimsFromUpstreamIDToken(oidcUpstream, token.IDToken.Claims)

	customSessionData, err := downstreamsession.MakeDownstreamOIDCCustomSessionData(oidcUpstream, token, username, upstreamUsername, upstreamGroups)
	if err != nil {
		oidc.WriteAuthorizeError(r, w, oauthHelper, authorizeRequester,
			fosite.ErrAccessDenied.WithHintf("Reason: %s.", err.Error()), true,
		)
		return nil
	}

	openIDSession := downstreamsession.MakeDownstreamSession(subject, username, groups,
		authorizeRequester.GetGrantedScopes(), authorizeRequester.GetClient().GetID(), customSessionData, additionalClaims)

	oidc.PerformAuthcodeRedirect(r, w, oauthHelper, authorizeRequester, openIDSession, true)

	return nil
}

func handleAuthRequestForOIDCUpstreamBrowserFlow(
	r *http.Request,
	w http.ResponseWriter,
	oauthHelper fosite.OAuth2Provider,
	generateCSRF func() (csrftoken.CSRFToken, error),
	generateNonce func() (nonce.Nonce, error),
	generatePKCE func() (pkce.Code, error),
	oidcUpstream *provider.FederationDomainResolvedOIDCIdentityProvider,
	downstreamIssuer string,
	upstreamStateEncoder oidc.Encoder,
	cookieCodec oidc.Codec,
	idpNameQueryParamValue string,
) error {
	authRequestState, err := handleBrowserFlowAuthRequest(
		r,
		w,
		oauthHelper,
		generateCSRF,
		generateNonce,
		generatePKCE,
		oidcUpstream.DisplayName,
		psession.ProviderTypeOIDC,
		cookieCodec,
		upstreamStateEncoder,
		idpNameQueryParamValue,
	)
	if err != nil {
		return err
	}
	if authRequestState == nil {
		// There was an error but handleBrowserFlowAuthRequest() already took care of writing the response for it.
		return nil
	}

	upstreamOAuthConfig := oauth2.Config{
		ClientID: oidcUpstream.Provider.GetClientID(),
		Endpoint: oauth2.Endpoint{
			AuthURL: oidcUpstream.Provider.GetAuthorizationURL().String(),
		},
		RedirectURL: fmt.Sprintf("%s/callback", downstreamIssuer),
		Scopes:      oidcUpstream.Provider.GetScopes(),
	}

	authCodeOptions := []oauth2.AuthCodeOption{
		authRequestState.nonce.Param(),
		authRequestState.pkce.Challenge(),
		authRequestState.pkce.Method(),
	}

	for key, val := range oidcUpstream.Provider.GetAdditionalAuthcodeParams() {
		authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam(key, val))
	}

	http.Redirect(w, r,
		upstreamOAuthConfig.AuthCodeURL(
			authRequestState.encodedStateParam,
			authCodeOptions...,
		),
		http.StatusSeeOther, // match fosite and https://tools.ietf.org/id/draft-ietf-oauth-security-topics-18.html#section-4.11
	)

	return nil
}

func requireStaticClientForUsernameAndPasswordHeaders(r *http.Request, w http.ResponseWriter, oauthHelper fosite.OAuth2Provider, authorizeRequester fosite.AuthorizeRequester) bool {
	isStaticClient := authorizeRequester.GetClient().GetID() == oidcapi.ClientIDPinnipedCLI
	if !isStaticClient {
		oidc.WriteAuthorizeError(r, w, oauthHelper, authorizeRequester,
			fosite.ErrAccessDenied.WithHintf("This client is not allowed to submit username or password headers to this endpoint."), true)
	}
	return isStaticClient
}

func requireNonEmptyUsernameAndPasswordHeaders(r *http.Request, w http.ResponseWriter, oauthHelper fosite.OAuth2Provider, authorizeRequester fosite.AuthorizeRequester) (string, string, bool) {
	username := r.Header.Get(oidcapi.AuthorizeUsernameHeaderName)
	password := r.Header.Get(oidcapi.AuthorizePasswordHeaderName)
	if username == "" || password == "" {
		oidc.WriteAuthorizeError(r, w, oauthHelper, authorizeRequester,
			fosite.ErrAccessDenied.WithHintf("Missing or blank username or password."), true)
		return "", "", false
	}
	return username, password, true
}

func newAuthorizeRequest(r *http.Request, w http.ResponseWriter, oauthHelper fosite.OAuth2Provider, isBrowserless bool) (fosite.AuthorizeRequester, bool) {
	authorizeRequester, err := oauthHelper.NewAuthorizeRequest(r.Context(), r)
	if err != nil {
		oidc.WriteAuthorizeError(r, w, oauthHelper, authorizeRequester, err, isBrowserless)
		return nil, false
	}

	// Automatically grant certain scopes, but only if they were requested.
	// Grant the openid scope (for now) if they asked for it so that `NewAuthorizeResponse` will perform its OIDC validations.
	// There don't seem to be any validations inside `NewAuthorizeResponse` related to the offline_access scope
	// at this time, however we will temporarily grant the scope just in case that changes in a future release of fosite.
	// This is instead of asking the user to approve these scopes. Note that `NewAuthorizeRequest` would have returned
	// an error if the client requested a scope that they are not allowed to request, so we don't need to worry about that here.
	downstreamsession.AutoApproveScopes(authorizeRequester)

	return authorizeRequester, true
}

func readCSRFCookie(r *http.Request, codec oidc.Decoder) csrftoken.CSRFToken {
	receivedCSRFCookie, err := r.Cookie(oidc.CSRFCookieName)
	if err != nil {
		// Error means that the cookie was not found
		return ""
	}

	var csrfFromCookie csrftoken.CSRFToken
	err = codec.Decode(oidc.CSRFCookieEncodingName, receivedCSRFCookie.Value, &csrfFromCookie)
	if err != nil {
		// We can ignore any errors and just make a new cookie. Hopefully this will
		// make the user experience better if, for example, the server rotated
		// cookie signing keys and then a user submitted a very old cookie.
		return ""
	}

	return csrfFromCookie
}

// chooseUpstreamIDP selects either an OIDC, an LDAP, or an AD IDP, or returns an error.
// Note that AD and LDAP IDPs both return the same interface type, but different ProviderTypes values.
func chooseUpstreamIDP(idpDisplayName string, idpLister provider.FederationDomainIdentityProvidersFinderI) (*provider.FederationDomainResolvedOIDCIdentityProvider, *provider.FederationDomainResolvedLDAPIdentityProvider, error) {
	// When a request is made to the authorization endpoint which does not specify the IDP name, then it might
	// be an old dynamic client (OIDCClient). We need to make this work, but only in the backwards compatibility case
	// where there is exactly one IDP defined in the namespace and no IDPs listed on the FederationDomain.
	// This backwards compatibility mode is handled by FindDefaultIDP().
	if len(idpDisplayName) == 0 {
		return idpLister.FindDefaultIDP()
	}
	return idpLister.FindUpstreamIDPByDisplayName(idpDisplayName)
}

func maybeLogDeprecationWarningForMissingIDPParam(idpNameQueryParamValue string, authorizeRequester fosite.AuthorizeRequester) {
	if len(idpNameQueryParamValue) != 0 {
		return
	}
	plog.Warning("Client attempted to perform an authorization flow (user login) without specifying the "+
		"query param to choose an identity provider. "+
		"This will not work when identity providers are configured explicitly on a FederationDomain. "+
		"Additionally, this behavior is deprecated and support for any authorization requests missing this query param "+
		"may be removed in a future release. "+
		"Please ask the author of this client to update the authorization request URL to include this query parameter. "+
		"The value of the parameter should be equal to the displayName of the identity provider as declared in the FederationDomain.",
		"missingParameterName", oidcapi.AuthorizeUpstreamIDPNameParamName,
		"clientID", authorizeRequester.GetClient().GetID(),
	)
}

type browserFlowAuthRequestState struct {
	encodedStateParam string
	pkce              pkce.Code
	nonce             nonce.Nonce
}

// handleBrowserFlowAuthRequest performs the shared validations and setup between browser based
// auth requests regardless of IDP type-- LDAP, Active Directory and OIDC.
// It generates the state param, sets the CSRF cookie, and validates the prompt param.
// It returns an error when it encounters an error without handling it, leaving it to
// the caller to decide how to handle it.
// It returns nil with no error when it encounters an error and also has already handled writing
// the error response to the ResponseWriter, in which case the caller should not also try to
// write the error response.
func handleBrowserFlowAuthRequest(
	r *http.Request,
	w http.ResponseWriter,
	oauthHelper fosite.OAuth2Provider,
	generateCSRF func() (csrftoken.CSRFToken, error),
	generateNonce func() (nonce.Nonce, error),
	generatePKCE func() (pkce.Code, error),
	upstreamDisplayName string,
	idpType psession.ProviderType,
	cookieCodec oidc.Codec,
	upstreamStateEncoder oidc.Encoder,
	idpNameQueryParamValue string,
) (*browserFlowAuthRequestState, error) {
	authorizeRequester, created := newAuthorizeRequest(r, w, oauthHelper, false)
	if !created {
		return nil, nil // already wrote the error response, don't return error
	}

	maybeLogDeprecationWarningForMissingIDPParam(idpNameQueryParamValue, authorizeRequester)

	now := time.Now()
	_, err := oauthHelper.NewAuthorizeResponse(r.Context(), authorizeRequester, &psession.PinnipedSession{
		Fosite: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				// Temporary claim values to allow `NewAuthorizeResponse` to perform other OIDC validations.
				Subject:     "none",
				AuthTime:    now,
				RequestedAt: now,
			},
		},
	})
	if err != nil {
		oidc.WriteAuthorizeError(r, w, oauthHelper, authorizeRequester, err, false)
		return nil, nil // already wrote the error response, don't return error
	}

	csrfValue, nonceValue, pkceValue, err := generateValues(generateCSRF, generateNonce, generatePKCE)
	if err != nil {
		plog.Error("authorize generate error", err)
		return nil, err
	}
	csrfFromCookie := readCSRFCookie(r, cookieCodec)
	if csrfFromCookie != "" {
		csrfValue = csrfFromCookie
	}

	encodedStateParamValue, err := upstreamStateParam(
		authorizeRequester,
		upstreamDisplayName,
		string(idpType),
		nonceValue,
		csrfValue,
		pkceValue,
		upstreamStateEncoder,
	)
	if err != nil {
		plog.Error("authorize upstream state param error", err)
		return nil, err
	}

	promptParam := r.Form.Get(promptParamName)
	if promptParam == promptParamNone && oidc.ScopeWasRequested(authorizeRequester, oidcapi.ScopeOpenID) {
		oidc.WriteAuthorizeError(r, w, oauthHelper, authorizeRequester, fosite.ErrLoginRequired, false)
		return nil, nil // already wrote the error response, don't return error
	}

	if csrfFromCookie == "" {
		// We did not receive an incoming CSRF cookie, so write a new one.
		err = addCSRFSetCookieHeader(w, csrfValue, cookieCodec)
		if err != nil {
			plog.Error("error setting CSRF cookie", err)
			return nil, err
		}
	}

	return &browserFlowAuthRequestState{
		encodedStateParam: encodedStateParamValue,
		pkce:              pkceValue,
		nonce:             nonceValue,
	}, nil
}

func generateValues(
	generateCSRF func() (csrftoken.CSRFToken, error),
	generateNonce func() (nonce.Nonce, error),
	generatePKCE func() (pkce.Code, error),
) (csrftoken.CSRFToken, nonce.Nonce, pkce.Code, error) {
	csrfValue, err := generateCSRF()
	if err != nil {
		return "", "", "", httperr.Wrap(http.StatusInternalServerError, "error generating CSRF token", err)
	}
	nonceValue, err := generateNonce()
	if err != nil {
		return "", "", "", httperr.Wrap(http.StatusInternalServerError, "error generating nonce param", err)
	}
	pkceValue, err := generatePKCE()
	if err != nil {
		return "", "", "", httperr.Wrap(http.StatusInternalServerError, "error generating PKCE param", err)
	}
	return csrfValue, nonceValue, pkceValue, nil
}

func upstreamStateParam(
	authorizeRequester fosite.AuthorizeRequester,
	upstreamDisplayName string,
	upstreamType string,
	nonceValue nonce.Nonce,
	csrfValue csrftoken.CSRFToken,
	pkceValue pkce.Code,
	encoder oidc.Encoder,
) (string, error) {
	stateParamData := oidc.UpstreamStateParamData{
		// The auth params might have included oidcapi.AuthorizeUpstreamIDPNameParamName and
		// oidcapi.AuthorizeUpstreamIDPTypeParamName, but those can be ignored by other handlers
		// that are reading from the encoded upstream state param being built here.
		// The UpstreamName and UpstreamType struct fields can be used instead.
		// Remove those params here to avoid potential confusion about which should be used later.
		AuthParams:    removeCustomIDPParams(authorizeRequester.GetRequestForm()).Encode(),
		UpstreamName:  upstreamDisplayName,
		UpstreamType:  upstreamType,
		Nonce:         nonceValue,
		CSRFToken:     csrfValue,
		PKCECode:      pkceValue,
		FormatVersion: oidc.UpstreamStateParamFormatVersion,
	}
	encodedStateParamValue, err := encoder.Encode(oidc.UpstreamStateParamEncodingName, stateParamData)
	if err != nil {
		return "", httperr.Wrap(http.StatusInternalServerError, "error encoding upstream state param", err)
	}
	return encodedStateParamValue, nil
}

func removeCustomIDPParams(params url.Values) url.Values {
	p := url.Values{}
	// Copy all params.
	for k, v := range params {
		p[k] = v
	}
	// Remove the unnecessary params.
	delete(p, oidcapi.AuthorizeUpstreamIDPNameParamName)
	delete(p, oidcapi.AuthorizeUpstreamIDPTypeParamName)
	return p
}

func addCSRFSetCookieHeader(w http.ResponseWriter, csrfValue csrftoken.CSRFToken, codec oidc.Encoder) error {
	encodedCSRFValue, err := codec.Encode(oidc.CSRFCookieEncodingName, csrfValue)
	if err != nil {
		return httperr.Wrap(http.StatusInternalServerError, "error encoding CSRF cookie", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     oidc.CSRFCookieName,
		Value:    encodedCSRFValue,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		Path:     "/",
	})

	return nil
}
