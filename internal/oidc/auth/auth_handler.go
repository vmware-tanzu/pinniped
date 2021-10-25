// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package auth provides a handler for the OIDC authorization endpoint.
package auth

import (
	"fmt"
	"net/http"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/authenticator"

	supervisoroidc "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/httputil/securityheader"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/downstreamsession"
	"go.pinniped.dev/internal/oidc/provider"
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
	idpLister oidc.UpstreamIdentityProvidersLister,
	oauthHelperWithoutStorage fosite.OAuth2Provider,
	oauthHelperWithStorage fosite.OAuth2Provider,
	generateCSRF func() (csrftoken.CSRFToken, error),
	generatePKCE func() (pkce.Code, error),
	generateNonce func() (nonce.Nonce, error),
	upstreamStateEncoder oidc.Encoder,
	cookieCodec oidc.Codec,
) http.Handler {
	return securityheader.Wrap(httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
			// Authorization Servers MUST support the use of the HTTP GET and POST methods defined in
			// RFC 2616 [RFC2616] at the Authorization Endpoint.
			return httperr.Newf(http.StatusMethodNotAllowed, "%s (try GET or POST)", r.Method)
		}

		oidcUpstream, ldapUpstream, idpType, err := chooseUpstreamIDP(idpLister)
		if err != nil {
			plog.WarningErr("authorize upstream config", err)
			return err
		}

		if idpType == psession.ProviderTypeOIDC {
			if len(r.Header.Values(supervisoroidc.AuthorizeUsernameHeaderName)) > 0 {
				// The client set a username header, so they are trying to log in with a username/password.
				return handleAuthRequestForOIDCUpstreamPasswordGrant(r, w, oauthHelperWithStorage, oidcUpstream)
			}
			return handleAuthRequestForOIDCUpstreamAuthcodeGrant(r, w,
				oauthHelperWithoutStorage,
				generateCSRF, generateNonce, generatePKCE,
				oidcUpstream,
				downstreamIssuer,
				upstreamStateEncoder,
				cookieCodec,
			)
		}
		return handleAuthRequestForLDAPUpstream(r, w,
			oauthHelperWithStorage,
			ldapUpstream,
			idpType,
		)
	}))
}

func handleAuthRequestForLDAPUpstream(
	r *http.Request,
	w http.ResponseWriter,
	oauthHelper fosite.OAuth2Provider,
	ldapUpstream provider.UpstreamLDAPIdentityProviderI,
	idpType psession.ProviderType,
) error {
	authorizeRequester, created := newAuthorizeRequest(r, w, oauthHelper)
	if !created {
		return nil
	}

	username, password, hadUsernamePasswordValues := requireNonEmptyUsernameAndPasswordHeaders(r, w, oauthHelper, authorizeRequester)
	if !hadUsernamePasswordValues {
		return nil
	}

	authenticateResponse, authenticated, err := ldapUpstream.AuthenticateUser(r.Context(), username, password)
	if err != nil {
		plog.WarningErr("unexpected error during upstream LDAP authentication", err, "upstreamName", ldapUpstream.GetName())
		return httperr.New(http.StatusBadGateway, "unexpected error during upstream authentication")
	}
	if !authenticated {
		return writeAuthorizeError(w, oauthHelper, authorizeRequester,
			fosite.ErrAccessDenied.WithHintf("Username/password not accepted by LDAP provider."))
	}

	subject := downstreamSubjectFromUpstreamLDAP(ldapUpstream, authenticateResponse)
	username = authenticateResponse.User.GetName()
	groups := authenticateResponse.User.GetGroups()
	dn := userDNFromAuthenticatedResponse(authenticateResponse)
	if dn == "" {
		return httperr.New(http.StatusInternalServerError, "unexpected error during upstream authentication")
	}

	customSessionData := &psession.CustomSessionData{
		ProviderUID:  ldapUpstream.GetResourceUID(),
		ProviderName: ldapUpstream.GetName(),
		ProviderType: idpType,
	}

	if idpType == psession.ProviderTypeLDAP {
		customSessionData.LDAP = &psession.LDAPSessionData{
			UserDN: dn,
		}
	}
	if idpType == psession.ProviderTypeActiveDirectory {
		customSessionData.ActiveDirectory = &psession.ActiveDirectorySessionData{
			UserDN: dn,
		}
	}

	return makeDownstreamSessionAndReturnAuthcodeRedirect(r, w,
		oauthHelper, authorizeRequester, subject, username, groups, customSessionData)
}

func handleAuthRequestForOIDCUpstreamPasswordGrant(
	r *http.Request,
	w http.ResponseWriter,
	oauthHelper fosite.OAuth2Provider,
	oidcUpstream provider.UpstreamOIDCIdentityProviderI,
) error {
	authorizeRequester, created := newAuthorizeRequest(r, w, oauthHelper)
	if !created {
		return nil
	}

	username, password, hadUsernamePasswordValues := requireNonEmptyUsernameAndPasswordHeaders(r, w, oauthHelper, authorizeRequester)
	if !hadUsernamePasswordValues {
		return nil
	}

	if !oidcUpstream.AllowsPasswordGrant() {
		// Return a user-friendly error for this case which is entirely within our control.
		return writeAuthorizeError(w, oauthHelper, authorizeRequester,
			fosite.ErrAccessDenied.WithHint(
				"Resource owner password credentials grant is not allowed for this upstream provider according to its configuration."))
	}

	token, err := oidcUpstream.PasswordCredentialsGrantAndValidateTokens(r.Context(), username, password)
	if err != nil {
		// Upstream password grant errors can be generic errors (e.g. a network failure) or can be oauth2.RetrieveError errors
		// which represent the http response from the upstream server. These could be a 5XX or some other unexpected error,
		// or could be a 400 with a JSON body as described by https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
		// which notes that wrong resource owner credentials should result in an "invalid_grant" error.
		// However, the exact response is undefined in the sense that there is no such thing as a password grant in
		// the OIDC spec, so we don't try too hard to read the upstream errors in this case. (E.g. Dex departs from the
		// spec and returns something other than an "invalid_grant" error for bad resource owner credentials.)
		return writeAuthorizeError(w, oauthHelper, authorizeRequester,
			fosite.ErrAccessDenied.WithDebug(err.Error())) // WithDebug hides the error from the client
	}

	if token.RefreshToken == nil || token.RefreshToken.Token == "" {
		plog.Warning("refresh token not returned by upstream provider during password grant, "+
			"please check configuration of OIDCIdentityProvider and the client in the upstream provider's API/UI",
			"upstreamName", oidcUpstream.GetName(),
			"scopes", oidcUpstream.GetScopes())
		return writeAuthorizeError(w, oauthHelper, authorizeRequester,
			fosite.ErrAccessDenied.WithHint(
				"Refresh token not returned by upstream provider during password grant."))
	}

	subject, username, groups, err := downstreamsession.GetDownstreamIdentityFromUpstreamIDToken(oidcUpstream, token.IDToken.Claims)
	if err != nil {
		// Return a user-friendly error for this case which is entirely within our control.
		return writeAuthorizeError(w, oauthHelper, authorizeRequester,
			fosite.ErrAccessDenied.WithHintf("Reason: %s.", err.Error()),
		)
	}

	customSessionData := &psession.CustomSessionData{
		ProviderUID:  oidcUpstream.GetResourceUID(),
		ProviderName: oidcUpstream.GetName(),
		ProviderType: psession.ProviderTypeOIDC,
		OIDC: &psession.OIDCSessionData{
			UpstreamRefreshToken: token.RefreshToken.Token,
		},
	}
	return makeDownstreamSessionAndReturnAuthcodeRedirect(r, w, oauthHelper, authorizeRequester, subject, username, groups, customSessionData)
}

func handleAuthRequestForOIDCUpstreamAuthcodeGrant(
	r *http.Request,
	w http.ResponseWriter,
	oauthHelper fosite.OAuth2Provider,
	generateCSRF func() (csrftoken.CSRFToken, error),
	generateNonce func() (nonce.Nonce, error),
	generatePKCE func() (pkce.Code, error),
	oidcUpstream provider.UpstreamOIDCIdentityProviderI,
	downstreamIssuer string,
	upstreamStateEncoder oidc.Encoder,
	cookieCodec oidc.Codec,
) error {
	authorizeRequester, created := newAuthorizeRequest(r, w, oauthHelper)
	if !created {
		return nil
	}

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
		return writeAuthorizeError(w, oauthHelper, authorizeRequester, err)
	}

	csrfValue, nonceValue, pkceValue, err := generateValues(generateCSRF, generateNonce, generatePKCE)
	if err != nil {
		plog.Error("authorize generate error", err)
		return err
	}
	csrfFromCookie := readCSRFCookie(r, cookieCodec)
	if csrfFromCookie != "" {
		csrfValue = csrfFromCookie
	}

	upstreamOAuthConfig := oauth2.Config{
		ClientID: oidcUpstream.GetClientID(),
		Endpoint: oauth2.Endpoint{
			AuthURL: oidcUpstream.GetAuthorizationURL().String(),
		},
		RedirectURL: fmt.Sprintf("%s/callback", downstreamIssuer),
		Scopes:      oidcUpstream.GetScopes(),
	}

	encodedStateParamValue, err := upstreamStateParam(
		authorizeRequester,
		oidcUpstream.GetName(),
		nonceValue,
		csrfValue,
		pkceValue,
		upstreamStateEncoder,
	)
	if err != nil {
		plog.Error("authorize upstream state param error", err)
		return err
	}

	authCodeOptions := []oauth2.AuthCodeOption{
		nonceValue.Param(),
		pkceValue.Challenge(),
		pkceValue.Method(),
	}

	promptParam := r.Form.Get(promptParamName)
	if promptParam == promptParamNone && oidc.ScopeWasRequested(authorizeRequester, coreosoidc.ScopeOpenID) {
		return writeAuthorizeError(w, oauthHelper, authorizeRequester, fosite.ErrLoginRequired)
	}

	for key, val := range oidcUpstream.GetAdditionalAuthcodeParams() {
		authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam(key, val))
	}

	if csrfFromCookie == "" {
		// We did not receive an incoming CSRF cookie, so write a new one.
		err := addCSRFSetCookieHeader(w, csrfValue, cookieCodec)
		if err != nil {
			plog.Error("error setting CSRF cookie", err)
			return err
		}
	}

	http.Redirect(w, r,
		upstreamOAuthConfig.AuthCodeURL(
			encodedStateParamValue,
			authCodeOptions...,
		),
		302,
	)

	return nil
}

func writeAuthorizeError(w http.ResponseWriter, oauthHelper fosite.OAuth2Provider, authorizeRequester fosite.AuthorizeRequester, err error) error {
	if plog.Enabled(plog.LevelTrace) {
		// When trace level logging is enabled, include the stack trace in the log message.
		keysAndValues := oidc.FositeErrorForLog(err)
		errWithStack := errors.WithStack(err)
		keysAndValues = append(keysAndValues, "errWithStack")
		// klog always prints error values using %s, which does not include stack traces,
		// so convert the error to a string which includes the stack trace here.
		keysAndValues = append(keysAndValues, fmt.Sprintf("%+v", errWithStack))
		plog.Trace("authorize response error", keysAndValues...)
	} else {
		plog.Info("authorize response error", oidc.FositeErrorForLog(err)...)
	}
	// Return an error according to OIDC spec 3.1.2.6 (second paragraph).
	oauthHelper.WriteAuthorizeError(w, authorizeRequester, err)
	return nil
}

func makeDownstreamSessionAndReturnAuthcodeRedirect(
	r *http.Request,
	w http.ResponseWriter,
	oauthHelper fosite.OAuth2Provider,
	authorizeRequester fosite.AuthorizeRequester,
	subject string,
	username string,
	groups []string,
	customSessionData *psession.CustomSessionData,
) error {
	openIDSession := downstreamsession.MakeDownstreamSession(subject, username, groups, customSessionData)

	authorizeResponder, err := oauthHelper.NewAuthorizeResponse(r.Context(), authorizeRequester, openIDSession)
	if err != nil {
		return writeAuthorizeError(w, oauthHelper, authorizeRequester, err)
	}

	oauthHelper.WriteAuthorizeResponse(w, authorizeRequester, authorizeResponder)

	return nil
}

func requireNonEmptyUsernameAndPasswordHeaders(r *http.Request, w http.ResponseWriter, oauthHelper fosite.OAuth2Provider, authorizeRequester fosite.AuthorizeRequester) (string, string, bool) {
	username := r.Header.Get(supervisoroidc.AuthorizeUsernameHeaderName)
	password := r.Header.Get(supervisoroidc.AuthorizePasswordHeaderName)
	if username == "" || password == "" {
		_ = writeAuthorizeError(w, oauthHelper, authorizeRequester,
			fosite.ErrAccessDenied.WithHintf("Missing or blank username or password."))
		return "", "", false
	}
	return username, password, true
}

func newAuthorizeRequest(r *http.Request, w http.ResponseWriter, oauthHelper fosite.OAuth2Provider) (fosite.AuthorizeRequester, bool) {
	authorizeRequester, err := oauthHelper.NewAuthorizeRequest(r.Context(), r)
	if err != nil {
		_ = writeAuthorizeError(w, oauthHelper, authorizeRequester, err)
		return nil, false
	}

	// Automatically grant the openid, offline_access, and pinniped:request-audience scopes, but only if they were requested.
	// Grant the openid scope (for now) if they asked for it so that `NewAuthorizeResponse` will perform its OIDC validations.
	// There don't seem to be any validations inside `NewAuthorizeResponse` related to the offline_access scope
	// at this time, however we will temporarily grant the scope just in case that changes in a future release of fosite.
	downstreamsession.GrantScopesIfRequested(authorizeRequester)

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

// Select either an OIDC, an LDAP or an AD IDP, or return an error.
func chooseUpstreamIDP(idpLister oidc.UpstreamIdentityProvidersLister) (provider.UpstreamOIDCIdentityProviderI, provider.UpstreamLDAPIdentityProviderI, psession.ProviderType, error) {
	oidcUpstreams := idpLister.GetOIDCIdentityProviders()
	ldapUpstreams := idpLister.GetLDAPIdentityProviders()
	adUpstreams := idpLister.GetActiveDirectoryIdentityProviders()
	switch {
	case len(oidcUpstreams)+len(ldapUpstreams)+len(adUpstreams) == 0:
		return nil, nil, "", httperr.New(
			http.StatusUnprocessableEntity,
			"No upstream providers are configured",
		)
	case len(oidcUpstreams)+len(ldapUpstreams)+len(adUpstreams) > 1:
		var upstreamIDPNames []string
		for _, idp := range oidcUpstreams {
			upstreamIDPNames = append(upstreamIDPNames, idp.GetName())
		}
		for _, idp := range ldapUpstreams {
			upstreamIDPNames = append(upstreamIDPNames, idp.GetName())
		}
		for _, idp := range adUpstreams {
			upstreamIDPNames = append(upstreamIDPNames, idp.GetName())
		}
		plog.Warning("Too many upstream providers are configured (found: %s)", upstreamIDPNames)
		return nil, nil, "", httperr.New(
			http.StatusUnprocessableEntity,
			"Too many upstream providers are configured (support for multiple upstreams is not yet implemented)",
		)
	case len(oidcUpstreams) == 1:
		return oidcUpstreams[0], nil, psession.ProviderTypeOIDC, nil
	case len(adUpstreams) == 1:
		return nil, adUpstreams[0], psession.ProviderTypeActiveDirectory, nil
	default:
		return nil, ldapUpstreams[0], psession.ProviderTypeLDAP, nil
	}
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
	upstreamName string,
	nonceValue nonce.Nonce,
	csrfValue csrftoken.CSRFToken,
	pkceValue pkce.Code,
	encoder oidc.Encoder,
) (string, error) {
	stateParamData := oidc.UpstreamStateParamData{
		AuthParams:    authorizeRequester.GetRequestForm().Encode(),
		UpstreamName:  upstreamName,
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

func downstreamSubjectFromUpstreamLDAP(ldapUpstream provider.UpstreamLDAPIdentityProviderI, authenticateResponse *authenticator.Response) string {
	ldapURL := *ldapUpstream.GetURL()
	return downstreamsession.DownstreamLDAPSubject(authenticateResponse.User.GetUID(), ldapURL)
}

func userDNFromAuthenticatedResponse(authenticatedResponse *authenticator.Response) string {
	// These errors shouldn't happen, but do some error checking anyway so it doesn't panic
	extra := authenticatedResponse.User.GetExtra()
	if len(extra) == 0 {
		return ""
	}
	dnSlice := extra["userDN"]
	if len(dnSlice) != 1 {
		return ""
	}
	return dnSlice[0]
}
