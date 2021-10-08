// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package callback provides a handler for the OIDC callback endpoint.
package callback

import (
	"crypto/subtle"
	"net/http"
	"net/url"

	"github.com/ory/fosite"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/httputil/securityheader"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/downstreamsession"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidc/provider/formposthtml"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
)

func NewHandler(
	upstreamIDPs oidc.UpstreamOIDCIdentityProvidersLister,
	oauthHelper fosite.OAuth2Provider,
	stateDecoder, cookieDecoder oidc.Decoder,
	redirectURI string,
) http.Handler {
	handler := httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		state, err := validateRequest(r, stateDecoder, cookieDecoder)
		if err != nil {
			return err
		}

		upstreamIDPConfig := findUpstreamIDPConfig(state.UpstreamName, upstreamIDPs)
		if upstreamIDPConfig == nil {
			plog.Warning("upstream provider not found")
			return httperr.New(http.StatusUnprocessableEntity, "upstream provider not found")
		}

		downstreamAuthParams, err := url.ParseQuery(state.AuthParams)
		if err != nil {
			plog.Error("error reading state downstream auth params", err)
			return httperr.New(http.StatusBadRequest, "error reading state downstream auth params")
		}

		// Recreate enough of the original authorize request so we can pass it to NewAuthorizeRequest().
		reconstitutedAuthRequest := &http.Request{Form: downstreamAuthParams}
		authorizeRequester, err := oauthHelper.NewAuthorizeRequest(r.Context(), reconstitutedAuthRequest)
		if err != nil {
			plog.Error("error using state downstream auth params", err)
			return httperr.New(http.StatusBadRequest, "error using state downstream auth params")
		}

		// Automatically grant the openid, offline_access, and pinniped:request-audience scopes, but only if they were requested.
		downstreamsession.GrantScopesIfRequested(authorizeRequester)

		token, err := upstreamIDPConfig.ExchangeAuthcodeAndValidateTokens(
			r.Context(),
			authcode(r),
			state.PKCECode,
			state.Nonce,
			redirectURI,
		)
		if err != nil {
			plog.WarningErr("error exchanging and validating upstream tokens", err, "upstreamName", upstreamIDPConfig.GetName())
			return httperr.New(http.StatusBadGateway, "error exchanging and validating upstream tokens")
		}

		if token.RefreshToken == nil || token.RefreshToken.Token == "" {
			plog.Warning("refresh token not returned by upstream provider during authcode exchange",
				"upstreamName", upstreamIDPConfig.GetName(),
				"scopes", upstreamIDPConfig.GetScopes(),
				"additionalParams", upstreamIDPConfig.GetAdditionalAuthcodeParams())
			return httperr.New(http.StatusUnprocessableEntity, "refresh token not returned by upstream provider during authcode exchange")
		}

		subject, username, groups, err := downstreamsession.GetDownstreamIdentityFromUpstreamIDToken(upstreamIDPConfig, token.IDToken.Claims)
		if err != nil {
			return httperr.Wrap(http.StatusUnprocessableEntity, err.Error(), err)
		}

		openIDSession := downstreamsession.MakeDownstreamSession(subject, username, groups, &psession.CustomSessionData{
			ProviderUID:  upstreamIDPConfig.GetResourceUID(),
			ProviderName: upstreamIDPConfig.GetName(),
			ProviderType: psession.ProviderTypeOIDC,
			OIDC: &psession.OIDCSessionData{
				UpstreamRefreshToken: token.RefreshToken.Token,
			},
		})

		authorizeResponder, err := oauthHelper.NewAuthorizeResponse(r.Context(), authorizeRequester, openIDSession)
		if err != nil {
			plog.WarningErr("error while generating and saving authcode", err, "upstreamName", upstreamIDPConfig.GetName())
			return httperr.Wrap(http.StatusInternalServerError, "error while generating and saving authcode", err)
		}

		oauthHelper.WriteAuthorizeResponse(w, authorizeRequester, authorizeResponder)

		return nil
	})
	return securityheader.WrapWithCustomCSP(handler, formposthtml.ContentSecurityPolicy())
}

func authcode(r *http.Request) string {
	return r.FormValue("code")
}

func validateRequest(r *http.Request, stateDecoder, cookieDecoder oidc.Decoder) (*oidc.UpstreamStateParamData, error) {
	if r.Method != http.MethodGet {
		return nil, httperr.Newf(http.StatusMethodNotAllowed, "%s (try GET)", r.Method)
	}

	csrfValue, err := readCSRFCookie(r, cookieDecoder)
	if err != nil {
		plog.InfoErr("error reading CSRF cookie", err)
		return nil, err
	}

	if authcode(r) == "" {
		plog.Info("code param not found")
		return nil, httperr.New(http.StatusBadRequest, "code param not found")
	}

	if r.FormValue("state") == "" {
		plog.Info("state param not found")
		return nil, httperr.New(http.StatusBadRequest, "state param not found")
	}

	state, err := readState(r, stateDecoder)
	if err != nil {
		plog.InfoErr("error reading state", err)
		return nil, err
	}

	if subtle.ConstantTimeCompare([]byte(state.CSRFToken), []byte(csrfValue)) != 1 {
		plog.InfoErr("CSRF value does not match", err)
		return nil, httperr.Wrap(http.StatusForbidden, "CSRF value does not match", err)
	}

	return state, nil
}

func findUpstreamIDPConfig(upstreamName string, upstreamIDPs oidc.UpstreamOIDCIdentityProvidersLister) provider.UpstreamOIDCIdentityProviderI {
	for _, p := range upstreamIDPs.GetOIDCIdentityProviders() {
		if p.GetName() == upstreamName {
			return p
		}
	}
	return nil
}

func readCSRFCookie(r *http.Request, cookieDecoder oidc.Decoder) (csrftoken.CSRFToken, error) {
	receivedCSRFCookie, err := r.Cookie(oidc.CSRFCookieName)
	if err != nil {
		// Error means that the cookie was not found
		return "", httperr.Wrap(http.StatusForbidden, "CSRF cookie is missing", err)
	}

	var csrfFromCookie csrftoken.CSRFToken
	err = cookieDecoder.Decode(oidc.CSRFCookieEncodingName, receivedCSRFCookie.Value, &csrfFromCookie)
	if err != nil {
		return "", httperr.Wrap(http.StatusForbidden, "error reading CSRF cookie", err)
	}

	return csrfFromCookie, nil
}

func readState(r *http.Request, stateDecoder oidc.Decoder) (*oidc.UpstreamStateParamData, error) {
	var state oidc.UpstreamStateParamData
	if err := stateDecoder.Decode(
		oidc.UpstreamStateParamEncodingName,
		r.FormValue("state"),
		&state,
	); err != nil {
		return nil, httperr.New(http.StatusBadRequest, "error reading state")
	}

	if state.FormatVersion != oidc.UpstreamStateParamFormatVersion {
		return nil, httperr.New(http.StatusUnprocessableEntity, "state format version is invalid")
	}

	return &state, nil
}
