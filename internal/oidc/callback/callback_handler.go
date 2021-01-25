// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package callback provides a handler for the OIDC callback endpoint.
package callback

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/httputil/securityheader"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
)

const (
	// The name of the email claim from https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
	emailClaimName = "email"

	// The name of the email_verified claim from https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
	emailVerifiedClaimName = "email_verified"
)

func NewHandler(
	idpListGetter oidc.IDPListGetter,
	oauthHelper fosite.OAuth2Provider,
	stateDecoder, cookieDecoder oidc.Decoder,
	redirectURI string,
) http.Handler {
	return securityheader.Wrap(httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		state, err := validateRequest(r, stateDecoder, cookieDecoder)
		if err != nil {
			return err
		}

		upstreamIDPConfig := findUpstreamIDPConfig(state.UpstreamName, idpListGetter)
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
		oidc.GrantScopeIfRequested(authorizeRequester, coreosoidc.ScopeOpenID)
		oidc.GrantScopeIfRequested(authorizeRequester, coreosoidc.ScopeOfflineAccess)
		oidc.GrantScopeIfRequested(authorizeRequester, "pinniped:request-audience")

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

		subject, username, err := getSubjectAndUsernameFromUpstreamIDToken(upstreamIDPConfig, token.IDToken.Claims)
		if err != nil {
			return err
		}

		groups, err := getGroupsFromUpstreamIDToken(upstreamIDPConfig, token.IDToken.Claims)
		if err != nil {
			return err
		}

		openIDSession := makeDownstreamSession(subject, username, groups)
		authorizeResponder, err := oauthHelper.NewAuthorizeResponse(r.Context(), authorizeRequester, openIDSession)
		if err != nil {
			plog.WarningErr("error while generating and saving authcode", err, "upstreamName", upstreamIDPConfig.GetName())
			return httperr.Wrap(http.StatusInternalServerError, "error while generating and saving authcode", err)
		}

		oauthHelper.WriteAuthorizeResponse(w, authorizeRequester, authorizeResponder)

		return nil
	}))
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

func findUpstreamIDPConfig(upstreamName string, idpListGetter oidc.IDPListGetter) provider.UpstreamOIDCIdentityProviderI {
	for _, p := range idpListGetter.GetIDPList() {
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

func getSubjectAndUsernameFromUpstreamIDToken(
	upstreamIDPConfig provider.UpstreamOIDCIdentityProviderI,
	idTokenClaims map[string]interface{},
) (string, string, error) {
	// The spec says the "sub" claim is only unique per issuer,
	// so we will prepend the issuer string to make it globally unique.
	upstreamIssuer := idTokenClaims[oidc.IDTokenIssuerClaim]
	if upstreamIssuer == "" {
		plog.Warning(
			"issuer claim in upstream ID token missing",
			"upstreamName", upstreamIDPConfig.GetName(),
			"issClaim", upstreamIssuer,
		)
		return "", "", httperr.New(http.StatusUnprocessableEntity, "issuer claim in upstream ID token missing")
	}
	upstreamIssuerAsString, ok := upstreamIssuer.(string)
	if !ok {
		plog.Warning(
			"issuer claim in upstream ID token has invalid format",
			"upstreamName", upstreamIDPConfig.GetName(),
			"issClaim", upstreamIssuer,
		)
		return "", "", httperr.New(http.StatusUnprocessableEntity, "issuer claim in upstream ID token has invalid format")
	}

	subjectAsInterface, ok := idTokenClaims[oidc.IDTokenSubjectClaim]
	if !ok {
		plog.Warning(
			"no subject claim in upstream ID token",
			"upstreamName", upstreamIDPConfig.GetName(),
		)
		return "", "", httperr.New(http.StatusUnprocessableEntity, "no subject claim in upstream ID token")
	}

	upstreamSubject, ok := subjectAsInterface.(string)
	if !ok {
		plog.Warning(
			"subject claim in upstream ID token has invalid format",
			"upstreamName", upstreamIDPConfig.GetName(),
		)
		return "", "", httperr.New(http.StatusUnprocessableEntity, "subject claim in upstream ID token has invalid format")
	}

	subject := fmt.Sprintf("%s?%s=%s", upstreamIssuerAsString, oidc.IDTokenSubjectClaim, upstreamSubject)

	usernameClaimName := upstreamIDPConfig.GetUsernameClaim()
	if usernameClaimName == "" {
		return subject, subject, nil
	}

	// If the upstream username claim is configured to be the special "email" claim and the upstream "email_verified"
	// claim is present, then validate that the "email_verified" claim is true.
	emailVerifiedAsInterface, ok := idTokenClaims[emailVerifiedClaimName]
	if usernameClaimName == emailClaimName && ok {
		emailVerified, ok := emailVerifiedAsInterface.(bool)
		if !ok {
			plog.Warning(
				"username claim configured as \"email\" and upstream email_verified claim is not a boolean",
				"upstreamName", upstreamIDPConfig.GetName(),
				"configuredUsernameClaim", usernameClaimName,
				"emailVerifiedClaim", emailVerifiedAsInterface,
			)
			return "", "", httperr.New(http.StatusUnprocessableEntity, "email_verified claim in upstream ID token has invalid format")
		}
		if !emailVerified {
			plog.Warning(
				"username claim configured as \"email\" and upstream email_verified claim has false value",
				"upstreamName", upstreamIDPConfig.GetName(),
				"configuredUsernameClaim", usernameClaimName,
			)
			return "", "", httperr.New(http.StatusUnprocessableEntity, "email_verified claim in upstream ID token has false value")
		}
	}

	usernameAsInterface, ok := idTokenClaims[usernameClaimName]
	if !ok {
		plog.Warning(
			"no username claim in upstream ID token",
			"upstreamName", upstreamIDPConfig.GetName(),
			"configuredUsernameClaim", usernameClaimName,
		)
		return "", "", httperr.New(http.StatusUnprocessableEntity, "no username claim in upstream ID token")
	}

	username, ok := usernameAsInterface.(string)
	if !ok {
		plog.Warning(
			"username claim in upstream ID token has invalid format",
			"upstreamName", upstreamIDPConfig.GetName(),
			"configuredUsernameClaim", usernameClaimName,
		)
		return "", "", httperr.New(http.StatusUnprocessableEntity, "username claim in upstream ID token has invalid format")
	}

	return subject, username, nil
}

func getGroupsFromUpstreamIDToken(
	upstreamIDPConfig provider.UpstreamOIDCIdentityProviderI,
	idTokenClaims map[string]interface{},
) ([]string, error) {
	groupsClaimName := upstreamIDPConfig.GetGroupsClaim()
	if groupsClaimName == "" {
		return nil, nil
	}

	groupsAsInterface, ok := idTokenClaims[groupsClaimName]
	if !ok {
		plog.Warning(
			"no groups claim in upstream ID token",
			"upstreamName", upstreamIDPConfig.GetName(),
			"configuredGroupsClaim", groupsClaimName,
		)
		return nil, nil // the upstream IDP may have omitted the claim if the user has no groups
	}

	groupsAsArray, okAsArray := extractGroups(groupsAsInterface)
	if !okAsArray {
		plog.Warning(
			"groups claim in upstream ID token has invalid format",
			"upstreamName", upstreamIDPConfig.GetName(),
			"configuredGroupsClaim", groupsClaimName,
		)
		return nil, httperr.New(http.StatusUnprocessableEntity, "groups claim in upstream ID token has invalid format")
	}

	return groupsAsArray, nil
}

func extractGroups(groupsAsInterface interface{}) ([]string, bool) {
	groupsAsString, okAsString := groupsAsInterface.(string)
	if okAsString {
		return []string{groupsAsString}, true
	}

	groupsAsStringArray, okAsStringArray := groupsAsInterface.([]string)
	if okAsStringArray {
		return groupsAsStringArray, true
	}

	groupsAsInterfaceArray, okAsArray := groupsAsInterface.([]interface{})
	if !okAsArray {
		return nil, false
	}

	var groupsAsStrings []string
	for _, groupAsInterface := range groupsAsInterfaceArray {
		groupAsString, okAsString := groupAsInterface.(string)
		if !okAsString {
			return nil, false
		}
		if groupAsString != "" {
			groupsAsStrings = append(groupsAsStrings, groupAsString)
		}
	}

	return groupsAsStrings, true
}

func makeDownstreamSession(subject string, username string, groups []string) *openid.DefaultSession {
	now := time.Now().UTC()
	openIDSession := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject:     subject,
			RequestedAt: now,
			AuthTime:    now,
		},
	}
	if groups == nil {
		groups = []string{}
	}
	openIDSession.Claims.Extra = map[string]interface{}{
		oidc.DownstreamUsernameClaim: username,
		oidc.DownstreamGroupsClaim:   groups,
	}
	return openIDSession
}
