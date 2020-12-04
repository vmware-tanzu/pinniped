// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package callback provides a handler for the OIDC callback endpoint.
package callback

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
)

const (
	// The name of the issuer claim specified in the OIDC spec.
	idTokenIssuerClaim = "iss"

	// The name of the subject claim specified in the OIDC spec.
	idTokenSubjectClaim = "sub"

	// defaultUpstreamUsernameClaim is what we will use to extract the username from an upstream OIDC
	// ID token if the upstream OIDC IDP did not tell us to use another claim.
	defaultUpstreamUsernameClaim = idTokenSubjectClaim

	// downstreamGroupsClaim is what we will use to encode the groups in the downstream OIDC ID token
	// information.
	downstreamGroupsClaim = "groups"
)

func NewHandler(
	idpListGetter oidc.IDPListGetter,
	oauthHelper fosite.OAuth2Provider,
	stateDecoder, cookieDecoder oidc.Decoder,
	redirectURI string,
) http.Handler {
	return httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
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

		// Grant the openid scope only if it was requested.
		grantOpenIDScopeIfRequested(authorizeRequester)

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

		username, err := getUsernameFromUpstreamIDToken(upstreamIDPConfig, token.IDToken.Claims)
		if err != nil {
			return err
		}

		groups, err := getGroupsFromUpstreamIDToken(upstreamIDPConfig, token.IDToken.Claims)
		if err != nil {
			return err
		}

		openIDSession := makeDownstreamSession(username, groups)
		authorizeResponder, err := oauthHelper.NewAuthorizeResponse(r.Context(), authorizeRequester, openIDSession)
		if err != nil {
			plog.WarningErr("error while generating and saving authcode", err, "upstreamName", upstreamIDPConfig.GetName())
			return httperr.Wrap(http.StatusInternalServerError, "error while generating and saving authcode", err)
		}

		oauthHelper.WriteAuthorizeResponse(w, authorizeRequester, authorizeResponder)

		return nil
	})
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

func grantOpenIDScopeIfRequested(authorizeRequester fosite.AuthorizeRequester) {
	for _, scope := range authorizeRequester.GetRequestedScopes() {
		if scope == "openid" {
			authorizeRequester.GrantScope(scope)
		}
	}
}

func getUsernameFromUpstreamIDToken(
	upstreamIDPConfig provider.UpstreamOIDCIdentityProviderI,
	idTokenClaims map[string]interface{},
) (string, error) {
	usernameClaim := upstreamIDPConfig.GetUsernameClaim()

	user := ""
	if usernameClaim == "" {
		// The spec says the "sub" claim is only unique per issuer, so by default when there is
		// no specific username claim configured we will prepend the issuer string to make it globally unique.
		upstreamIssuer := idTokenClaims[idTokenIssuerClaim]
		if upstreamIssuer == "" {
			plog.Warning(
				"issuer claim in upstream ID token missing",
				"upstreamName", upstreamIDPConfig.GetName(),
				"issClaim", upstreamIssuer,
			)
			return "", httperr.New(http.StatusUnprocessableEntity, "issuer claim in upstream ID token missing")
		}
		upstreamIssuerAsString, ok := upstreamIssuer.(string)
		if !ok {
			plog.Warning(
				"issuer claim in upstream ID token has invalid format",
				"upstreamName", upstreamIDPConfig.GetName(),
				"issClaim", upstreamIssuer,
			)
			return "", httperr.New(http.StatusUnprocessableEntity, "issuer claim in upstream ID token has invalid format")
		}
		user = fmt.Sprintf("%s?%s=", upstreamIssuerAsString, idTokenSubjectClaim)
		usernameClaim = defaultUpstreamUsernameClaim
	}

	usernameAsInterface, ok := idTokenClaims[usernameClaim]
	if !ok {
		plog.Warning(
			"no username claim in upstream ID token",
			"upstreamName", upstreamIDPConfig.GetName(),
			"configuredUsernameClaim", upstreamIDPConfig.GetUsernameClaim(),
			"usernameClaim", usernameClaim,
		)
		return "", httperr.New(http.StatusUnprocessableEntity, "no username claim in upstream ID token")
	}

	username, ok := usernameAsInterface.(string)
	if !ok {
		plog.Warning(
			"username claim in upstream ID token has invalid format",
			"upstreamName", upstreamIDPConfig.GetName(),
			"configuredUsernameClaim", upstreamIDPConfig.GetUsernameClaim(),
			"usernameClaim", usernameClaim,
		)
		return "", httperr.New(http.StatusUnprocessableEntity, "username claim in upstream ID token has invalid format")
	}

	return fmt.Sprintf("%s%s", user, username), nil
}

func getGroupsFromUpstreamIDToken(
	upstreamIDPConfig provider.UpstreamOIDCIdentityProviderI,
	idTokenClaims map[string]interface{},
) ([]string, error) {
	groupsClaim := upstreamIDPConfig.GetGroupsClaim()
	if groupsClaim == "" {
		return nil, nil
	}

	groupsAsInterface, ok := idTokenClaims[groupsClaim]
	if !ok {
		plog.Warning(
			"no groups claim in upstream ID token",
			"upstreamName", upstreamIDPConfig.GetName(),
			"configuredGroupsClaim", upstreamIDPConfig.GetGroupsClaim(),
			"groupsClaim", groupsClaim,
		)
		return nil, httperr.New(http.StatusUnprocessableEntity, "no groups claim in upstream ID token")
	}

	groups, ok := groupsAsInterface.([]string)
	if !ok {
		plog.Warning(
			"groups claim in upstream ID token has invalid format",
			"upstreamName", upstreamIDPConfig.GetName(),
			"configuredGroupsClaim", upstreamIDPConfig.GetGroupsClaim(),
			"groupsClaim", groupsClaim,
		)
		return nil, httperr.New(http.StatusUnprocessableEntity, "groups claim in upstream ID token has invalid format")
	}

	return groups, nil
}

func makeDownstreamSession(username string, groups []string) *openid.DefaultSession {
	now := time.Now().UTC()
	openIDSession := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject:     username,
			RequestedAt: now,
			AuthTime:    now,
		},
	}
	if groups != nil {
		openIDSession.Claims.Extra = map[string]interface{}{
			downstreamGroupsClaim: groups,
		}
	}
	return openIDSession
}
