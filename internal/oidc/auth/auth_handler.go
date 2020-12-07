// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package auth provides a handler for the OIDC authorization endpoint.
package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"golang.org/x/oauth2"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

func NewHandler(
	downstreamIssuer string,
	idpListGetter oidc.IDPListGetter,
	oauthHelper fosite.OAuth2Provider,
	generateCSRF func() (csrftoken.CSRFToken, error),
	generatePKCE func() (pkce.Code, error),
	generateNonce func() (nonce.Nonce, error),
	upstreamStateEncoder oidc.Encoder,
	cookieCodec oidc.Codec,
) http.Handler {
	return httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
			// Authorization Servers MUST support the use of the HTTP GET and POST methods defined in
			// RFC 2616 [RFC2616] at the Authorization Endpoint.
			return httperr.Newf(http.StatusMethodNotAllowed, "%s (try GET or POST)", r.Method)
		}

		csrfFromCookie := readCSRFCookie(r, cookieCodec)

		authorizeRequester, err := oauthHelper.NewAuthorizeRequest(r.Context(), r)
		if err != nil {
			plog.Info("authorize request error", oidc.FositeErrorForLog(err)...)
			oauthHelper.WriteAuthorizeError(w, authorizeRequester, err)
			return nil
		}

		upstreamIDP, err := chooseUpstreamIDP(idpListGetter)
		if err != nil {
			plog.WarningErr("authorize upstream config", err)
			return err
		}

		// Grant the openid scope (for now) if they asked for it so that `NewAuthorizeResponse` will perform its OIDC validations.
		grantOpenIDScopeIfRequested(authorizeRequester)

		now := time.Now()
		_, err = oauthHelper.NewAuthorizeResponse(r.Context(), authorizeRequester, &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				// Temporary claim values to allow `NewAuthorizeResponse` to perform other OIDC validations.
				Subject:     "none",
				AuthTime:    now,
				RequestedAt: now,
			},
		})
		if err != nil {
			plog.Info("authorize response error", oidc.FositeErrorForLog(err)...)
			oauthHelper.WriteAuthorizeError(w, authorizeRequester, err)
			return nil
		}

		csrfValue, nonceValue, pkceValue, err := generateValues(generateCSRF, generateNonce, generatePKCE)
		if err != nil {
			plog.Error("authorize generate error", err)
			return err
		}
		if csrfFromCookie != "" {
			csrfValue = csrfFromCookie
		}

		upstreamOAuthConfig := oauth2.Config{
			ClientID: upstreamIDP.GetClientID(),
			Endpoint: oauth2.Endpoint{
				AuthURL: upstreamIDP.GetAuthorizationURL().String(),
			},
			RedirectURL: fmt.Sprintf("%s/callback", downstreamIssuer),
			Scopes:      upstreamIDP.GetScopes(),
		}

		encodedStateParamValue, err := upstreamStateParam(
			authorizeRequester,
			upstreamIDP.GetName(),
			nonceValue,
			csrfValue,
			pkceValue,
			upstreamStateEncoder,
		)
		if err != nil {
			plog.Error("authorize upstream state param error", err)
			return err
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
				oauth2.AccessTypeOffline,
				nonceValue.Param(),
				pkceValue.Challenge(),
				pkceValue.Method(),
			),
			302,
		)

		return nil
	})
}

func readCSRFCookie(r *http.Request, codec oidc.Codec) csrftoken.CSRFToken {
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

func grantOpenIDScopeIfRequested(authorizeRequester fosite.AuthorizeRequester) {
	for _, scope := range authorizeRequester.GetRequestedScopes() {
		if scope == "openid" {
			authorizeRequester.GrantScope(scope)
		}
	}
}

func chooseUpstreamIDP(idpListGetter oidc.IDPListGetter) (provider.UpstreamOIDCIdentityProviderI, error) {
	allUpstreamIDPs := idpListGetter.GetIDPList()
	if len(allUpstreamIDPs) == 0 {
		return nil, httperr.New(
			http.StatusUnprocessableEntity,
			"No upstream providers are configured",
		)
	} else if len(allUpstreamIDPs) > 1 {
		return nil, httperr.New(
			http.StatusUnprocessableEntity,
			"Too many upstream providers are configured (support for multiple upstreams is not yet implemented)",
		)
	}
	return allUpstreamIDPs[0], nil
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

func addCSRFSetCookieHeader(w http.ResponseWriter, csrfValue csrftoken.CSRFToken, codec oidc.Codec) error {
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
