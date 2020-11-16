// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package auth provides a handler for the OIDC authorization endpoint.
package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"golang.org/x/oauth2"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidcclient/nonce"
	"go.pinniped.dev/internal/oidcclient/pkce"
	"go.pinniped.dev/internal/plog"
)

const (
	// Just in case we need to make a breaking change to the format of the upstream state param,
	// we are including a format version number. This gives the opportunity for a future version of Pinniped
	// to have the consumer of this format decide to reject versions that it doesn't understand.
	upstreamStateParamFormatVersion = "1"

	// The `name` passed to the encoder for encoding the upstream state param value. This name is short
	// because it will be encoded into the upstream state param value and we're trying to keep that small.
	upstreamStateParamEncodingName = "s"
)

// Encoder is the encoding side of the securecookie.Codec interface.
type Encoder interface {
	Encode(name string, value interface{}) (string, error)
}

func NewHandler(
	issuer string,
	idpListGetter oidc.IDPListGetter,
	oauthHelper fosite.OAuth2Provider,
	generateCSRF func() (csrftoken.CSRFToken, error),
	generatePKCE func() (pkce.Code, error),
	generateNonce func() (nonce.Nonce, error),
	upstreamStateEncoder Encoder,
	cookieCodec securecookie.Codec,
) http.Handler {
	return httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
			// Authorization Servers MUST support the use of the HTTP GET and POST methods defined in
			// RFC 2616 [RFC2616] at the Authorization Endpoint.
			return httperr.Newf(http.StatusMethodNotAllowed, "%s (try GET or POST)", r.Method)
		}

		csrfFromCookie, err := readCSRFCookie(r, cookieCodec)
		if err != nil {
			plog.InfoErr("error reading CSRF cookie", err)
			return err
		}

		authorizeRequester, err := oauthHelper.NewAuthorizeRequest(r.Context(), r)
		if err != nil {
			plog.Info("authorize request error", fositeErrorForLog(err)...)
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
			plog.Info("authorize response error", fositeErrorForLog(err)...)
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
			ClientID: upstreamIDP.ClientID,
			Endpoint: oauth2.Endpoint{
				AuthURL: upstreamIDP.AuthorizationURL.String(),
			},
			RedirectURL: fmt.Sprintf("%s/callback/%s", issuer, upstreamIDP.Name),
			Scopes:      upstreamIDP.Scopes,
		}

		encodedStateParamValue, err := upstreamStateParam(authorizeRequester, nonceValue, csrfValue, pkceValue, upstreamStateEncoder)
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

func readCSRFCookie(r *http.Request, codec securecookie.Codec) (csrftoken.CSRFToken, error) {
	receivedCSRFCookie, err := r.Cookie(oidc.CSRFCookieName)
	if err != nil {
		// Error means that the cookie was not found
		return "", nil
	}

	var csrfFromCookie csrftoken.CSRFToken
	err = codec.Decode(oidc.CSRFCookieEncodingName, receivedCSRFCookie.Value, &csrfFromCookie)
	if err != nil {
		return "", httperr.Wrap(http.StatusUnprocessableEntity, "error reading CSRF cookie", err)
	}

	return csrfFromCookie, nil
}

func grantOpenIDScopeIfRequested(authorizeRequester fosite.AuthorizeRequester) {
	for _, scope := range authorizeRequester.GetRequestedScopes() {
		if scope == "openid" {
			authorizeRequester.GrantScope(scope)
		}
	}
}

func chooseUpstreamIDP(idpListGetter oidc.IDPListGetter) (*provider.UpstreamOIDCIdentityProvider, error) {
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
	return &allUpstreamIDPs[0], nil
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

// Keep the JSON to a minimal size because the upstream provider could impose size limitations on the state param.
type upstreamStateParamData struct {
	AuthParams              string              `json:"p"`
	Nonce                   nonce.Nonce         `json:"n"`
	CSRFToken               csrftoken.CSRFToken `json:"c"`
	PKCECode                pkce.Code           `json:"k"`
	StateParamFormatVersion string              `json:"v"`
}

func upstreamStateParam(
	authorizeRequester fosite.AuthorizeRequester,
	nonceValue nonce.Nonce,
	csrfValue csrftoken.CSRFToken,
	pkceValue pkce.Code,
	encoder Encoder,
) (string, error) {
	stateParamData := upstreamStateParamData{
		AuthParams:              authorizeRequester.GetRequestForm().Encode(),
		Nonce:                   nonceValue,
		CSRFToken:               csrfValue,
		PKCECode:                pkceValue,
		StateParamFormatVersion: upstreamStateParamFormatVersion,
	}
	encodedStateParamValue, err := encoder.Encode(upstreamStateParamEncodingName, stateParamData)
	if err != nil {
		return "", httperr.Wrap(http.StatusInternalServerError, "error encoding upstream state param", err)
	}
	return encodedStateParamValue, nil
}

func addCSRFSetCookieHeader(w http.ResponseWriter, csrfValue csrftoken.CSRFToken, codec securecookie.Codec) error {
	encodedCSRFValue, err := codec.Encode(oidc.CSRFCookieEncodingName, csrfValue)
	if err != nil {
		return httperr.Wrap(http.StatusInternalServerError, "error encoding CSRF cookie", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     oidc.CSRFCookieName,
		Value:    encodedCSRFValue,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
	})

	return nil
}

func fositeErrorForLog(err error) []interface{} {
	rfc6749Error := fosite.ErrorToRFC6749Error(err)
	keysAndValues := make([]interface{}, 0)
	keysAndValues = append(keysAndValues, "name")
	keysAndValues = append(keysAndValues, rfc6749Error.Name)
	keysAndValues = append(keysAndValues, "status")
	keysAndValues = append(keysAndValues, rfc6749Error.Status())
	keysAndValues = append(keysAndValues, "description")
	keysAndValues = append(keysAndValues, rfc6749Error.Description)
	return keysAndValues
}
