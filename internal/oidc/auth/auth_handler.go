// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package auth provides a handler for the OIDC authorization endpoint.
package auth

import (
	"fmt"
	"net/http"
	"time"

	"go.pinniped.dev/internal/plog"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidcclient/nonce"
	"go.pinniped.dev/internal/oidcclient/pkce"
	"go.pinniped.dev/internal/oidcclient/state"
	"golang.org/x/oauth2"
)

type IDPListGetter interface {
	GetIDPList() []provider.UpstreamOIDCIdentityProvider
}

func NewHandler(
	issuer string,
	idpListGetter IDPListGetter,
	oauthHelper fosite.OAuth2Provider,
	generateState func() (state.State, error),
	generatePKCE func() (pkce.Code, error),
	generateNonce func() (nonce.Nonce, error),
) http.Handler {
	return httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
			// Authorization Servers MUST support the use of the HTTP GET and POST methods defined in
			// RFC 2616 [RFC2616] at the Authorization Endpoint.
			return httperr.Newf(http.StatusMethodNotAllowed, "%s (try GET or POST)", r.Method)
		}

		authorizeRequester, err := oauthHelper.NewAuthorizeRequest(r.Context(), r)
		if err != nil {
			plog.Info("authorize request error", fositeErrorForLog(err)...)
			oauthHelper.WriteAuthorizeError(w, authorizeRequester, err)
			return nil
		}

		upstreamIDP, err := chooseUpstreamIDP(idpListGetter)
		if err != nil {
			plog.InfoErr("authorize request error", err)
			return err
		}

		// Grant the openid scope (for now) if they asked for it so that `NewAuthorizeResponse` will perform its OIDC validations.
		for _, scope := range authorizeRequester.GetRequestedScopes() {
			if scope == "openid" {
				authorizeRequester.GrantScope(scope)
			}
		}

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

		stateValue, nonceValue, pkceValue, err := generateParams(generateState, generateNonce, generatePKCE)
		if err != nil {
			plog.InfoErr("authorize generate error", err)
			return err
		}

		upstreamOAuthConfig := oauth2.Config{
			ClientID: upstreamIDP.ClientID,
			Endpoint: oauth2.Endpoint{
				AuthURL: upstreamIDP.AuthorizationURL.String(),
			},
			RedirectURL: fmt.Sprintf("%s/callback/%s", issuer, upstreamIDP.Name),
			Scopes:      upstreamIDP.Scopes,
		}

		http.Redirect(w, r,
			upstreamOAuthConfig.AuthCodeURL(
				stateValue.String(),
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

func chooseUpstreamIDP(idpListGetter IDPListGetter) (*provider.UpstreamOIDCIdentityProvider, error) {
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

func generateParams(
	generateState func() (state.State, error),
	generateNonce func() (nonce.Nonce, error),
	generatePKCE func() (pkce.Code, error),
) (state.State, nonce.Nonce, pkce.Code, error) {
	stateValue, err := generateState()
	if err != nil {
		plog.InfoErr("error generating state param", err)
		return "", "", "", httperr.Wrap(http.StatusInternalServerError, "error generating state param", err)
	}
	nonceValue, err := generateNonce()
	if err != nil {
		plog.InfoErr("error generating nonce param", err)
		return "", "", "", httperr.Wrap(http.StatusInternalServerError, "error generating nonce param", err)
	}
	pkceValue, err := generatePKCE()
	if err != nil {
		plog.InfoErr("error generating PKCE param", err)
		return "", "", "", httperr.Wrap(http.StatusInternalServerError, "error generating PKCE param", err)
	}
	return stateValue, nonceValue, pkceValue, nil
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
