// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package auth provides a handler for the OIDC authorization endpoint.
package auth

import (
	"fmt"
	"net/http"

	"github.com/ory/fosite/handler/openid"

	"github.com/ory/fosite"

	"golang.org/x/oauth2"
	"k8s.io/klog/v2"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidcclient/nonce"
	"go.pinniped.dev/internal/oidcclient/pkce"
	"go.pinniped.dev/internal/oidcclient/state"
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
			oauthHelper.WriteAuthorizeError(w, authorizeRequester, err)
			return nil
		}

		upstreamIDP, err := chooseUpstreamIDP(idpListGetter)
		if err != nil {
			return err
		}

		_, err = oauthHelper.NewAuthorizeResponse(r.Context(), authorizeRequester, &openid.DefaultSession{})
		if err != nil {
			oauthHelper.WriteAuthorizeError(w, authorizeRequester, err)
			return nil
		}

		stateValue, nonceValue, pkceValue, err := generateParams(generateState, generateNonce, generatePKCE)
		if err != nil {
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
		klog.InfoS("error generating state param", "err", err)
		return "", "", "", httperr.Wrap(http.StatusInternalServerError, "error generating state param", err)
	}
	nonceValue, err := generateNonce()
	if err != nil {
		klog.InfoS("error generating nonce param", "err", err)
		return "", "", "", httperr.Wrap(http.StatusInternalServerError, "error generating nonce param", err)
	}
	pkceValue, err := generatePKCE()
	if err != nil {
		klog.InfoS("error generating PKCE param", "err", err)
		return "", "", "", httperr.Wrap(http.StatusInternalServerError, "error generating PKCE param", err)
	}
	return stateValue, nonceValue, pkceValue, nil
}
