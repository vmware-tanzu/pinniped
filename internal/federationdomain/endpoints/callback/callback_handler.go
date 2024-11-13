// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package callback provides a handler for the OIDC callback endpoint.
package callback

import (
	"net/http"
	"net/url"

	"github.com/ory/fosite"

	"go.pinniped.dev/internal/auditevent"
	"go.pinniped.dev/internal/federationdomain/downstreamsession"
	"go.pinniped.dev/internal/federationdomain/federationdomainproviders"
	"go.pinniped.dev/internal/federationdomain/formposthtml"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/stateparam"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/httputil/securityheader"
	"go.pinniped.dev/internal/plog"
)

func NewHandler(
	upstreamIDPs federationdomainproviders.FederationDomainIdentityProvidersFinderI,
	oauthHelper fosite.OAuth2Provider,
	stateDecoder, cookieDecoder oidc.Decoder,
	redirectURI string,
	auditLogger plog.AuditLogger,
) http.Handler {
	handler := httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		encodedState, decodedState, err := validateRequest(r, stateDecoder, cookieDecoder)
		if err != nil {
			return err
		}

		auditLogger.Audit(auditevent.AuthorizeIDFromParameters, &plog.AuditParams{
			ReqCtx:        r.Context(),
			KeysAndValues: []any{"authorizeID", encodedState.AuthorizeID()},
		})

		idp, err := upstreamIDPs.FindUpstreamIDPByDisplayName(decodedState.UpstreamName)
		if err != nil || idp == nil {
			plog.Warning("upstream provider not found")
			return httperr.New(http.StatusUnprocessableEntity, "upstream provider not found")
		}

		auditLogger.Audit(auditevent.UsingUpstreamIDP, &plog.AuditParams{
			ReqCtx: r.Context(),
			KeysAndValues: []any{
				"displayName", idp.GetDisplayName(),
				"resourceName", idp.GetProvider().GetResourceName(),
				"resourceUID", idp.GetProvider().GetResourceUID(),
				"type", idp.GetSessionProviderType(),
			},
		})

		downstreamAuthParams, err := url.ParseQuery(decodedState.AuthParams)
		if err != nil {
			plog.Error("error reading state downstream auth params", err)
			return httperr.New(http.StatusBadRequest, "error reading state downstream auth params")
		}

		// Recreate enough of the original authorize request, so we can pass it to NewAuthorizeRequest().
		reconstitutedAuthRequest := &http.Request{Form: downstreamAuthParams}
		authorizeRequester, err := oauthHelper.NewAuthorizeRequest(r.Context(), reconstitutedAuthRequest)
		if err != nil {
			plog.Error("error using state downstream auth params", err,
				"identityProviderDisplayName", idp.GetDisplayName(),
				"identityProviderResourceName", idp.GetProvider().GetResourceName(),
				"supervisorCallbackURL", redirectURI,
				"fositeErr", oidc.FositeErrorForLog(err))
			return httperr.New(http.StatusBadRequest, "error using state downstream auth params")
		}

		// Automatically grant certain scopes, but only if they were requested.
		// This is instead of asking the user to approve these scopes. Note that `NewAuthorizeRequest` would have returned
		// an error if the client requested a scope that they are not allowed to request, so we don't need to worry about that here.
		downstreamsession.AutoApproveScopes(authorizeRequester)

		identity, loginExtras, err := idp.LoginFromCallback(r.Context(), authcode(r), decodedState.PKCECode, decodedState.Nonce, redirectURI)
		if err != nil {
			plog.WarningErr("unable to complete login from callback", err,
				"identityProviderDisplayName", idp.GetDisplayName(),
				"identityProviderResourceName", idp.GetProvider().GetResourceName(),
				"supervisorCallbackURL", redirectURI)
			return err
		}

		session, err := downstreamsession.NewPinnipedSession(r.Context(), auditLogger, &downstreamsession.SessionConfig{
			UpstreamIdentity:    identity,
			UpstreamLoginExtras: loginExtras,
			ClientID:            authorizeRequester.GetClient().GetID(),
			GrantedScopes:       authorizeRequester.GetGrantedScopes(),
			IdentityProvider:    idp,
			SessionIDGetter:     authorizeRequester,
		})
		if err != nil {
			plog.WarningErr("unable to create a Pinniped session", err,
				"identityProviderDisplayName", idp.GetDisplayName(),
				"identityProviderResourceName", idp.GetProvider().GetResourceName(),
				"supervisorCallbackURL", redirectURI)
			return httperr.Wrap(http.StatusUnprocessableEntity, err.Error(), err)
		}

		authorizeResponder, err := oauthHelper.NewAuthorizeResponse(r.Context(), authorizeRequester, session)
		if err != nil {
			plog.WarningErr("error while generating and saving authcode", err,
				"identityProviderDisplayName", idp.GetDisplayName(),
				"identityProviderResourceName", idp.GetProvider().GetResourceName(),
				"supervisorCallbackURL", redirectURI,
				"fositeErr", oidc.FositeErrorForLog(err))
			return httperr.Wrap(http.StatusInternalServerError, "error while generating and saving authcode", err)
		}

		oauthHelper.WriteAuthorizeResponse(r.Context(), w, authorizeRequester, authorizeResponder)

		return nil
	})
	return securityheader.WrapWithCustomCSP(handler, formposthtml.ContentSecurityPolicy())
}

func authcode(r *http.Request) string {
	return r.FormValue("code")
}

func validateRequest(r *http.Request, stateDecoder, cookieDecoder oidc.Decoder) (stateparam.Encoded, *oidc.UpstreamStateParamData, error) {
	if r.Method != http.MethodGet {
		return "", nil, httperr.Newf(http.StatusMethodNotAllowed, "%s (try GET)", r.Method)
	}

	encodedState, decodedState, err := oidc.ReadStateParamAndValidateCSRFCookie(r, cookieDecoder, stateDecoder)
	if err != nil {
		plog.InfoErr("state or CSRF error", err)
		return "", nil, err
	}

	if authcode(r) == "" {
		plog.Info("code param not found")
		return "", nil, httperr.New(http.StatusBadRequest, "code param not found")
	}

	return encodedState, decodedState, nil
}
