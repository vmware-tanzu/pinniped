// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/ory/fosite"

	"go.pinniped.dev/internal/federationdomain/downstreamsession"
	"go.pinniped.dev/internal/federationdomain/endpoints/loginurl"
	"go.pinniped.dev/internal/federationdomain/federationdomainproviders"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider/resolvedldap"
	"go.pinniped.dev/internal/federationdomain/stateparam"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/plog"
)

func NewPostHandler(
	issuerURL string,
	upstreamIDPs federationdomainproviders.FederationDomainIdentityProvidersFinderI,
	oauthHelper fosite.OAuth2Provider,
	auditLogger plog.AuditLogger,
) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, encodedState stateparam.Encoded, decodedState *oidc.UpstreamStateParamData) error {
		// Note that the login handler prevents this handler from being called with OIDC upstreams.
		idp, err := upstreamIDPs.FindUpstreamIDPByDisplayName(decodedState.UpstreamName)
		if err != nil {
			// This shouldn't normally happen because the authorization endpoint ensured that this provider existed
			// at that time. It would be possible in the unlikely event that the provider was deleted during the login.
			plog.Error("error finding upstream provider", err)
			return httperr.Wrap(http.StatusUnprocessableEntity, "error finding upstream provider", err)
		}

		// Get the original params that were used at the authorization endpoint.
		downstreamAuthParams, err := url.ParseQuery(decodedState.AuthParams)
		if err != nil {
			// This shouldn't really happen because the authorization endpoint encoded these query params correctly.
			plog.Error("error reading state downstream auth params", err)
			return httperr.New(http.StatusBadRequest, "error reading state downstream auth params")
		}

		// Recreate enough of the original authorize request so we can pass it to NewAuthorizeRequest().
		reconstitutedAuthRequest := &http.Request{Form: downstreamAuthParams}
		authorizeRequester, err := oauthHelper.NewAuthorizeRequest(r.Context(), reconstitutedAuthRequest)
		if err != nil {
			// This shouldn't really happen because the authorization endpoint has already validated these params
			// by calling NewAuthorizeRequest() itself.
			plog.Error("error using state downstream auth params", err,
				"fositeErr", oidc.FositeErrorForLog(err))
			return httperr.New(http.StatusBadRequest, "error using state downstream auth params")
		}

		// Automatically grant certain scopes, but only if they were requested.
		// This is instead of asking the user to approve these scopes. Note that `NewAuthorizeRequest` would have returned
		// an error if the client requested a scope that they are not allowed to request, so we don't need to worry about that here.
		downstreamsession.AutoApproveScopes(authorizeRequester)

		// Get the username and password form params from the POST body.
		submittedUsername := r.PostFormValue(loginurl.UsernameParamName)
		submittedPassword := r.PostFormValue(loginurl.PasswordParamName)

		// Treat blank username or password as a bad username/password combination, as opposed to an internal error.
		if submittedUsername == "" || submittedPassword == "" {
			// User forgot to enter one of the required fields.
			// The user may try to log in again if they'd like, so redirect back to the login page with an error.
			return redirectToLoginPage(r, w, issuerURL, encodedState, loginurl.ShowBadUserPassErr)
		}

		// Attempt to authenticate the user with the upstream IDP.
		identity, loginExtras, err := idp.Login(r.Context(), submittedUsername, submittedPassword)
		if err != nil {
			switch {
			case errors.Is(err, resolvedldap.ErrUnexpectedUpstreamLDAPError):
				// There was some problem during authentication with the upstream, aside from bad username/password.
				// The user may try to log in again if they'd like, so redirect back to the login page with an error.
				return redirectToLoginPage(r, w, issuerURL, encodedState, loginurl.ShowInternalError)
			case err == resolvedldap.ErrAccessDeniedDueToUsernamePasswordNotAccepted:
				// The upstream did not accept the username/password combination.
				// The user may try to log in again if they'd like, so redirect back to the login page with an error.
				return redirectToLoginPage(r, w, issuerURL, encodedState, loginurl.ShowBadUserPassErr)
			default:
				// Some other error happened.
				oidc.WriteAuthorizeError(r, w, oauthHelper, authorizeRequester, err, false)
				return nil
			}
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
			err = fosite.ErrAccessDenied.WithHintf("Reason: %s.", err.Error())
			oidc.WriteAuthorizeError(r, w, oauthHelper, authorizeRequester, err, false)
			return nil
		}

		oidc.PerformAuthcodeRedirect(r, w, oauthHelper, authorizeRequester, session, false)

		return nil
	}
}

// redirectToLoginPage redirects to the GET /login page of the specified issuer.
func redirectToLoginPage(
	r *http.Request,
	w http.ResponseWriter,
	downstreamIssuer string,
	encodedStateParamValue stateparam.Encoded,
	errToDisplay loginurl.ErrorParamValue,
) error {
	loginURL, err := loginurl.URL(downstreamIssuer, encodedStateParamValue, errToDisplay)
	if err != nil {
		return err
	}

	http.Redirect(w, r,
		loginURL,
		http.StatusSeeOther, // match fosite and https://tools.ietf.org/id/draft-ietf-oauth-security-topics-18.html#section-4.11
	)

	return nil
}
