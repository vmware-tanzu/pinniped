// Copyright 2022-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"net/http"
	"net/url"

	"github.com/ory/fosite"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/downstreamsession"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
)

func NewPostHandler(issuerURL string, upstreamIDPs provider.FederationDomainIdentityProvidersFinderI, oauthHelper fosite.OAuth2Provider) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, encodedState string, decodedState *oidc.UpstreamStateParamData) error {
		// Note that the login handler prevents this handler from being called with OIDC upstreams.
		_, ldapUpstream, err := upstreamIDPs.FindUpstreamIDPByDisplayName(decodedState.UpstreamName)
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
		submittedUsername := r.PostFormValue(usernameParamName)
		submittedPassword := r.PostFormValue(passwordParamName)

		// Treat blank username or password as a bad username/password combination, as opposed to an internal error.
		if submittedUsername == "" || submittedPassword == "" {
			// User forgot to enter one of the required fields.
			// The user may try to log in again if they'd like, so redirect back to the login page with an error.
			return RedirectToLoginPage(r, w, issuerURL, encodedState, ShowBadUserPassErr)
		}

		// Attempt to authenticate the user with the upstream IDP.
		authenticateResponse, authenticated, err := ldapUpstream.Provider.AuthenticateUser(r.Context(), submittedUsername, submittedPassword, authorizeRequester.GetGrantedScopes())
		if err != nil {
			plog.WarningErr("unexpected error during upstream LDAP authentication", err, "upstreamName", ldapUpstream.Provider.GetName())
			// There was some problem during authentication with the upstream, aside from bad username/password.
			// The user may try to log in again if they'd like, so redirect back to the login page with an error.
			return RedirectToLoginPage(r, w, issuerURL, encodedState, ShowInternalError)
		}
		if !authenticated {
			// The upstream did not accept the username/password combination.
			// The user may try to log in again if they'd like, so redirect back to the login page with an error.
			return RedirectToLoginPage(r, w, issuerURL, encodedState, ShowBadUserPassErr)
		}

		// We had previously interrupted the regular steps of the OIDC authcode flow to show the login page UI.
		// Now the upstream IDP has authenticated the user, so now we're back into the regular OIDC authcode flow steps.
		// Both success and error responses from this point onwards should look like the usual fosite redirect
		// responses, and a happy redirect response will include a downstream authcode.
		subject := downstreamsession.DownstreamSubjectFromUpstreamLDAP(ldapUpstream.Provider, authenticateResponse)
		upstreamUsername := authenticateResponse.User.GetName()
		upstreamGroups := authenticateResponse.User.GetGroups()

		username, groups, err := downstreamsession.ApplyIdentityTransformations(r.Context(), ldapUpstream.Transforms, upstreamUsername, upstreamGroups)
		if err != nil {
			oidc.WriteAuthorizeError(r, w, oauthHelper, authorizeRequester,
				fosite.ErrAccessDenied.WithHintf("Reason: %s.", err.Error()), false,
			)
			return nil
		}

		customSessionData := downstreamsession.MakeDownstreamLDAPOrADCustomSessionData(ldapUpstream.Provider, ldapUpstream.SessionProviderType, authenticateResponse, username, upstreamUsername, upstreamGroups)
		openIDSession := downstreamsession.MakeDownstreamSession(subject, username, groups,
			authorizeRequester.GetGrantedScopes(), authorizeRequester.GetClient().GetID(), customSessionData, map[string]interface{}{})
		oidc.PerformAuthcodeRedirect(r, w, oauthHelper, authorizeRequester, openIDSession, false)

		return nil
	}
}
