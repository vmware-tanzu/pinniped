// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package token provides a handler for the OIDC token endpoint.
package token

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/ory/fosite"
	errorsx "github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/warning"

	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/federationdomain/federationdomainproviders"
	"go.pinniped.dev/internal/federationdomain/idtokenlifespan"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/federationdomain/timeouts"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
)

//nolint:gochecknoglobals // please treat this as a readonly const, do not mutate
var paramsSafeToLog = sets.New[string](
	// Standard params from https://openid.net/specs/openid-connect-core-1_0.html for authcde and refresh grants.
	// Redacting code, client_secret, refresh_token, and PKCE code_verifier params.
	"grant_type", "client_id", "redirect_uri", "scope",
	// Token exchange params from https://datatracker.ietf.org/doc/html/rfc8693.
	// Redact subject_token and actor_token.
	// We don't allow all of these, but they should be safe to log.
	"audience", "resource", "scope", "requested_token_type", "actor_token_type", "subject_token_type",
)

func NewHandler(
	idpLister federationdomainproviders.FederationDomainIdentityProvidersListerI,
	oauthHelper fosite.OAuth2Provider,
	overrideAccessTokenLifespan timeouts.OverrideLifespan,
	overrideIDTokenLifespan timeouts.OverrideLifespan,
	auditLogger plog.AuditLogger,
) http.Handler {
	return httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		session := psession.NewPinnipedSession()
		accessRequest, err := oauthHelper.NewAccessRequest(r.Context(), r, session)
		if err != nil {
			plog.Info("token request error", oidc.FositeErrorForLog(err)...)
			oauthHelper.WriteAccessError(r.Context(), w, accessRequest, err)
			return nil
		}

		// Note that r.PostForm and accessRequest were populated by NewAccessRequest().
		auditLogger.Audit(plog.AuditEventHTTPRequestParameters, r.Context(), accessRequest,
			"params", plog.SanitizeParams(r.PostForm, paramsSafeToLog))

		// Check if we are performing a refresh grant.
		if accessRequest.GetGrantTypes().ExactOne(oidcapi.GrantTypeRefreshToken) {
			// The above call to NewAccessRequest has loaded the session from storage into the accessRequest variable.
			// The session, requested scopes, and requested audience from the original authorize request was retrieved
			// from the Kube storage layer and added to the accessRequest. Additionally, the audience and scopes may
			// have already been granted on the accessRequest.
			err = upstreamRefresh(r.Context(), accessRequest, idpLister, auditLogger)
			if err != nil {
				plog.Info("upstream refresh error", oidc.FositeErrorForLog(err)...)
				oauthHelper.WriteAccessError(r.Context(), w, accessRequest, err)
				return nil
			}
		}

		// When we are in the authorization code flow, check if we have any warnings that previous handlers want us
		// to send to the client to be printed on the CLI.
		if accessRequest.GetGrantTypes().ExactOne(oidcapi.GrantTypeAuthorizationCode) {
			storedSession := accessRequest.GetSession().(*psession.PinnipedSession)
			customSessionData := storedSession.Custom
			if customSessionData != nil {
				for _, warningText := range customSessionData.Warnings {
					warning.AddWarning(r.Context(), "", warningText)
				}
			}
		}

		// Lifetimes of the access and refresh tokens are determined by the above call to NewAccessRequest.
		// Depending on the request, sometimes override the default access token lifespan.
		maybeOverrideDefaultAccessTokenLifetime(overrideAccessTokenLifespan, accessRequest)

		// Create the token response.
		// The lifetime of the ID token will be determined inside the call NewAccessResponse.
		// Depending on the request, sometimes override the default ID token lifespan by putting
		// the override value onto the context.
		accessResponse, err := oauthHelper.NewAccessResponse(
			maybeOverrideDefaultIDTokenLifetime(r.Context(), overrideIDTokenLifespan, accessRequest),
			accessRequest)
		if err != nil {
			plog.Info("token response error", oidc.FositeErrorForLog(err)...)
			oauthHelper.WriteAccessError(r.Context(), w, accessRequest, err)
			return nil
		}

		oauthHelper.WriteAccessResponse(r.Context(), w, accessRequest, accessResponse)

		return nil
	})
}

func maybeOverrideDefaultAccessTokenLifetime(overrideAccessTokenLifespan timeouts.OverrideLifespan, accessRequest fosite.AccessRequester) {
	if newLifespan, doOverride := overrideAccessTokenLifespan(accessRequest); doOverride {
		accessRequest.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(newLifespan).Round(time.Second))
	}
}

func maybeOverrideDefaultIDTokenLifetime(baseCtx context.Context, overrideIDTokenLifespan timeouts.OverrideLifespan, accessRequest fosite.AccessRequester) context.Context {
	if newLifespan, doOverride := overrideIDTokenLifespan(accessRequest); doOverride {
		return idtokenlifespan.OverrideIDTokenLifespanInContext(baseCtx, newLifespan)
	}
	return baseCtx
}

func errMissingUpstreamSessionInternalError() *fosite.RFC6749Error {
	return &fosite.RFC6749Error{
		ErrorField:       "error",
		DescriptionField: "There was an internal server error.",
		HintField:        "Required upstream data not found in session.",
		CodeField:        http.StatusInternalServerError,
	}
}

func errUpstreamRefreshError() *fosite.RFC6749Error {
	return &fosite.RFC6749Error{
		ErrorField:       "error",
		DescriptionField: "Error during upstream refresh.",
		CodeField:        http.StatusUnauthorized,
	}
}

func upstreamRefresh(
	ctx context.Context,
	accessRequest fosite.AccessRequester,
	idpLister federationdomainproviders.FederationDomainIdentityProvidersListerI,
	auditLogger plog.AuditLogger,
) error {
	session := accessRequest.GetSession().(*psession.PinnipedSession)

	customSessionData := session.Custom
	if customSessionData == nil {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}
	providerName := customSessionData.ProviderName
	providerType := customSessionData.ProviderType
	providerUID := customSessionData.ProviderUID
	if providerUID == "" || providerName == "" {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}

	skipGroups := !slices.Contains(accessRequest.GetGrantedScopes(), oidcapi.ScopeGroups)

	if session.IDTokenClaims().AuthTime.IsZero() {
		return errorsx.WithStack(resolvedprovider.ErrMissingUpstreamSessionInternalError())
	}

	err := validateSessionHasUsername(session)
	if err != nil {
		return err
	}

	var oldTransformedGroups []string
	if !skipGroups {
		// Only validate the groups in the session if the groups scope was granted.
		oldTransformedGroups, err = validateAndGetDownstreamGroupsFromSession(session)
		if err != nil {
			return err
		}
	}

	idp, err := findProviderByNameAndType(providerName, customSessionData.ProviderType, providerUID, idpLister)
	if err != nil {
		return err
	}

	cloneOfIDPSpecificSessionData := idp.CloneIDPSpecificSessionDataFromSession(session.Custom)
	if cloneOfIDPSpecificSessionData == nil {
		return errorsx.WithStack(resolvedprovider.ErrMissingUpstreamSessionInternalError())
	}

	oldUntransformedUsername := session.Custom.UpstreamUsername
	oldUntransformedGroups := session.Custom.UpstreamGroups
	oldTransformedUsername := session.Custom.Username

	previousIdentity := &resolvedprovider.Identity{
		UpstreamUsername:       oldUntransformedUsername,
		UpstreamGroups:         oldUntransformedGroups,
		DownstreamSubject:      session.Fosite.Claims.Subject,
		IDPSpecificSessionData: cloneOfIDPSpecificSessionData,
	}

	// Perform the upstream refresh.
	refreshedIdentity, err := idp.UpstreamRefresh(ctx, previousIdentity)
	if err != nil {
		return err
	}

	auditLogger.Audit(plog.AuditEventIdentityRefreshedFromUpstreamIDP, ctx, accessRequest,
		"upstreamUsername", refreshedIdentity.UpstreamUsername,
		"upstreamGroups", refreshedIdentity.UpstreamGroups)

	// If the idp wants to update the session with new information from the refresh, then update it.
	if refreshedIdentity.IDPSpecificSessionData != nil {
		idp.ApplyIDPSpecificSessionDataToSession(session.Custom, refreshedIdentity.IDPSpecificSessionData)
	}

	if refreshedIdentity.UpstreamGroups == nil {
		// If we could not get a new list of groups, then we still need the untransformed groups list to be able to
		// run the transformations again, so fetch the original untransformed groups list from the session.
		// We should also run the transformations on the original groups even when the groups scope was not granted,
		// because a transformation policy may want to reject the authentication based on the group memberships, even
		// though the group memberships will not be shared with the client (in the code below) due to the groups scope
		// not being granted.
		refreshedIdentity.UpstreamGroups = oldUntransformedGroups
	}

	refreshedTransformedUsername, refreshedTransformedGroups, err := applyIdentityTransformationsDuringRefresh(ctx,
		idp.GetTransforms(),
		refreshedIdentity.UpstreamUsername,
		refreshedIdentity.UpstreamGroups,
		providerName,
		providerType,
	)
	if err != nil {
		auditLogger.Audit(plog.AuditEventAuthenticationRejectedByTransforms, ctx, accessRequest,
			"err", err)
		return err
	}

	if oldTransformedUsername != refreshedTransformedUsername {
		return errUpstreamRefreshError().WithHintf(
			"Upstream refresh failed.").
			WithTrace(errors.New("username in upstream refresh does not match previous value")).
			WithDebugf("provider name: %q, provider type: %q", providerName, providerType)
	}

	if !skipGroups {
		warnIfGroupsChanged(ctx, oldTransformedGroups, refreshedTransformedGroups, oldTransformedUsername, accessRequest.GetClient().GetID())
		// Replace the old value for the downstream groups in the user's session with the new value.
		session.Fosite.Claims.Extra[oidcapi.IDTokenClaimGroups] = refreshedTransformedGroups
	}

	auditLogger.Audit(plog.AuditEventSessionRefreshed, ctx, accessRequest,
		"username", oldTransformedUsername, // not allowed to change above so must be the same as old
		"groups", refreshedTransformedGroups,
		"subject", previousIdentity.DownstreamSubject)

	return nil
}

// findProviderByNameAndType finds the IDP by its resource name and IDP type,
// and validates that its resource UID matches the expected UID.
func findProviderByNameAndType(
	providerResourceName string,
	providerType psession.ProviderType,
	mustHaveResourceUID types.UID,
	idpLister federationdomainproviders.FederationDomainIdentityProvidersListerI,
) (resolvedprovider.FederationDomainResolvedIdentityProvider, error) {
	for _, p := range idpLister.GetIdentityProviders() {
		if p.GetSessionProviderType() == providerType && p.GetProvider().GetResourceName() == providerResourceName {
			if p.GetProvider().GetResourceUID() != mustHaveResourceUID {
				return nil, errorsx.WithStack(errUpstreamRefreshError().WithHint(
					"Provider from upstream session data has changed its resource UID since authentication."))
			}
			return p, nil
		}
	}
	return nil, errorsx.WithStack(errUpstreamRefreshError().
		WithHint("Provider from upstream session data was not found.").
		WithDebugf("provider name: %q, provider type: %q", providerResourceName, providerType))
}

func validateSessionHasUsername(session *psession.PinnipedSession) error {
	downstreamUsername := session.Custom.Username
	if len(downstreamUsername) == 0 {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}
	return nil
}

// applyIdentityTransformationsDuringRefresh is similar to downstreamsession.applyIdentityTransformations
// but with slightly different error messaging.
func applyIdentityTransformationsDuringRefresh(
	ctx context.Context,
	transforms *idtransform.TransformationPipeline,
	upstreamUsername string,
	upstreamGroups []string,
	providerName string,
	providerType psession.ProviderType,
) (string, []string, error) {
	transformationResult, err := transforms.Evaluate(ctx, upstreamUsername, upstreamGroups)
	if err != nil {
		return "", nil, errUpstreamRefreshError().WithHintf(
			"Upstream refresh error while applying configured identity transformations.").
			WithTrace(err).
			WithDebugf("provider name: %q, provider type: %q", providerName, providerType)
	}

	if !transformationResult.AuthenticationAllowed {
		return "", nil, errUpstreamRefreshError().WithHintf(
			"Upstream refresh rejected by configured identity policy: %s.", transformationResult.RejectedAuthenticationMessage).
			WithDebugf("provider name: %q, provider type: %q", providerName, providerType)
	}

	return transformationResult.Username, transformationResult.Groups, nil
}

func validateAndGetDownstreamGroupsFromSession(session *psession.PinnipedSession) ([]string, error) {
	extra := session.Fosite.Claims.Extra
	if extra == nil {
		return nil, errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}
	downstreamGroupsInterface := extra[oidcapi.IDTokenClaimGroups]
	if downstreamGroupsInterface == nil {
		return nil, errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}
	downstreamGroupsInterfaceList, ok := downstreamGroupsInterface.([]any)
	if !ok {
		return nil, errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}

	downstreamGroups := make([]string, 0, len(downstreamGroupsInterfaceList))
	for _, downstreamGroupInterface := range downstreamGroupsInterfaceList {
		downstreamGroup, ok := downstreamGroupInterface.(string)
		if !ok || len(downstreamGroup) == 0 {
			return nil, errorsx.WithStack(errMissingUpstreamSessionInternalError())
		}
		downstreamGroups = append(downstreamGroups, downstreamGroup)
	}
	return downstreamGroups, nil
}

func warnIfGroupsChanged(ctx context.Context, oldGroups, newGroups []string, username string, clientID string) {
	if clientID != oidcapi.ClientIDPinnipedCLI {
		// Only send these warnings to the CLI client. They are intended for kubectl to print to the screen.
		// A webapp using a dynamic client wouldn't know to look for these special warning headers, and
		// if the dynamic client lacked the username scope, then these warning messages would be leaking
		// the user's username to the client within the text of the warning.
		return
	}

	added, removed := diffSortedGroups(oldGroups, newGroups)

	if len(added) > 0 {
		warning.AddWarning(ctx, "", fmt.Sprintf("User %q has been added to the following groups: %q", username, added))
	}
	if len(removed) > 0 {
		warning.AddWarning(ctx, "", fmt.Sprintf("User %q has been removed from the following groups: %q", username, removed))
	}
}

func diffSortedGroups(oldGroups, newGroups []string) ([]string, []string) {
	oldGroupsAsSet := sets.NewString(oldGroups...)
	newGroupsAsSet := sets.NewString(newGroups...)
	added := newGroupsAsSet.Difference(oldGroupsAsSet)   // groups in newGroups that are not in oldGroups i.e. added
	removed := oldGroupsAsSet.Difference(newGroupsAsSet) // groups in oldGroups that are not in newGroups i.e. removed
	return added.List(), removed.List()
}
