// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package token provides a handler for the OIDC token endpoint.
package token

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ory/fosite"
	errorsx "github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/warning"
	"k8s.io/utils/strings/slices"

	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/federationdomain/federationdomainproviders"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
)

func NewHandler(
	idpLister federationdomainproviders.FederationDomainIdentityProvidersListerI,
	oauthHelper fosite.OAuth2Provider,
) http.Handler {
	return httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		session := psession.NewPinnipedSession()
		accessRequest, err := oauthHelper.NewAccessRequest(r.Context(), r, session)
		if err != nil {
			plog.Info("token request error", oidc.FositeErrorForLog(err)...)
			oauthHelper.WriteAccessError(r.Context(), w, accessRequest, err)
			return nil
		}

		// Check if we are performing a refresh grant.
		if accessRequest.GetGrantTypes().ExactOne(oidcapi.GrantTypeRefreshToken) {
			// The above call to NewAccessRequest has loaded the session from storage into the accessRequest variable.
			// The session, requested scopes, and requested audience from the original authorize request was retrieved
			// from the Kube storage layer and added to the accessRequest. Additionally, the audience and scopes may
			// have already been granted on the accessRequest.
			err = upstreamRefresh(r.Context(), accessRequest, idpLister)
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

		accessResponse, err := oauthHelper.NewAccessResponse(r.Context(), accessRequest)
		if err != nil {
			plog.Info("token response error", oidc.FositeErrorForLog(err)...)
			oauthHelper.WriteAccessError(r.Context(), w, accessRequest, err)
			return nil
		}

		oauthHelper.WriteAccessResponse(r.Context(), w, accessRequest, accessResponse)

		return nil
	})
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
) error {
	session := accessRequest.GetSession().(*psession.PinnipedSession)

	customSessionData := session.Custom
	if customSessionData == nil {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}
	providerName := customSessionData.ProviderName
	providerUID := customSessionData.ProviderUID
	if providerUID == "" || providerName == "" {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}

	skipGroups := !slices.Contains(accessRequest.GetGrantedScopes(), oidcapi.ScopeGroups)

	clientID := accessRequest.GetClient().GetID()

	err := validateSessionHasUsername(session)
	if err != nil {
		return err
	}

	idp, err := findProviderByNameAndType(providerName, customSessionData.ProviderType, providerUID, idpLister)
	if err != nil {
		return err
	}

	oldTransformedUsername := session.Custom.Username
	var oldTransformedGroups []string
	if !skipGroups {
		oldTransformedGroups, err = getDownstreamGroupsFromSession(session)
		if err != nil {
			return err
		}
	}

	refreshedGroups, err := idp.UpstreamRefresh(ctx, session, skipGroups)
	if err != nil {
		return err
	}

	if !skipGroups {
		warnIfGroupsChanged(ctx, oldTransformedGroups, refreshedGroups, oldTransformedUsername, clientID)
		// Replace the old value for the downstream groups in the user's session with the new value.
		session.Fosite.Claims.Extra[oidcapi.IDTokenClaimGroups] = refreshedGroups
	}

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
		if p.GetSessionProviderType() == providerType && p.GetProvider().GetName() == providerResourceName {
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

func getDownstreamGroupsFromSession(session *psession.PinnipedSession) ([]string, error) {
	extra := session.Fosite.Claims.Extra
	if extra == nil {
		return nil, errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}
	downstreamGroupsInterface := extra[oidcapi.IDTokenClaimGroups]
	if downstreamGroupsInterface == nil {
		return nil, errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}
	downstreamGroupsInterfaceList, ok := downstreamGroupsInterface.([]interface{})
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
