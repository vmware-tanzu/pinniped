// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package token provides a handler for the OIDC token endpoint.
package token

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/ory/fosite"
	errorsx "github.com/pkg/errors"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/warning"
	"k8s.io/utils/strings/slices"

	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/downstreamsession"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/oidc/provider/upstreamprovider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
)

func NewHandler(
	idpLister provider.FederationDomainIdentityProvidersListerI,
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

func upstreamRefresh(ctx context.Context, accessRequest fosite.AccessRequester, idpLister provider.FederationDomainIdentityProvidersListerI) error {
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

	grantedScopes := accessRequest.GetGrantedScopes()
	clientID := accessRequest.GetClient().GetID()

	switch customSessionData.ProviderType {
	case psession.ProviderTypeOIDC:
		return upstreamOIDCRefresh(ctx, session, idpLister, grantedScopes, clientID)
	case psession.ProviderTypeLDAP:
		return upstreamLDAPRefresh(ctx, idpLister, session, grantedScopes, clientID)
	case psession.ProviderTypeActiveDirectory:
		return upstreamLDAPRefresh(ctx, idpLister, session, grantedScopes, clientID)
	default:
		return errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}
}

func upstreamOIDCRefresh(
	ctx context.Context,
	session *psession.PinnipedSession,
	idpLister provider.FederationDomainIdentityProvidersListerI,
	grantedScopes []string,
	clientID string,
) error {
	s := session.Custom
	if s.OIDC == nil {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}

	accessTokenStored := s.OIDC.UpstreamAccessToken != ""
	refreshTokenStored := s.OIDC.UpstreamRefreshToken != ""

	exactlyOneTokenStored := (accessTokenStored || refreshTokenStored) && !(accessTokenStored && refreshTokenStored)
	if !exactlyOneTokenStored {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}

	p, err := findOIDCProviderByNameAndValidateUID(s, idpLister)
	if err != nil {
		return err
	}

	plog.Debug("attempting upstream refresh request",
		"providerName", s.ProviderName, "providerType", s.ProviderType, "providerUID", s.ProviderUID)

	var tokens *oauth2.Token
	if refreshTokenStored {
		tokens, err = p.Provider.PerformRefresh(ctx, s.OIDC.UpstreamRefreshToken)
		if err != nil {
			return errUpstreamRefreshError().WithHint(
				"Upstream refresh failed.",
			).WithTrace(err).WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType)
		}
	} else {
		tokens = &oauth2.Token{AccessToken: s.OIDC.UpstreamAccessToken}
	}

	// Upstream refresh may or may not return a new ID token. From the spec:
	// "the response body is the Token Response of Section 3.1.3.3 except that it might not contain an id_token."
	// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
	_, hasIDTok := tokens.Extra("id_token").(string)

	// We may or may not have an ID token, and we may or may not have a userinfo endpoint to call for more claims.
	// Use what we can (one, both, or neither) and return the union of their claims. If we stored an access token,
	// then require that the userinfo endpoint exists and returns a successful response, or else we would have no
	// way to check that the user's session was not revoked on the server.
	// The spec is not 100% clear about whether an ID token from the refresh flow should include a nonce, and at
	// least some providers do not include one, so we skip the nonce validation here (but not other validations).
	validatedTokens, err := p.Provider.ValidateTokenAndMergeWithUserInfo(ctx, tokens, "", hasIDTok, accessTokenStored)
	if err != nil {
		return errUpstreamRefreshError().WithHintf(
			"Upstream refresh returned an invalid ID token or UserInfo response.").WithTrace(err).
			WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType)
	}
	mergedClaims := validatedTokens.IDToken.Claims

	oldTransformedUsername, err := getDownstreamUsernameFromPinnipedSession(session)
	if err != nil {
		return err
	}
	oldTransformedGroups, err := getDownstreamGroupsFromPinnipedSession(session)
	if err != nil {
		return err
	}

	// To the extent possible, check that the user's basic identity hasn't changed.
	err = validateSubjectAndIssuerUnchangedSinceInitialLogin(mergedClaims, session)
	if err != nil {
		return err
	}

	var refreshedUntransformedGroups []string
	groupsScope := slices.Contains(grantedScopes, oidcapi.ScopeGroups)
	if groupsScope { //nolint:nestif
		// If possible, update the user's group memberships. The configured groups claim name (if there is one) may or
		// may not be included in the newly fetched and merged claims. It could be missing due to a misconfiguration of the
		// claim name. It could also be missing because the claim was originally found in the ID token during login, but
		// now we might not have a refreshed ID token.
		// If the claim is found, then use it to update the user's group membership in the session.
		// If the claim is not found, then we have no new information about groups, so skip updating the group membership
		// and let any old groups memberships in the session remain.
		refreshedUntransformedGroups, err = downstreamsession.GetGroupsFromUpstreamIDToken(p.Provider, mergedClaims)
		if err != nil {
			return errUpstreamRefreshError().WithHintf(
				"Upstream refresh error while extracting groups claim.").WithTrace(err).
				WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType)
		}
	}

	// It's possible that a username wasn't returned by the upstream provider during refresh,
	// but if it is, verify that the transformed version of it hasn't changed.
	refreshedUntransformedUsername, hasRefreshedUntransformedUsername := getString(mergedClaims, p.Provider.GetUsernameClaim())

	if !hasRefreshedUntransformedUsername {
		// If we could not get a new username, then we still need the untransformed username to be able to
		// run the transformations again, so fetch the original untransformed username from the session.
		refreshedUntransformedUsername = s.UpstreamUsername
	}
	if refreshedUntransformedGroups == nil {
		// If we could not get a new list of groups, then we still need the untransformed groups list to be able to
		// run the transformations again, so fetch the original untransformed groups list from the session.
		refreshedUntransformedGroups = s.UpstreamGroups
	}

	transformationResult, err := transformRefreshedIdentity(ctx,
		p.Transforms,
		oldTransformedUsername,
		refreshedUntransformedUsername,
		refreshedUntransformedGroups,
		s.ProviderName,
		s.ProviderType,
	)
	if err != nil {
		return err
	}

	warnIfGroupsChanged(ctx, oldTransformedGroups, transformationResult.Groups, transformationResult.Username, clientID)
	session.Fosite.Claims.Extra[oidcapi.IDTokenClaimGroups] = refreshedUntransformedGroups

	// Upstream refresh may or may not return a new refresh token. If we got a new refresh token, then update it in
	// the user's session. If we did not get a new refresh token, then keep the old one in the session by avoiding
	// overwriting the old one.
	if tokens.RefreshToken != "" {
		plog.Debug("upstream refresh request returned a new refresh token",
			"providerName", s.ProviderName, "providerType", s.ProviderType, "providerUID", s.ProviderUID)
		s.OIDC.UpstreamRefreshToken = tokens.RefreshToken
	}

	return nil
}

// print out the diff between two lists of sorted groups.
func diffSortedGroups(oldGroups, newGroups []string) ([]string, []string) {
	oldGroupsAsSet := sets.NewString(oldGroups...)
	newGroupsAsSet := sets.NewString(newGroups...)
	added := newGroupsAsSet.Difference(oldGroupsAsSet)   // groups in newGroups that are not in oldGroups i.e. added
	removed := oldGroupsAsSet.Difference(newGroupsAsSet) // groups in oldGroups that are not in newGroups i.e. removed
	return added.List(), removed.List()
}

func validateSubjectAndIssuerUnchangedSinceInitialLogin(mergedClaims map[string]interface{}, session *psession.PinnipedSession) error {
	s := session.Custom

	// If we have any claims at all, we better have a subject, and it better match the previous value.
	// but it's possible that we don't because both returning a new id token on refresh and having a userinfo
	// endpoint are optional.
	if len(mergedClaims) == 0 {
		return nil
	}

	newSub, hasSub := getString(mergedClaims, oidcapi.IDTokenClaimSubject)
	if !hasSub {
		return errUpstreamRefreshError().WithHintf(
			"Upstream refresh failed.").WithTrace(errors.New("subject in upstream refresh not found")).
			WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType)
	}
	if s.OIDC.UpstreamSubject != newSub {
		return errUpstreamRefreshError().WithHintf(
			"Upstream refresh failed.").WithTrace(errors.New("subject in upstream refresh does not match previous value")).
			WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType)
	}

	newIssuer, hasIssuer := getString(mergedClaims, oidcapi.IDTokenClaimIssuer)
	// It's possible that an issuer wasn't returned by the upstream provider during refresh,
	// but if it is, verify that it hasn't changed.
	if hasIssuer && s.OIDC.UpstreamIssuer != newIssuer {
		return errUpstreamRefreshError().WithHintf(
			"Upstream refresh failed.").WithTrace(errors.New("issuer in upstream refresh does not match previous value")).
			WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType)
	}

	return nil
}

func getString(m map[string]interface{}, key string) (string, bool) {
	val, ok := m[key].(string)
	return val, ok
}

func findOIDCProviderByNameAndValidateUID(
	s *psession.CustomSessionData,
	idpLister provider.FederationDomainIdentityProvidersListerI,
) (*provider.FederationDomainResolvedOIDCIdentityProvider, error) {
	for _, p := range idpLister.GetOIDCIdentityProviders() {
		if p.Provider.GetName() == s.ProviderName {
			if p.Provider.GetResourceUID() != s.ProviderUID {
				return nil, errorsx.WithStack(errUpstreamRefreshError().WithHint(
					"Provider from upstream session data has changed its resource UID since authentication."))
			}
			return p, nil
		}
	}
	return nil, errorsx.WithStack(errUpstreamRefreshError().
		WithHint("Provider from upstream session data was not found.").
		WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType))
}

func upstreamLDAPRefresh(
	ctx context.Context,
	idpLister provider.FederationDomainIdentityProvidersListerI,
	session *psession.PinnipedSession,
	grantedScopes []string,
	clientID string,
) error {
	oldTransformedUsername, err := getDownstreamUsernameFromPinnipedSession(session)
	if err != nil {
		return err
	}
	subject := session.Fosite.Claims.Subject
	var oldTransformedGroups []string
	if slices.Contains(grantedScopes, oidcapi.ScopeGroups) {
		oldTransformedGroups, err = getDownstreamGroupsFromPinnipedSession(session)
		if err != nil {
			return err
		}
	}
	s := session.Custom

	validLDAP := s.ProviderType == psession.ProviderTypeLDAP && s.LDAP != nil && s.LDAP.UserDN != ""
	validAD := s.ProviderType == psession.ProviderTypeActiveDirectory && s.ActiveDirectory != nil && s.ActiveDirectory.UserDN != ""
	if !(validLDAP || validAD) {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}

	var additionalAttributes map[string]string
	if s.ProviderType == psession.ProviderTypeLDAP {
		additionalAttributes = s.LDAP.ExtraRefreshAttributes
	} else {
		additionalAttributes = s.ActiveDirectory.ExtraRefreshAttributes
	}

	p, dn, err := findLDAPProviderByNameAndValidateUID(s, idpLister)
	if err != nil {
		return err
	}
	if session.IDTokenClaims().AuthTime.IsZero() {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}

	refreshedUntransformedGroups, err := p.Provider.PerformRefresh(ctx, upstreamprovider.RefreshAttributes{
		Username:             s.UpstreamUsername,
		Subject:              subject,
		DN:                   dn,
		Groups:               s.UpstreamGroups,
		AdditionalAttributes: additionalAttributes,
		GrantedScopes:        grantedScopes,
	})
	if err != nil {
		return errUpstreamRefreshError().WithHint(
			"Upstream refresh failed.").WithTrace(err).
			WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType)
	}

	transformationResult, err := transformRefreshedIdentity(ctx,
		p.Transforms,
		oldTransformedUsername,
		s.UpstreamUsername,
		refreshedUntransformedGroups,
		s.ProviderName,
		s.ProviderType,
	)
	if err != nil {
		return err
	}

	groupsScope := slices.Contains(grantedScopes, oidcapi.ScopeGroups)
	if groupsScope {
		warnIfGroupsChanged(ctx, oldTransformedGroups, transformationResult.Groups, transformationResult.Username, clientID)
		// Replace the old value with the new value.
		session.Fosite.Claims.Extra[oidcapi.IDTokenClaimGroups] = transformationResult.Groups
	}

	return nil
}

func transformRefreshedIdentity(
	ctx context.Context,
	transforms *idtransform.TransformationPipeline,
	oldTransformedUsername string,
	upstreamUsername string,
	upstreamGroups []string,
	providerName string,
	providerType psession.ProviderType,
) (*idtransform.TransformationResult, error) {
	transformationResult, err := transforms.Evaluate(ctx, upstreamUsername, upstreamGroups)
	if err != nil {
		return nil, errUpstreamRefreshError().WithHintf(
			"Upstream refresh error while applying configured identity transformations.").
			WithTrace(err).
			WithDebugf("provider name: %q, provider type: %q", providerName, providerType)
	}

	if !transformationResult.AuthenticationAllowed {
		return nil, errUpstreamRefreshError().WithHintf(
			"Upstream refresh rejected by configured identity policy: %s.", transformationResult.RejectedAuthenticationMessage).
			WithDebugf("provider name: %q, provider type: %q", providerName, providerType)
	}

	if oldTransformedUsername != transformationResult.Username {
		return nil, errUpstreamRefreshError().WithHintf(
			"Upstream refresh failed.").
			WithTrace(errors.New("username in upstream refresh does not match previous value")).
			WithDebugf("provider name: %q, provider type: %q", providerName, providerType)
	}

	return transformationResult, nil
}

func findLDAPProviderByNameAndValidateUID(
	s *psession.CustomSessionData,
	idpLister provider.FederationDomainIdentityProvidersListerI,
) (*provider.FederationDomainResolvedLDAPIdentityProvider, string, error) {
	var providers []*provider.FederationDomainResolvedLDAPIdentityProvider
	var dn string
	if s.ProviderType == psession.ProviderTypeLDAP {
		providers = idpLister.GetLDAPIdentityProviders()
		dn = s.LDAP.UserDN
	} else if s.ProviderType == psession.ProviderTypeActiveDirectory {
		providers = idpLister.GetActiveDirectoryIdentityProviders()
		dn = s.ActiveDirectory.UserDN
	}

	for _, p := range providers {
		if p.Provider.GetName() == s.ProviderName {
			if p.Provider.GetResourceUID() != s.ProviderUID {
				return nil, "", errorsx.WithStack(errUpstreamRefreshError().WithHint(
					"Provider from upstream session data has changed its resource UID since authentication.").
					WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType))
			}
			return p, dn, nil
		}
	}

	return nil, "", errorsx.WithStack(errUpstreamRefreshError().
		WithHint("Provider from upstream session data was not found.").
		WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType))
}

func getDownstreamUsernameFromPinnipedSession(session *psession.PinnipedSession) (string, error) {
	downstreamUsername := session.Custom.Username
	if len(downstreamUsername) == 0 {
		return "", errorsx.WithStack(errMissingUpstreamSessionInternalError())
	}
	return downstreamUsername, nil
}

func getDownstreamGroupsFromPinnipedSession(session *psession.PinnipedSession) ([]string, error) {
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
