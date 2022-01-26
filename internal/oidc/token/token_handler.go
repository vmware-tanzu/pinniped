// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package token provides a handler for the OIDC token endpoint.
package token

import (
	"context"
	"errors"
	"net/http"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/warning"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/downstreamsession"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
)

var (
	errMissingUpstreamSessionInternalError = &fosite.RFC6749Error{
		ErrorField:       "error",
		DescriptionField: "There was an internal server error.",
		HintField:        "Required upstream data not found in session.",
		CodeField:        http.StatusInternalServerError,
	}

	errUpstreamRefreshError = &fosite.RFC6749Error{
		ErrorField:       "error",
		DescriptionField: "Error during upstream refresh.",
		CodeField:        http.StatusUnauthorized,
	}
)

func NewHandler(
	idpLister oidc.UpstreamIdentityProvidersLister,
	oauthHelper fosite.OAuth2Provider,
) http.Handler {
	return httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		session := psession.NewPinnipedSession()
		accessRequest, err := oauthHelper.NewAccessRequest(r.Context(), r, session)
		if err != nil {
			plog.Info("token request error", oidc.FositeErrorForLog(err)...)
			oauthHelper.WriteAccessError(w, accessRequest, err)
			return nil
		}

		// Check if we are performing a refresh grant.
		if accessRequest.GetGrantTypes().ExactOne("refresh_token") {
			// The above call to NewAccessRequest has loaded the session from storage into the accessRequest variable.
			// The session, requested scopes, and requested audience from the original authorize request was retrieved
			// from the Kube storage layer and added to the accessRequest. Additionally, the audience and scopes may
			// have already been granted on the accessRequest.
			err = upstreamRefresh(r.Context(), accessRequest, idpLister)
			if err != nil {
				plog.Info("upstream refresh error", oidc.FositeErrorForLog(err)...)
				oauthHelper.WriteAccessError(w, accessRequest, err)
				return nil
			}
		}

		// When we are in the authorization code flow, check if we have any warnings that previous handlers want us
		// to send to the client to be printed on the CLI.
		if accessRequest.GetGrantTypes().ExactOne("authorization_code") {
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
			oauthHelper.WriteAccessError(w, accessRequest, err)
			return nil
		}

		oauthHelper.WriteAccessResponse(w, accessRequest, accessResponse)

		return nil
	})
}

func upstreamRefresh(ctx context.Context, accessRequest fosite.AccessRequester, providerCache oidc.UpstreamIdentityProvidersLister) error {
	session := accessRequest.GetSession().(*psession.PinnipedSession)

	customSessionData := session.Custom
	if customSessionData == nil {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError)
	}
	providerName := customSessionData.ProviderName
	providerUID := customSessionData.ProviderUID
	if providerUID == "" || providerName == "" {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError)
	}

	switch customSessionData.ProviderType {
	case psession.ProviderTypeOIDC:
		return upstreamOIDCRefresh(ctx, session, providerCache)
	case psession.ProviderTypeLDAP:
		return upstreamLDAPRefresh(ctx, providerCache, session)
	case psession.ProviderTypeActiveDirectory:
		return upstreamLDAPRefresh(ctx, providerCache, session)
	default:
		return errorsx.WithStack(errMissingUpstreamSessionInternalError)
	}
}

func upstreamOIDCRefresh(ctx context.Context, session *psession.PinnipedSession, providerCache oidc.UpstreamIdentityProvidersLister) error {
	s := session.Custom
	if s.OIDC == nil {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError)
	}

	accessTokenStored := s.OIDC.UpstreamAccessToken != ""
	refreshTokenStored := s.OIDC.UpstreamRefreshToken != ""

	exactlyOneTokenStored := (accessTokenStored || refreshTokenStored) && !(accessTokenStored && refreshTokenStored)
	if !exactlyOneTokenStored {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError)
	}

	p, err := findOIDCProviderByNameAndValidateUID(s, providerCache)
	if err != nil {
		return err
	}

	plog.Debug("attempting upstream refresh request",
		"providerName", s.ProviderName, "providerType", s.ProviderType, "providerUID", s.ProviderUID)

	var tokens *oauth2.Token
	if refreshTokenStored {
		tokens, err = p.PerformRefresh(ctx, s.OIDC.UpstreamRefreshToken)
		if err != nil {
			return errorsx.WithStack(errUpstreamRefreshError.WithHint(
				"Upstream refresh failed.",
			).WithWrap(err).WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType))
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
	validatedTokens, err := p.ValidateTokenAndMergeWithUserInfo(ctx, tokens, "", hasIDTok, accessTokenStored)
	if err != nil {
		return errorsx.WithStack(errUpstreamRefreshError.WithHintf(
			"Upstream refresh returned an invalid ID token or UserInfo response.").WithWrap(err).
			WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType))
	}
	mergedClaims := validatedTokens.IDToken.Claims

	// To the extent possible, check that the user's basic identity hasn't changed.
	err = validateIdentityUnchangedSinceInitialLogin(mergedClaims, session, p.GetUsernameClaim())
	if err != nil {
		return err
	}

	// If possible, update the user's group memberships. The configured groups claim name (if there is one) may or
	// may not be included in the newly fetched and merged claims. It could be missing due to a misconfiguration of the
	// claim name. It could also be missing because the claim was originally found in the ID token during login, but
	// now we might not have a refreshed ID token.
	// If the claim is found, then use it to update the user's group membership in the session.
	// If the claim is not found, then we have no new information about groups, so skip updating the group membership
	// and let any old groups memberships in the session remain.
	refreshedGroups, err := downstreamsession.GetGroupsFromUpstreamIDToken(p, mergedClaims)
	if err != nil {
		return errorsx.WithStack(errUpstreamRefreshError.WithHintf(
			"Upstream refresh error while extracting groups claim.").WithWrap(err).
			WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType))
	}
	if refreshedGroups != nil {
		session.Fosite.Claims.Extra[oidc.DownstreamGroupsClaim] = refreshedGroups
	}

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

func validateIdentityUnchangedSinceInitialLogin(mergedClaims map[string]interface{}, session *psession.PinnipedSession, usernameClaimName string) error {
	s := session.Custom

	// If we have any claims at all, we better have a subject, and it better match the previous value.
	// but it's possible that we don't because both returning a new id token on refresh and having a userinfo
	// endpoint are optional.
	if len(mergedClaims) == 0 {
		return nil
	}

	newSub, hasSub := getString(mergedClaims, oidc.IDTokenSubjectClaim)
	if !hasSub {
		return errorsx.WithStack(errUpstreamRefreshError.WithHintf(
			"Upstream refresh failed.").WithWrap(errors.New("subject in upstream refresh not found")).
			WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType))
	}
	if s.OIDC.UpstreamSubject != newSub {
		return errorsx.WithStack(errUpstreamRefreshError.WithHintf(
			"Upstream refresh failed.").WithWrap(errors.New("subject in upstream refresh does not match previous value")).
			WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType))
	}

	newUsername, hasUsername := getString(mergedClaims, usernameClaimName)
	oldUsername := session.Fosite.Claims.Extra[oidc.DownstreamUsernameClaim]
	// It's possible that a username wasn't returned by the upstream provider during refresh,
	// but if it is, verify that it hasn't changed.
	if hasUsername && oldUsername != newUsername {
		return errorsx.WithStack(errUpstreamRefreshError.WithHintf(
			"Upstream refresh failed.").WithWrap(errors.New("username in upstream refresh does not match previous value")).
			WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType))
	}

	newIssuer, hasIssuer := getString(mergedClaims, oidc.IDTokenIssuerClaim)
	// It's possible that an issuer wasn't returned by the upstream provider during refresh,
	// but if it is, verify that it hasn't changed.
	if hasIssuer && s.OIDC.UpstreamIssuer != newIssuer {
		return errorsx.WithStack(errUpstreamRefreshError.WithHintf(
			"Upstream refresh failed.").WithWrap(errors.New("issuer in upstream refresh does not match previous value")).
			WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType))
	}

	return nil
}

func getString(m map[string]interface{}, key string) (string, bool) {
	val, ok := m[key].(string)
	return val, ok
}

func findOIDCProviderByNameAndValidateUID(
	s *psession.CustomSessionData,
	providerCache oidc.UpstreamIdentityProvidersLister,
) (provider.UpstreamOIDCIdentityProviderI, error) {
	for _, p := range providerCache.GetOIDCIdentityProviders() {
		if p.GetName() == s.ProviderName {
			if p.GetResourceUID() != s.ProviderUID {
				return nil, errorsx.WithStack(errUpstreamRefreshError.WithHint(
					"Provider from upstream session data has changed its resource UID since authentication."))
			}
			return p, nil
		}
	}
	return nil, errorsx.WithStack(errUpstreamRefreshError.
		WithHint("Provider from upstream session data was not found.").
		WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType))
}

func upstreamLDAPRefresh(ctx context.Context, providerCache oidc.UpstreamIdentityProvidersLister, session *psession.PinnipedSession) error {
	username, err := getDownstreamUsernameFromPinnipedSession(session)
	if err != nil {
		return err
	}
	subject := session.Fosite.Claims.Subject

	s := session.Custom

	// if you have neither a valid ldap session config nor a valid active directory session config
	validLDAP := s.ProviderType == psession.ProviderTypeLDAP && s.LDAP != nil && s.LDAP.UserDN != ""
	validAD := s.ProviderType == psession.ProviderTypeActiveDirectory && s.ActiveDirectory != nil && s.ActiveDirectory.UserDN != ""
	if !(validLDAP || validAD) {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError)
	}

	var additionalAttributes map[string]string
	if s.ProviderType == psession.ProviderTypeLDAP {
		additionalAttributes = s.LDAP.ExtraRefreshAttributes
	} else {
		additionalAttributes = s.ActiveDirectory.ExtraRefreshAttributes
	}

	// get ldap/ad provider out of cache
	p, dn, err := findLDAPProviderByNameAndValidateUID(s, providerCache)
	if err != nil {
		return err
	}
	if session.IDTokenClaims().AuthTime.IsZero() {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError)
	}
	// run PerformRefresh
	groups, err := p.PerformRefresh(ctx, provider.StoredRefreshAttributes{
		Username:             username,
		Subject:              subject,
		DN:                   dn,
		AdditionalAttributes: additionalAttributes,
	})
	if err != nil {
		return errorsx.WithStack(errUpstreamRefreshError.WithHint(
			"Upstream refresh failed.").WithWrap(err).
			WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType))
	}
	// If we got groups back, then replace the old value with the new value.
	if groups != nil {
		session.Fosite.Claims.Extra[oidc.DownstreamGroupsClaim] = groups
	}

	return nil
}

func findLDAPProviderByNameAndValidateUID(
	s *psession.CustomSessionData,
	providerCache oidc.UpstreamIdentityProvidersLister,
) (provider.UpstreamLDAPIdentityProviderI, string, error) {
	var providers []provider.UpstreamLDAPIdentityProviderI
	var dn string
	if s.ProviderType == psession.ProviderTypeLDAP {
		providers = providerCache.GetLDAPIdentityProviders()
		dn = s.LDAP.UserDN
	} else if s.ProviderType == psession.ProviderTypeActiveDirectory {
		providers = providerCache.GetActiveDirectoryIdentityProviders()
		dn = s.ActiveDirectory.UserDN
	}

	for _, p := range providers {
		if p.GetName() == s.ProviderName {
			if p.GetResourceUID() != s.ProviderUID {
				return nil, "", errorsx.WithStack(errUpstreamRefreshError.WithHint(
					"Provider from upstream session data has changed its resource UID since authentication.").
					WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType))
			}
			return p, dn, nil
		}
	}

	return nil, "", errorsx.WithStack(errUpstreamRefreshError.
		WithHint("Provider from upstream session data was not found.").
		WithDebugf("provider name: %q, provider type: %q", s.ProviderName, s.ProviderType))
}

func getDownstreamUsernameFromPinnipedSession(session *psession.PinnipedSession) (string, error) {
	extra := session.Fosite.Claims.Extra
	if extra == nil {
		return "", errorsx.WithStack(errMissingUpstreamSessionInternalError)
	}
	downstreamUsernameInterface := extra["username"]
	if downstreamUsernameInterface == nil {
		return "", errorsx.WithStack(errMissingUpstreamSessionInternalError)
	}
	downstreamUsername, ok := downstreamUsernameInterface.(string)
	if !ok || len(downstreamUsername) == 0 {
		return "", errorsx.WithStack(errMissingUpstreamSessionInternalError)
	}
	return downstreamUsername, nil
}
