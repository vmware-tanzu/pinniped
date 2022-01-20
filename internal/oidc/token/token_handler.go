// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package token provides a handler for the OIDC token endpoint.
package token

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"

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
	// Each retry of a failed upstream refresh will multiply the previous sleep duration by this factor.
	// This only exists as a parameter so that unit tests can override it to avoid running slowly.
	upstreamRefreshRetryOnErrorFactor := 4.0

	return newHandler(idpLister, oauthHelper, upstreamRefreshRetryOnErrorFactor)
}

func newHandler(
	idpLister oidc.UpstreamIdentityProvidersLister,
	oauthHelper fosite.OAuth2Provider,
	upstreamRefreshRetryOnErrorFactor float64,
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
			err = upstreamRefresh(r.Context(), accessRequest, idpLister, upstreamRefreshRetryOnErrorFactor)
			if err != nil {
				plog.Info("upstream refresh error", oidc.FositeErrorForLog(err)...)
				oauthHelper.WriteAccessError(w, accessRequest, err)
				return nil
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

func upstreamRefresh(
	ctx context.Context,
	accessRequest fosite.AccessRequester,
	providerCache oidc.UpstreamIdentityProvidersLister,
	retryOnErrorFactor float64,
) error {
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
		return upstreamOIDCRefresh(ctx, session, providerCache, retryOnErrorFactor)
	case psession.ProviderTypeLDAP:
		return upstreamLDAPRefresh(ctx, providerCache, session)
	case psession.ProviderTypeActiveDirectory:
		return upstreamLDAPRefresh(ctx, providerCache, session)
	default:
		return errorsx.WithStack(errMissingUpstreamSessionInternalError)
	}
}

func upstreamOIDCRefresh(
	ctx context.Context,
	session *psession.PinnipedSession,
	providerCache oidc.UpstreamIdentityProvidersLister,
	retryOnErrorFactor float64,
) error {
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
		tokens, err = performUpstreamOIDCRefreshWithRetriesOnError(ctx, p, s, retryOnErrorFactor)
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

func performUpstreamOIDCRefreshWithRetriesOnError(
	ctx context.Context,
	p provider.UpstreamOIDCIdentityProviderI,
	s *psession.CustomSessionData,
	retryOnErrorFactor float64,
) (*oauth2.Token, error) {
	var tokens *oauth2.Token

	// For the default retryOnErrorFactor of 4.0 this backoff means...
	// Try once, then retry upon error after sleeps of 50ms, 0.2s, 0.8s, 3.2s, and 12.8s.
	// Give up after a total of 6 tries over ~17s if they all resulted in errors.
	backoff := wait.Backoff{Steps: 6, Duration: 50 * time.Millisecond, Factor: retryOnErrorFactor}

	isRetryableError := func(err error) bool {
		plog.DebugErr("upstream refresh request failed in retry loop", err,
			"providerName", s.ProviderName, "providerType", s.ProviderType, "providerUID", s.ProviderUID)
		if ctx.Err() != nil {
			return false // Stop retrying if the context was closed (cancelled or timed out).
		}
		retrieveError := &oauth2.RetrieveError{}
		if errors.As(err, &retrieveError) {
			return retrieveError.Response.StatusCode >= 500 // 5xx statuses are inconclusive and might be worth retrying.
		}
		return true // Retry any other errors, e.g. connection errors.
	}

	performRefreshOnce := func() error {
		var err error
		// Timeout to more likely have a chance to retry before a client gets tired of waiting and disconnects.
		timeoutCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		tokens, err = p.PerformRefresh(timeoutCtx, s.OIDC.UpstreamRefreshToken)
		return err
	}

	err := retry.OnError(backoff, isRetryableError, performRefreshOnce)

	// If all retries failed, then err will hold the error of the final failed retry.
	return tokens, err
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
	err = p.PerformRefresh(ctx, provider.StoredRefreshAttributes{
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
