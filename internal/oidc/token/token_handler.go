// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package token provides a handler for the OIDC token endpoint.
package token

import (
	"context"
	"net/http"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/oidc"
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
	downstreamUsername, err := getDownstreamUsernameFromPinnipedSession(session)
	if err != nil {
		return err
	}
	downstreamSubject := session.Fosite.Claims.Subject

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
		return upstreamOIDCRefresh(ctx, customSessionData, providerCache)
	case psession.ProviderTypeLDAP:
		return upstreamLDAPRefresh(ctx, customSessionData, providerCache, downstreamUsername, downstreamSubject)
	case psession.ProviderTypeActiveDirectory:
		return upstreamLDAPRefresh(ctx, customSessionData, providerCache, downstreamUsername, downstreamSubject)
	default:
		return errorsx.WithStack(errMissingUpstreamSessionInternalError)
	}
}

func upstreamOIDCRefresh(ctx context.Context, s *psession.CustomSessionData, providerCache oidc.UpstreamIdentityProvidersLister) error {
	if s.OIDC == nil || s.OIDC.UpstreamRefreshToken == "" {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError)
	}

	p, err := findOIDCProviderByNameAndValidateUID(s, providerCache)
	if err != nil {
		return err
	}

	plog.Debug("attempting upstream refresh request",
		"providerName", s.ProviderName, "providerType", s.ProviderType, "providerUID", s.ProviderUID)

	refreshedTokens, err := p.PerformRefresh(ctx, s.OIDC.UpstreamRefreshToken)
	if err != nil {
		return errorsx.WithStack(errUpstreamRefreshError.WithHintf(
			"Upstream refresh failed using provider %q of type %q.",
			s.ProviderName, s.ProviderType).WithWrap(err))
	}

	// Upstream refresh may or may not return a new ID token. From the spec:
	// "the response body is the Token Response of Section 3.1.3.3 except that it might not contain an id_token."
	// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
	_, hasIDTok := refreshedTokens.Extra("id_token").(string)
	if hasIDTok {
		// The spec is not 100% clear about whether an ID token from the refresh flow should include a nonce, and at
		// least some providers do not include one, so we skip the nonce validation here (but not other validations).
		_, err = p.ValidateToken(ctx, refreshedTokens, "")
		if err != nil {
			return errorsx.WithStack(errUpstreamRefreshError.WithHintf(
				"Upstream refresh returned an invalid ID token using provider %q of type %q.",
				s.ProviderName, s.ProviderType).WithWrap(err))
		}
	} else {
		plog.Debug("upstream refresh request did not return a new ID token",
			"providerName", s.ProviderName, "providerType", s.ProviderType, "providerUID", s.ProviderUID)
	}

	// Upstream refresh may or may not return a new refresh token. If we got a new refresh token, then update it in
	// the user's session. If we did not get a new refresh token, then keep the old one in the session by avoiding
	// overwriting the old one.
	if refreshedTokens.RefreshToken != "" {
		plog.Debug("upstream refresh request did not return a new refresh token",
			"providerName", s.ProviderName, "providerType", s.ProviderType, "providerUID", s.ProviderUID)
		s.OIDC.UpstreamRefreshToken = refreshedTokens.RefreshToken
	}

	return nil
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
		WithHintf("Provider %q of type %q from upstream session data was not found.", s.ProviderName, s.ProviderType))
}

func upstreamLDAPRefresh(ctx context.Context, s *psession.CustomSessionData, providerCache oidc.UpstreamIdentityProvidersLister, username string, subject string) error {
	// if you have neither a valid ldap session config nor a valid active directory session config
	if (s.LDAP == nil || s.LDAP.UserDN == "") && (s.ActiveDirectory == nil || s.ActiveDirectory.UserDN == "") {
		return errorsx.WithStack(errMissingUpstreamSessionInternalError)
	}

	// get ldap/ad provider out of cache
	p, dn, err := findLDAPProviderByNameAndValidateUID(s, providerCache)
	if err != nil {
		return err
	}
	// run PerformRefresh
	err = p.PerformRefresh(ctx, dn, username, subject)
	if err != nil {
		return errorsx.WithStack(errUpstreamRefreshError.WithHintf(
			"Upstream refresh failed using provider %q of type %q.",
			s.ProviderName, s.ProviderType).WithWrap(err))
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
				return nil, "", errorsx.WithStack(errUpstreamRefreshError.WithHintf(
					"Provider %q of type %q from upstream session data has changed its resource UID since authentication.",
					s.ProviderName, s.ProviderType))
			}
			return p, dn, nil
		}
	}

	return nil, "", errorsx.WithStack(errUpstreamRefreshError.
		WithHintf("Provider %q of type %q from upstream session data was not found.", s.ProviderName, s.ProviderType))
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
	downstreamUsername := downstreamUsernameInterface.(string)
	return downstreamUsername, nil
}
