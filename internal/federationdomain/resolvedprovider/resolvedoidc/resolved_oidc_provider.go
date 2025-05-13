// Copyright 2024-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resolvedoidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ory/fosite"
	errorsx "github.com/pkg/errors"
	"golang.org/x/oauth2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/federationdomain/downstreamsubject"
	"go.pinniped.dev/internal/federationdomain/resolvedprovider"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

const (
	// The name of the email claim from https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
	emailClaimName = oidcapi.ScopeEmail

	// The name of the email_verified claim from https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
	emailVerifiedClaimName = "email_verified"

	requiredClaimMissingErr            = constable.Error("required claim in upstream ID token missing")
	requiredClaimInvalidFormatErr      = constable.Error("required claim in upstream ID token has invalid format")
	requiredClaimEmptyErr              = constable.Error("required claim in upstream ID token is empty")
	emailVerifiedClaimInvalidFormatErr = constable.Error("email_verified claim in upstream ID token has invalid format")
	emailVerifiedClaimFalseErr         = constable.Error("email_verified claim in upstream ID token has false value")
)

// FederationDomainResolvedOIDCIdentityProvider represents a FederationDomainIdentityProvider which has
// been resolved dynamically based on the currently loaded IDP CRs to include the provider.UpstreamOIDCIdentityProviderI
// and other metadata about the provider.
type FederationDomainResolvedOIDCIdentityProvider struct {
	DisplayName         string
	Provider            upstreamprovider.UpstreamOIDCIdentityProviderI
	SessionProviderType psession.ProviderType
	Transforms          *idtransform.TransformationPipeline
}

var _ resolvedprovider.FederationDomainResolvedIdentityProvider = (*FederationDomainResolvedOIDCIdentityProvider)(nil)

func (p *FederationDomainResolvedOIDCIdentityProvider) GetDisplayName() string {
	return p.DisplayName
}

func (p *FederationDomainResolvedOIDCIdentityProvider) GetProvider() upstreamprovider.UpstreamIdentityProviderI {
	return p.Provider
}

func (p *FederationDomainResolvedOIDCIdentityProvider) GetSessionProviderType() psession.ProviderType {
	return p.SessionProviderType
}

func (p *FederationDomainResolvedOIDCIdentityProvider) GetIDPDiscoveryType() v1alpha1.IDPType {
	return v1alpha1.IDPTypeOIDC
}

func (p *FederationDomainResolvedOIDCIdentityProvider) GetIDPDiscoveryFlows() []v1alpha1.IDPFlow {
	flows := []v1alpha1.IDPFlow{v1alpha1.IDPFlowBrowserAuthcode}
	if p.Provider.AllowsPasswordGrant() {
		flows = append(flows, v1alpha1.IDPFlowCLIPassword)
	}
	return flows
}

func (p *FederationDomainResolvedOIDCIdentityProvider) GetTransforms() *idtransform.TransformationPipeline {
	return p.Transforms
}

func (p *FederationDomainResolvedOIDCIdentityProvider) CloneIDPSpecificSessionDataFromSession(session *psession.CustomSessionData) any {
	if session.OIDC == nil {
		return nil
	}
	return session.OIDC.Clone()
}

func (p *FederationDomainResolvedOIDCIdentityProvider) ApplyIDPSpecificSessionDataToSession(session *psession.CustomSessionData, idpSpecificSessionData any) {
	session.OIDC = idpSpecificSessionData.(*psession.OIDCSessionData)
}

func (p *FederationDomainResolvedOIDCIdentityProvider) UpstreamAuthorizeRedirectURL(state *resolvedprovider.UpstreamAuthorizeRequestState, downstreamIssuerURL string) (string, error) {
	upstreamOAuthConfig := oauth2.Config{
		ClientID: p.Provider.GetClientID(),
		Endpoint: oauth2.Endpoint{
			AuthURL: p.Provider.GetAuthorizationURL().String(),
		},
		RedirectURL: fmt.Sprintf("%s/callback", downstreamIssuerURL),
		Scopes:      p.Provider.GetScopes(),
	}

	authCodeOptions := []oauth2.AuthCodeOption{
		state.Nonce.Param(),
		state.PKCE.Challenge(),
		state.PKCE.Method(),
	}

	for key, val := range p.Provider.GetAdditionalAuthcodeParams() {
		authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam(key, val))
	}

	redirectURL := upstreamOAuthConfig.AuthCodeURL(
		state.EncodedStateParam.String(),
		authCodeOptions...,
	)

	return redirectURL, nil
}

func (p *FederationDomainResolvedOIDCIdentityProvider) Login(
	ctx context.Context,
	submittedUsername string,
	submittedPassword string,
) (*resolvedprovider.Identity, *resolvedprovider.IdentityLoginExtras, error) {
	if !p.Provider.AllowsPasswordGrant() {
		// Return a user-friendly error for this case which is entirely within our control.
		return nil, nil, fosite.ErrAccessDenied.WithHint(
			"Resource owner password credentials grant is not allowed for this upstream provider according to its configuration.")
	}

	token, err := p.Provider.PasswordCredentialsGrantAndValidateTokens(ctx, submittedUsername, submittedPassword)
	if err != nil {
		// Upstream password grant errors can be generic errors (e.g. a network failure) or can be oauth2.RetrieveError errors
		// which represent the http response from the upstream server. These could be a 5XX or some other unexpected error,
		// or could be a 400 with a JSON body as described by https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
		// which notes that wrong resource owner credentials should result in an "invalid_grant" error.
		// However, the exact response is undefined in the sense that there is no such thing as a password grant in
		// the OIDC spec, so we don't try too hard to read the upstream errors in this case. (E.g. Dex departs from the
		// spec and returns something other than an "invalid_grant" error for bad resource owner credentials.)
		return nil, nil, fosite.ErrAccessDenied.WithDebug(err.Error()) // WithDebug hides the error from the client
	}

	subject, upstreamUsername, upstreamGroups, err := getIdentityFromUpstreamIDToken(
		p.Provider, token.IDToken.Claims, p.GetDisplayName(),
	)
	if err != nil {
		// Return a user-friendly error for this case which is entirely within our control.
		return nil, nil, fosite.ErrAccessDenied.WithHintf("Reason: %s.", err.Error())
	}

	additionalClaims := mapAdditionalClaimsFromUpstreamIDToken(p.Provider, token.IDToken.Claims)

	oidcSessionData, warnings, err := makeDownstreamOIDCSessionData(p.Provider, token)
	if err != nil {
		return nil, nil, fosite.ErrAccessDenied.WithHintf("Reason: %s.", err.Error())
	}

	return &resolvedprovider.Identity{
			UpstreamUsername:       upstreamUsername,
			UpstreamGroups:         upstreamGroups,
			DownstreamSubject:      subject,
			IDPSpecificSessionData: oidcSessionData,
		},
		&resolvedprovider.IdentityLoginExtras{
			DownstreamAdditionalClaims: additionalClaims,
			Warnings:                   warnings,
		},
		nil
}

func (p *FederationDomainResolvedOIDCIdentityProvider) LoginFromCallback(
	ctx context.Context,
	authCode string,
	pkce pkce.Code,
	nonce nonce.Nonce,
	redirectURI string,
) (*resolvedprovider.Identity, *resolvedprovider.IdentityLoginExtras, error) {
	token, err := p.Provider.ExchangeAuthcodeAndValidateTokens(
		ctx,
		authCode,
		pkce,
		nonce,
		redirectURI,
	)
	if err != nil {
		return nil, nil, httperr.Wrap(http.StatusBadGateway, "error exchanging and validating upstream tokens", err)
	}

	subject, upstreamUsername, upstreamGroups, err := getIdentityFromUpstreamIDToken(
		p.Provider, token.IDToken.Claims, p.GetDisplayName(),
	)
	if err != nil {
		return nil, nil, httperr.Wrap(http.StatusUnprocessableEntity, err.Error(), err)
	}

	additionalClaims := mapAdditionalClaimsFromUpstreamIDToken(p.Provider, token.IDToken.Claims)

	oidcSessionData, warnings, err := makeDownstreamOIDCSessionData(p.Provider, token)
	if err != nil {
		return nil, nil, httperr.Wrap(http.StatusUnprocessableEntity, err.Error(), err)
	}

	return &resolvedprovider.Identity{
			UpstreamUsername:       upstreamUsername,
			UpstreamGroups:         upstreamGroups,
			DownstreamSubject:      subject,
			IDPSpecificSessionData: oidcSessionData,
		},
		&resolvedprovider.IdentityLoginExtras{
			DownstreamAdditionalClaims: additionalClaims,
			Warnings:                   warnings,
		},
		nil
}

func (p *FederationDomainResolvedOIDCIdentityProvider) UpstreamRefresh(
	ctx context.Context,
	identity *resolvedprovider.Identity,
) (refreshedIdentity *resolvedprovider.RefreshedIdentity, err error) {
	sessionData, ok := identity.IDPSpecificSessionData.(*psession.OIDCSessionData)
	if !ok {
		// This shouldn't really happen.
		return nil, errorsx.WithStack(resolvedprovider.ErrMissingUpstreamSessionInternalError())
	}

	accessTokenStored := sessionData.UpstreamAccessToken != ""
	refreshTokenStored := sessionData.UpstreamRefreshToken != ""

	//nolint:staticcheck // De Morgan's doesn't make this more readable
	exactlyOneTokenStored := (accessTokenStored || refreshTokenStored) && !(accessTokenStored && refreshTokenStored)
	if !exactlyOneTokenStored {
		return nil, errorsx.WithStack(resolvedprovider.ErrMissingUpstreamSessionInternalError())
	}

	plog.Debug("attempting upstream refresh request",
		"identityProviderResourceName", p.Provider.GetResourceName(),
		"identityProviderType", p.GetSessionProviderType(),
		"identityProviderUID", p.Provider.GetResourceUID())

	var tokens *oauth2.Token
	if refreshTokenStored {
		tokens, err = p.Provider.PerformRefresh(ctx, sessionData.UpstreamRefreshToken)
		if err != nil {
			return nil, resolvedprovider.ErrUpstreamRefreshError().WithHint(
				"Upstream refresh failed.",
			).WithTrace(err).WithDebugf("provider name: %q, provider type: %q", p.Provider.GetResourceName(), p.GetSessionProviderType())
		}
	} else {
		tokens = &oauth2.Token{AccessToken: sessionData.UpstreamAccessToken}
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
		return nil, resolvedprovider.ErrUpstreamRefreshError().WithHintf(
			"Upstream refresh returned an invalid ID token or UserInfo response.").WithTrace(err).
			WithDebugf("provider name: %q, provider type: %q", p.Provider.GetResourceName(), p.GetSessionProviderType())
	}
	mergedClaims := validatedTokens.IDToken.Claims

	// To the extent possible, check that the user's basic identity hasn't changed. We check that their downstream
	// username has not changed separately below, as part of reapplying the transformations.
	err = validateUpstreamSubjectAndIssuerUnchangedSinceInitialLogin(mergedClaims, sessionData, p.Provider.GetResourceName(), p.GetSessionProviderType())
	if err != nil {
		return nil, err
	}

	// If possible, update the user's group memberships. The configured groups claim name (if there is one) may or
	// may not be included in the newly fetched and merged claims. It could be missing due to a misconfiguration of the
	// claim name. It could also be missing because the claim was originally found in the ID token during login, but
	// now we might not have a refreshed ID token.
	// If the claim is found, then use it to update the user's group membership in the session.
	// If the claim is not found, then we have no new information about groups, so skip updating the group membership
	// and let any old groups memberships in the session remain.
	refreshedUntransformedGroups, err := getGroupsFromUpstreamIDToken(p.Provider, mergedClaims)
	if err != nil {
		return nil, resolvedprovider.ErrUpstreamRefreshError().WithHintf(
			"Upstream refresh error while extracting groups claim.").WithTrace(err).
			WithDebugf("provider name: %q, provider type: %q", p.Provider.GetResourceName(), p.GetSessionProviderType())
	}

	// It's possible that a username wasn't returned by the upstream provider during refresh,
	// but if it is, verify that the transformed version of it hasn't changed.
	refreshedUntransformedUsername, hasRefreshedUntransformedUsername := getString(mergedClaims, p.Provider.GetUsernameClaim())

	if !hasRefreshedUntransformedUsername {
		// If we could not get a new username, then we still need the untransformed username to be able to
		// run the transformations again, so use the original untransformed username from the session.
		refreshedUntransformedUsername = identity.UpstreamUsername
	}

	updatedSessionData := sessionData.Clone()

	// Upstream refresh may or may not return a new refresh token. If we got a new refresh token, then update it in
	// the user's session. If we did not get a new refresh token, then keep the old one in the session by avoiding
	// overwriting the old one.
	if tokens.RefreshToken != "" {
		plog.Debug("upstream refresh request returned a new refresh token",
			"identityProviderResourceName", p.Provider.GetResourceName(),
			"identityProviderType", p.GetSessionProviderType(),
			"identityProviderUID", p.Provider.GetResourceUID())

		updatedSessionData.UpstreamRefreshToken = tokens.RefreshToken
	}

	return &resolvedprovider.RefreshedIdentity{
		UpstreamUsername:       refreshedUntransformedUsername,
		UpstreamGroups:         refreshedUntransformedGroups,
		IDPSpecificSessionData: updatedSessionData,
	}, nil
}

func validateUpstreamSubjectAndIssuerUnchangedSinceInitialLogin(
	mergedClaims map[string]any,
	s *psession.OIDCSessionData,
	providerName string,
	providerType psession.ProviderType,
) error {
	// If we have any claims at all, we better have a subject, and it better match the previous value.
	// but it's possible that we don't because both returning a new id token on refresh and having a userinfo
	// endpoint are optional.
	if len(mergedClaims) == 0 {
		return nil
	}

	newSub, hasSub := getString(mergedClaims, oidcapi.IDTokenClaimSubject)
	if !hasSub {
		return resolvedprovider.ErrUpstreamRefreshError().WithHintf(
			"Upstream refresh failed.").WithTrace(errors.New("subject in upstream refresh not found")).
			WithDebugf("provider name: %q, provider type: %q", providerName, providerType)
	}
	if s.UpstreamSubject != newSub {
		return resolvedprovider.ErrUpstreamRefreshError().WithHintf(
			"Upstream refresh failed.").WithTrace(errors.New("subject in upstream refresh does not match previous value")).
			WithDebugf("provider name: %q, provider type: %q", providerName, providerType)
	}

	newIssuer, hasIssuer := getString(mergedClaims, oidcapi.IDTokenClaimIssuer)
	// It's possible that an issuer wasn't returned by the upstream provider during refresh,
	// but if it is, verify that it hasn't changed.
	if hasIssuer && s.UpstreamIssuer != newIssuer {
		return resolvedprovider.ErrUpstreamRefreshError().WithHintf(
			"Upstream refresh failed.").WithTrace(errors.New("issuer in upstream refresh does not match previous value")).
			WithDebugf("provider name: %q, provider type: %q", providerName, providerType)
	}

	return nil
}

func getString(m map[string]any, key string) (string, bool) {
	val, ok := m[key].(string)
	return val, ok
}

func makeDownstreamOIDCSessionData(
	oidcUpstream upstreamprovider.UpstreamOIDCIdentityProviderI,
	token *oidctypes.Token,
) (*psession.OIDCSessionData, []string, error) {
	upstreamSubject, err := extractStringClaimValue(oidcapi.IDTokenClaimSubject, oidcUpstream.GetResourceName(), token.IDToken.Claims)
	if err != nil {
		return nil, nil, err
	}
	upstreamIssuer, err := extractStringClaimValue(oidcapi.IDTokenClaimIssuer, oidcUpstream.GetResourceName(), token.IDToken.Claims)
	if err != nil {
		return nil, nil, err
	}

	sessionData := &psession.OIDCSessionData{
		UpstreamIssuer:  upstreamIssuer,
		UpstreamSubject: upstreamSubject,
	}

	const pleaseCheck = "please check configuration of OIDCIdentityProvider and the client in the " +
		"upstream provider's API/UI and try to get a refresh token if possible"
	logKV := []any{
		"identityProviderResourceName", oidcUpstream.GetResourceName(),
		"scopes", oidcUpstream.GetScopes(),
		"additionalParams", oidcUpstream.GetAdditionalAuthcodeParams(),
	}

	var warnings []string

	hasRefreshToken := token.RefreshToken != nil && token.RefreshToken.Token != ""
	hasAccessToken := token.AccessToken != nil && token.AccessToken.Token != ""
	switch {
	case hasRefreshToken: // we prefer refresh tokens, so check for this first
		sessionData.UpstreamRefreshToken = token.RefreshToken.Token
	case hasAccessToken: // as a fallback, we can use the access token as long as there is a userinfo endpoint
		if !oidcUpstream.HasUserInfoURL() {
			plog.Warning("access token was returned by upstream provider during login without a refresh token "+
				"and there was no userinfo endpoint available on the provider. "+pleaseCheck, logKV...)
			return nil, nil, errors.New("access token was returned by upstream provider but there was no userinfo endpoint")
		}
		plog.Info("refresh token not returned by upstream provider during login, using access token instead. "+pleaseCheck, logKV...)
		sessionData.UpstreamAccessToken = token.AccessToken.Token
		// When we are in a flow where we will be performing access token based refresh, issue a warning to the client if the access
		// token lifetime is very short, since that would mean that the user's session is very short.
		// The warnings are stored here and will be processed by the token handler.
		threeHoursFromNow := metav1.NewTime(time.Now().Add(3 * time.Hour))
		if !token.AccessToken.Expiry.IsZero() && token.AccessToken.Expiry.Before(&threeHoursFromNow) {
			warnings = []string{"Access token from identity provider has lifetime of less than 3 hours. Expect frequent prompts to log in."}
		}
	default:
		plog.Warning("refresh token and access token not returned by upstream provider during login. "+pleaseCheck, logKV...)
		return nil, nil, errors.New("neither access token nor refresh token returned by upstream provider")
	}

	return sessionData, warnings, nil
}

// getIdentityFromUpstreamIDToken returns the mapped subject, username, and group names, in that order.
func getIdentityFromUpstreamIDToken(
	upstreamIDPConfig upstreamprovider.UpstreamOIDCIdentityProviderI,
	idTokenClaims map[string]any,
	idpDisplayName string,
) (string, string, []string, error) {
	subject, username, err := getDownstreamSubjectAndUpstreamUsernameFromUpstreamIDToken(upstreamIDPConfig, idTokenClaims, idpDisplayName)
	if err != nil {
		return "", "", nil, err
	}

	groups, err := getGroupsFromUpstreamIDToken(upstreamIDPConfig, idTokenClaims)
	if err != nil {
		return "", "", nil, err
	}

	return subject, username, groups, err
}

// mapAdditionalClaimsFromUpstreamIDToken returns the additionalClaims mapped from the upstream token, if any.
func mapAdditionalClaimsFromUpstreamIDToken(
	upstreamIDPConfig upstreamprovider.UpstreamOIDCIdentityProviderI,
	idTokenClaims map[string]any,
) map[string]any {
	mapped := make(map[string]any, len(upstreamIDPConfig.GetAdditionalClaimMappings()))
	for downstreamClaimName, upstreamClaimName := range upstreamIDPConfig.GetAdditionalClaimMappings() {
		upstreamClaimValue, ok := idTokenClaims[upstreamClaimName]
		if !ok {
			plog.Warning(
				"additionalClaims mapping claim in upstream ID token missing",
				"identityProviderResourceName", upstreamIDPConfig.GetResourceName(),
				"claimName", upstreamClaimName,
			)
		} else {
			mapped[downstreamClaimName] = upstreamClaimValue
		}
	}
	return mapped
}

func getDownstreamSubjectAndUpstreamUsernameFromUpstreamIDToken(
	upstreamIDPConfig upstreamprovider.UpstreamOIDCIdentityProviderI,
	idTokenClaims map[string]any,
	idpDisplayName string,
) (string, string, error) {
	// The spec says the "sub" claim is only unique per issuer,
	// so we will prepend the issuer string to make it globally unique.
	upstreamIssuer, err := extractStringClaimValue(oidcapi.IDTokenClaimIssuer, upstreamIDPConfig.GetResourceName(), idTokenClaims)
	if err != nil {
		return "", "", err
	}
	upstreamSubject, err := extractStringClaimValue(oidcapi.IDTokenClaimSubject, upstreamIDPConfig.GetResourceName(), idTokenClaims)
	if err != nil {
		return "", "", err
	}
	subject := downstreamsubject.OIDC(upstreamIssuer, upstreamSubject, idpDisplayName)

	usernameClaimName := upstreamIDPConfig.GetUsernameClaim()
	if usernameClaimName == "" {
		return subject, mappedUsernameFromUpstreamOIDCSubject(upstreamIssuer, upstreamSubject), nil
	}

	// If the upstream username claim is configured to be the special "email" claim and the upstream "email_verified"
	// claim is present, then validate that the "email_verified" claim is true.
	emailVerifiedAsInterface, ok := idTokenClaims[emailVerifiedClaimName]
	if usernameClaimName == emailClaimName && ok {
		emailVerified, ok := emailVerifiedAsInterface.(bool)
		if !ok {
			plog.Warning(
				"username claim configured as \"email\" and upstream email_verified claim is not a boolean",
				"identityProviderResourceName", upstreamIDPConfig.GetResourceName(),
				"configuredUsernameClaim", usernameClaimName,
				"emailVerifiedClaim", emailVerifiedAsInterface,
			)
			return "", "", emailVerifiedClaimInvalidFormatErr
		}
		if !emailVerified {
			plog.Warning(
				"username claim configured as \"email\" and upstream email_verified claim has false value",
				"identityProviderResourceName", upstreamIDPConfig.GetResourceName(),
				"configuredUsernameClaim", usernameClaimName,
			)
			return "", "", emailVerifiedClaimFalseErr
		}
	}

	username, err := extractStringClaimValue(usernameClaimName, upstreamIDPConfig.GetResourceName(), idTokenClaims)
	if err != nil {
		return "", "", err
	}

	return subject, username, nil
}

func extractStringClaimValue(claimName string, upstreamIDPName string, idTokenClaims map[string]any) (string, error) {
	value, ok := idTokenClaims[claimName]
	if !ok {
		plog.Warning(
			"required claim in upstream ID token missing",
			"upstreamName", upstreamIDPName,
			"claimName", claimName,
		)
		return "", requiredClaimMissingErr
	}

	valueAsString, ok := value.(string)
	if !ok {
		plog.Warning(
			"required claim in upstream ID token is not a string value",
			"upstreamName", upstreamIDPName,
			"claimName", claimName,
		)
		return "", requiredClaimInvalidFormatErr
	}

	if valueAsString == "" {
		plog.Warning(
			"required claim in upstream ID token has an empty string value",
			"upstreamName", upstreamIDPName,
			"claimName", claimName,
		)
		return "", requiredClaimEmptyErr
	}

	return valueAsString, nil
}

func mappedUsernameFromUpstreamOIDCSubject(upstreamIssuerAsString string, upstreamSubject string) string {
	return fmt.Sprintf("%s?%s=%s", upstreamIssuerAsString,
		oidcapi.IDTokenClaimSubject, url.QueryEscape(upstreamSubject),
	)
}

// getGroupsFromUpstreamIDToken returns mapped group names coerced into a slice of strings.
// It returns nil when there is no configured groups claim name, or then when the configured claim name is not found
// in the provided map of claims. It returns an error when the claim exists but its value cannot be parsed.
func getGroupsFromUpstreamIDToken(
	upstreamIDPConfig upstreamprovider.UpstreamOIDCIdentityProviderI,
	idTokenClaims map[string]any,
) ([]string, error) {
	groupsClaimName := upstreamIDPConfig.GetGroupsClaim()
	if groupsClaimName == "" {
		return nil, nil
	}

	groupsAsInterface, ok := idTokenClaims[groupsClaimName]
	if !ok {
		plog.Warning(
			"no groups claim in upstream ID token",
			"identityProviderResourceName", upstreamIDPConfig.GetResourceName(),
			"configuredGroupsClaim", groupsClaimName,
		)
		return nil, nil // the upstream IDP may have omitted the claim if the user has no groups
	}

	groupsAsArray, okAsArray := extractGroups(groupsAsInterface)
	if !okAsArray {
		plog.Warning(
			"groups claim in upstream ID token has invalid format",
			"identityProviderResourceName", upstreamIDPConfig.GetResourceName(),
			"configuredGroupsClaim", groupsClaimName,
		)
		return nil, requiredClaimInvalidFormatErr
	}

	return groupsAsArray, nil
}

func extractGroups(groupsAsInterface any) ([]string, bool) {
	groupsAsString, okAsString := groupsAsInterface.(string)
	if okAsString {
		return []string{groupsAsString}, true
	}

	groupsAsStringArray, okAsStringArray := groupsAsInterface.([]string)
	if okAsStringArray {
		return groupsAsStringArray, true
	}

	groupsAsInterfaceArray, okAsArray := groupsAsInterface.([]any)
	if !okAsArray {
		return nil, false
	}

	var groupsAsStrings []string
	for _, groupAsInterface := range groupsAsInterfaceArray {
		groupAsString, okAsString := groupAsInterface.(string)
		if !okAsString {
			return nil, false
		}
		if groupAsString != "" {
			groupsAsStrings = append(groupsAsStrings, groupAsString)
		}
	}

	return groupsAsStrings, true
}
