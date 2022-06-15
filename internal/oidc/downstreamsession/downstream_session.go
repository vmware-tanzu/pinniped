// Copyright 2021-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package downstreamsession provides some shared helpers for creating downstream OIDC sessions.
package downstreamsession

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"k8s.io/utils/strings/slices"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/authenticators"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
)

const (
	// The name of the email claim from https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
	emailClaimName = "email"

	// The name of the email_verified claim from https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
	emailVerifiedClaimName = "email_verified"

	requiredClaimMissingErr            = constable.Error("required claim in upstream ID token missing")
	requiredClaimInvalidFormatErr      = constable.Error("required claim in upstream ID token has invalid format")
	requiredClaimEmptyErr              = constable.Error("required claim in upstream ID token is empty")
	emailVerifiedClaimInvalidFormatErr = constable.Error("email_verified claim in upstream ID token has invalid format")
	emailVerifiedClaimFalseErr         = constable.Error("email_verified claim in upstream ID token has false value")
)

// MakeDownstreamSession creates a downstream OIDC session.
func MakeDownstreamSession(subject string, username string, groups []string, grantedScopes []string, custom *psession.CustomSessionData) *psession.PinnipedSession {
	now := time.Now().UTC()
	openIDSession := &psession.PinnipedSession{
		Fosite: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:     subject,
				RequestedAt: now,
				AuthTime:    now,
			},
		},
		Custom: custom,
	}
	if groups == nil {
		groups = []string{}
	}
	openIDSession.IDTokenClaims().Extra = map[string]interface{}{
		oidc.DownstreamUsernameClaim: username,
	}
	if slices.Contains(grantedScopes, oidc.DownstreamGroupsScope) {
		openIDSession.IDTokenClaims().Extra[oidc.DownstreamGroupsClaim] = groups
	}
	return openIDSession
}

func MakeDownstreamLDAPOrADCustomSessionData(
	ldapUpstream provider.UpstreamLDAPIdentityProviderI,
	idpType psession.ProviderType,
	authenticateResponse *authenticators.Response,
) *psession.CustomSessionData {
	customSessionData := &psession.CustomSessionData{
		ProviderUID:  ldapUpstream.GetResourceUID(),
		ProviderName: ldapUpstream.GetName(),
		ProviderType: idpType,
	}

	if idpType == psession.ProviderTypeLDAP {
		customSessionData.LDAP = &psession.LDAPSessionData{
			UserDN:                 authenticateResponse.DN,
			ExtraRefreshAttributes: authenticateResponse.ExtraRefreshAttributes,
		}
	}

	if idpType == psession.ProviderTypeActiveDirectory {
		customSessionData.ActiveDirectory = &psession.ActiveDirectorySessionData{
			UserDN:                 authenticateResponse.DN,
			ExtraRefreshAttributes: authenticateResponse.ExtraRefreshAttributes,
		}
	}

	return customSessionData
}

func MakeDownstreamOIDCCustomSessionData(oidcUpstream provider.UpstreamOIDCIdentityProviderI, token *oidctypes.Token) (*psession.CustomSessionData, error) {
	upstreamSubject, err := ExtractStringClaimValue(oidc.IDTokenSubjectClaim, oidcUpstream.GetName(), token.IDToken.Claims)
	if err != nil {
		return nil, err
	}
	upstreamIssuer, err := ExtractStringClaimValue(oidc.IDTokenIssuerClaim, oidcUpstream.GetName(), token.IDToken.Claims)
	if err != nil {
		return nil, err
	}

	customSessionData := &psession.CustomSessionData{
		ProviderUID:  oidcUpstream.GetResourceUID(),
		ProviderName: oidcUpstream.GetName(),
		ProviderType: psession.ProviderTypeOIDC,
		OIDC: &psession.OIDCSessionData{
			UpstreamIssuer:  upstreamIssuer,
			UpstreamSubject: upstreamSubject,
		},
	}

	const pleaseCheck = "please check configuration of OIDCIdentityProvider and the client in the " +
		"upstream provider's API/UI and try to get a refresh token if possible"
	logKV := []interface{}{
		"upstreamName", oidcUpstream.GetName(),
		"scopes", oidcUpstream.GetScopes(),
		"additionalParams", oidcUpstream.GetAdditionalAuthcodeParams(),
	}

	hasRefreshToken := token.RefreshToken != nil && token.RefreshToken.Token != ""
	hasAccessToken := token.AccessToken != nil && token.AccessToken.Token != ""
	switch {
	case hasRefreshToken: // we prefer refresh tokens, so check for this first
		customSessionData.OIDC.UpstreamRefreshToken = token.RefreshToken.Token
	case hasAccessToken: // as a fallback, we can use the access token as long as there is a userinfo endpoint
		if !oidcUpstream.HasUserInfoURL() {
			plog.Warning("access token was returned by upstream provider during login without a refresh token "+
				"and there was no userinfo endpoint available on the provider. "+pleaseCheck, logKV...)
			return nil, errors.New("access token was returned by upstream provider but there was no userinfo endpoint")
		}
		plog.Info("refresh token not returned by upstream provider during login, using access token instead. "+pleaseCheck, logKV...)
		customSessionData.OIDC.UpstreamAccessToken = token.AccessToken.Token
		// When we are in a flow where we will be performing access token based refresh, issue a warning to the client if the access
		// token lifetime is very short, since that would mean that the user's session is very short.
		// The warnings are stored here and will be processed by the token handler.
		threeHoursFromNow := metav1.NewTime(time.Now().Add(3 * time.Hour))
		if !token.AccessToken.Expiry.IsZero() && token.AccessToken.Expiry.Before(&threeHoursFromNow) {
			customSessionData.Warnings = append(customSessionData.Warnings, "Access token from identity provider has lifetime of less than 3 hours. Expect frequent prompts to log in.")
		}
	default:
		plog.Warning("refresh token and access token not returned by upstream provider during login. "+pleaseCheck, logKV...)
		return nil, errors.New("neither access token nor refresh token returned by upstream provider")
	}

	return customSessionData, nil
}

// GrantScopesIfRequested auto-grants the scopes for which we do not require end-user approval, if they were requested.
func GrantScopesIfRequested(authorizeRequester fosite.AuthorizeRequester, scopes []string) {
	for _, scope := range scopes {
		oidc.GrantScopeIfRequested(authorizeRequester, scope)
	}
}

// GetDownstreamIdentityFromUpstreamIDToken returns the mapped subject, username, and group names, in that order.
func GetDownstreamIdentityFromUpstreamIDToken(
	upstreamIDPConfig provider.UpstreamOIDCIdentityProviderI,
	idTokenClaims map[string]interface{},
) (string, string, []string, error) {
	subject, username, err := getSubjectAndUsernameFromUpstreamIDToken(upstreamIDPConfig, idTokenClaims)
	if err != nil {
		return "", "", nil, err
	}

	groups, err := GetGroupsFromUpstreamIDToken(upstreamIDPConfig, idTokenClaims)
	if err != nil {
		return "", "", nil, err
	}

	return subject, username, groups, err
}

func getSubjectAndUsernameFromUpstreamIDToken(
	upstreamIDPConfig provider.UpstreamOIDCIdentityProviderI,
	idTokenClaims map[string]interface{},
) (string, string, error) {
	// The spec says the "sub" claim is only unique per issuer,
	// so we will prepend the issuer string to make it globally unique.
	upstreamIssuer, err := ExtractStringClaimValue(oidc.IDTokenIssuerClaim, upstreamIDPConfig.GetName(), idTokenClaims)
	if err != nil {
		return "", "", err
	}
	upstreamSubject, err := ExtractStringClaimValue(oidc.IDTokenSubjectClaim, upstreamIDPConfig.GetName(), idTokenClaims)
	if err != nil {
		return "", "", err
	}
	subject := downstreamSubjectFromUpstreamOIDC(upstreamIssuer, upstreamSubject)

	usernameClaimName := upstreamIDPConfig.GetUsernameClaim()
	if usernameClaimName == "" {
		return subject, subject, nil
	}

	// If the upstream username claim is configured to be the special "email" claim and the upstream "email_verified"
	// claim is present, then validate that the "email_verified" claim is true.
	emailVerifiedAsInterface, ok := idTokenClaims[emailVerifiedClaimName]
	if usernameClaimName == emailClaimName && ok {
		emailVerified, ok := emailVerifiedAsInterface.(bool)
		if !ok {
			plog.Warning(
				"username claim configured as \"email\" and upstream email_verified claim is not a boolean",
				"upstreamName", upstreamIDPConfig.GetName(),
				"configuredUsernameClaim", usernameClaimName,
				"emailVerifiedClaim", emailVerifiedAsInterface,
			)
			return "", "", emailVerifiedClaimInvalidFormatErr
		}
		if !emailVerified {
			plog.Warning(
				"username claim configured as \"email\" and upstream email_verified claim has false value",
				"upstreamName", upstreamIDPConfig.GetName(),
				"configuredUsernameClaim", usernameClaimName,
			)
			return "", "", emailVerifiedClaimFalseErr
		}
	}

	username, err := ExtractStringClaimValue(usernameClaimName, upstreamIDPConfig.GetName(), idTokenClaims)
	if err != nil {
		return "", "", err
	}

	return subject, username, nil
}

func ExtractStringClaimValue(claimName string, upstreamIDPName string, idTokenClaims map[string]interface{}) (string, error) {
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

func DownstreamSubjectFromUpstreamLDAP(ldapUpstream provider.UpstreamLDAPIdentityProviderI, authenticateResponse *authenticators.Response) string {
	ldapURL := *ldapUpstream.GetURL()
	return DownstreamLDAPSubject(authenticateResponse.User.GetUID(), ldapURL)
}

func DownstreamLDAPSubject(uid string, ldapURL url.URL) string {
	q := ldapURL.Query()
	q.Set(oidc.IDTokenSubjectClaim, uid)
	ldapURL.RawQuery = q.Encode()
	return ldapURL.String()
}

func downstreamSubjectFromUpstreamOIDC(upstreamIssuerAsString string, upstreamSubject string) string {
	return fmt.Sprintf("%s?%s=%s", upstreamIssuerAsString, oidc.IDTokenSubjectClaim, url.QueryEscape(upstreamSubject))
}

// GetGroupsFromUpstreamIDToken returns mapped group names coerced into a slice of strings.
// It returns nil when there is no configured groups claim name, or then when the configured claim name is not found
// in the provided map of claims. It returns an error when the claim exists but its value cannot be parsed.
func GetGroupsFromUpstreamIDToken(
	upstreamIDPConfig provider.UpstreamOIDCIdentityProviderI,
	idTokenClaims map[string]interface{},
) ([]string, error) {
	groupsClaimName := upstreamIDPConfig.GetGroupsClaim()
	if groupsClaimName == "" {
		return nil, nil
	}

	groupsAsInterface, ok := idTokenClaims[groupsClaimName]
	if !ok {
		plog.Warning(
			"no groups claim in upstream ID token",
			"upstreamName", upstreamIDPConfig.GetName(),
			"configuredGroupsClaim", groupsClaimName,
		)
		return nil, nil // the upstream IDP may have omitted the claim if the user has no groups
	}

	groupsAsArray, okAsArray := extractGroups(groupsAsInterface)
	if !okAsArray {
		plog.Warning(
			"groups claim in upstream ID token has invalid format",
			"upstreamName", upstreamIDPConfig.GetName(),
			"configuredGroupsClaim", groupsClaimName,
		)
		return nil, requiredClaimInvalidFormatErr
	}

	return groupsAsArray, nil
}

func extractGroups(groupsAsInterface interface{}) ([]string, bool) {
	groupsAsString, okAsString := groupsAsInterface.(string)
	if okAsString {
		return []string{groupsAsString}, true
	}

	groupsAsStringArray, okAsStringArray := groupsAsInterface.([]string)
	if okAsStringArray {
		return groupsAsStringArray, true
	}

	groupsAsInterfaceArray, okAsArray := groupsAsInterface.([]interface{})
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
