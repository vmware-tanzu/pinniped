// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package downstreamsession provides some shared helpers for creating downstream OIDC sessions.
package downstreamsession

import (
	"fmt"
	"net/url"
	"time"

	oidc2 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/psession"
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
func MakeDownstreamSession(subject string, username string, groups []string, custom *psession.CustomSessionData) *psession.PinnipedSession {
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
		oidc.DownstreamGroupsClaim:   groups,
	}
	return openIDSession
}

// GrantScopesIfRequested auto-grants the scopes for which we do not require end-user approval, if they were requested.
func GrantScopesIfRequested(authorizeRequester fosite.AuthorizeRequester) {
	oidc.GrantScopeIfRequested(authorizeRequester, oidc2.ScopeOpenID)
	oidc.GrantScopeIfRequested(authorizeRequester, oidc2.ScopeOfflineAccess)
	oidc.GrantScopeIfRequested(authorizeRequester, "pinniped:request-audience")
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

	groups, err := getGroupsFromUpstreamIDToken(upstreamIDPConfig, idTokenClaims)
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
	upstreamIssuer, err := extractStringClaimValue(oidc.IDTokenIssuerClaim, upstreamIDPConfig.GetName(), idTokenClaims)
	if err != nil {
		return "", "", err
	}
	upstreamSubject, err := extractStringClaimValue(oidc.IDTokenSubjectClaim, upstreamIDPConfig.GetName(), idTokenClaims)
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

	username, err := extractStringClaimValue(usernameClaimName, upstreamIDPConfig.GetName(), idTokenClaims)
	if err != nil {
		return "", "", err
	}

	return subject, username, nil
}

func extractStringClaimValue(claimName string, upstreamIDPName string, idTokenClaims map[string]interface{}) (string, error) {
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

func DownstreamLDAPSubject(uid string, ldapURL url.URL) string {
	q := ldapURL.Query()
	q.Set(oidc.IDTokenSubjectClaim, uid)
	ldapURL.RawQuery = q.Encode()
	return ldapURL.String()
}

func downstreamSubjectFromUpstreamOIDC(upstreamIssuerAsString string, upstreamSubject string) string {
	return fmt.Sprintf("%s?%s=%s", upstreamIssuerAsString, oidc.IDTokenSubjectClaim, url.QueryEscape(upstreamSubject))
}

func getGroupsFromUpstreamIDToken(
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
