// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcclientvalidator

import (
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/crypto/bcrypt"
	v1 "k8s.io/api/core/v1"

	"go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	"go.pinniped.dev/internal/oidcclientsecretstorage"
)

const (
	clientSecretExists     = "ClientSecretExists"
	allowedGrantTypesValid = "AllowedGrantTypesValid"
	allowedScopesValid     = "AllowedScopesValid"

	reasonSuccess                  = "Success"
	reasonMissingRequiredValue     = "MissingRequiredValue"
	reasonNoClientSecretFound      = "NoClientSecretFound"
	reasonInvalidClientSecretFound = "InvalidClientSecretFound"

	authorizationCodeGrantTypeName = "authorization_code"
	refreshTokenGrantTypeName      = "refresh_token"
	tokenExchangeGrantTypeName     = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // this is not a credential

	openidScopeName          = oidc.ScopeOpenID
	offlineAccessScopeName   = oidc.ScopeOfflineAccess
	requestAudienceScopeName = "pinniped:request-audience"
	usernameScopeName        = "username"
	groupsScopeName          = "groups"

	allowedGrantTypesFieldName = "allowedGrantTypes"
	allowedScopesFieldName     = "allowedScopes"

	minimumRequiredBcryptCost = 15
)

// Validate validates the OIDCClient and its corresponding client secret storage Secret.
// When the corresponding client secret storage Secret was not found, pass nil to this function to
// get the validation error for that case. It returns a bool to indicate if the client is valid,
// along with a slice of conditions containing more details, and the list of client secrets in the
// case that the client was valid.
func Validate(oidcClient *v1alpha1.OIDCClient, secret *v1.Secret) (bool, []*v1alpha1.Condition, []string) {
	conds := make([]*v1alpha1.Condition, 0, 3)

	conds, clientSecrets := validateSecret(secret, conds)
	conds = validateAllowedGrantTypes(oidcClient, conds)
	conds = validateAllowedScopes(oidcClient, conds)

	valid := true
	for _, cond := range conds {
		if cond.Status != v1alpha1.ConditionTrue {
			valid = false
			break
		}
	}
	return valid, conds, clientSecrets
}

// validateAllowedScopes checks if allowedScopes is valid on the OIDCClient.
func validateAllowedScopes(oidcClient *v1alpha1.OIDCClient, conditions []*v1alpha1.Condition) []*v1alpha1.Condition {
	m := make([]string, 0, 4)

	if !allowedScopesContains(oidcClient, openidScopeName) {
		m = append(m, fmt.Sprintf("%q must always be included in %q", openidScopeName, allowedScopesFieldName))
	}
	if allowedGrantTypesContains(oidcClient, refreshTokenGrantTypeName) && !allowedScopesContains(oidcClient, offlineAccessScopeName) {
		m = append(m, fmt.Sprintf("%q must be included in %q when %q is included in %q",
			offlineAccessScopeName, allowedScopesFieldName, refreshTokenGrantTypeName, allowedGrantTypesFieldName))
	}
	if allowedScopesContains(oidcClient, requestAudienceScopeName) &&
		(!allowedScopesContains(oidcClient, usernameScopeName) || !allowedScopesContains(oidcClient, groupsScopeName)) {
		m = append(m, fmt.Sprintf("%q and %q must be included in %q when %q is included in %q",
			usernameScopeName, groupsScopeName, allowedScopesFieldName, requestAudienceScopeName, allowedScopesFieldName))
	}
	if allowedGrantTypesContains(oidcClient, tokenExchangeGrantTypeName) && !allowedScopesContains(oidcClient, requestAudienceScopeName) {
		m = append(m, fmt.Sprintf("%q must be included in %q when %q is included in %q",
			requestAudienceScopeName, allowedScopesFieldName, tokenExchangeGrantTypeName, allowedGrantTypesFieldName))
	}

	if len(m) == 0 {
		conditions = append(conditions, &v1alpha1.Condition{
			Type:    allowedScopesValid,
			Status:  v1alpha1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: fmt.Sprintf("%q is valid", allowedScopesFieldName),
		})
	} else {
		conditions = append(conditions, &v1alpha1.Condition{
			Type:    allowedScopesValid,
			Status:  v1alpha1.ConditionFalse,
			Reason:  reasonMissingRequiredValue,
			Message: strings.Join(m, "; "),
		})
	}

	return conditions
}

// validateAllowedGrantTypes checks if allowedGrantTypes is valid on the OIDCClient.
func validateAllowedGrantTypes(oidcClient *v1alpha1.OIDCClient, conditions []*v1alpha1.Condition) []*v1alpha1.Condition {
	m := make([]string, 0, 3)

	if !allowedGrantTypesContains(oidcClient, authorizationCodeGrantTypeName) {
		m = append(m, fmt.Sprintf("%q must always be included in %q",
			authorizationCodeGrantTypeName, allowedGrantTypesFieldName))
	}
	if allowedScopesContains(oidcClient, offlineAccessScopeName) && !allowedGrantTypesContains(oidcClient, refreshTokenGrantTypeName) {
		m = append(m, fmt.Sprintf("%q must be included in %q when %q is included in %q",
			refreshTokenGrantTypeName, allowedGrantTypesFieldName, offlineAccessScopeName, allowedScopesFieldName))
	}
	if allowedScopesContains(oidcClient, requestAudienceScopeName) && !allowedGrantTypesContains(oidcClient, tokenExchangeGrantTypeName) {
		m = append(m, fmt.Sprintf("%q must be included in %q when %q is included in %q",
			tokenExchangeGrantTypeName, allowedGrantTypesFieldName, requestAudienceScopeName, allowedScopesFieldName))
	}

	if len(m) == 0 {
		conditions = append(conditions, &v1alpha1.Condition{
			Type:    allowedGrantTypesValid,
			Status:  v1alpha1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: fmt.Sprintf("%q is valid", allowedGrantTypesFieldName),
		})
	} else {
		conditions = append(conditions, &v1alpha1.Condition{
			Type:    allowedGrantTypesValid,
			Status:  v1alpha1.ConditionFalse,
			Reason:  reasonMissingRequiredValue,
			Message: strings.Join(m, "; "),
		})
	}

	return conditions
}

// validateSecret checks if the client secret storage Secret is valid and contains at least one client secret.
// It returns the updated conditions slice along with the client secrets found in that case that it is valid.
func validateSecret(secret *v1.Secret, conditions []*v1alpha1.Condition) ([]*v1alpha1.Condition, []string) {
	emptyList := []string{}

	if secret == nil {
		// Invalid: no storage Secret found.
		conditions = append(conditions, &v1alpha1.Condition{
			Type:    clientSecretExists,
			Status:  v1alpha1.ConditionFalse,
			Reason:  reasonNoClientSecretFound,
			Message: "no client secret found (no Secret storage found)",
		})
		return conditions, emptyList
	}

	storedClientSecret, err := oidcclientsecretstorage.ReadFromSecret(secret)
	if err != nil {
		// Invalid: storage Secret exists but its data could not be parsed.
		conditions = append(conditions, &v1alpha1.Condition{
			Type:    clientSecretExists,
			Status:  v1alpha1.ConditionFalse,
			Reason:  reasonNoClientSecretFound,
			Message: fmt.Sprintf("error reading client secret storage: %s", err.Error()),
		})
		return conditions, emptyList
	}

	// Successfully read the stored client secrets, so check if there are any stored in the list.
	storedClientSecretsCount := len(storedClientSecret.SecretHashes)
	if storedClientSecretsCount == 0 {
		// Invalid: no client secrets stored.
		conditions = append(conditions, &v1alpha1.Condition{
			Type:    clientSecretExists,
			Status:  v1alpha1.ConditionFalse,
			Reason:  reasonNoClientSecretFound,
			Message: "no client secret found (empty list in storage)",
		})
		return conditions, emptyList
	}

	// Check each hashed password's format and bcrypt cost.
	bcryptErrs := make([]string, 0, storedClientSecretsCount)
	for i, p := range storedClientSecret.SecretHashes {
		cost, err := bcrypt.Cost([]byte(p))
		if err != nil {
			bcryptErrs = append(bcryptErrs, fmt.Sprintf(
				"hashed client secret at index %d: %s",
				i, err.Error()))
		} else if cost < minimumRequiredBcryptCost {
			bcryptErrs = append(bcryptErrs, fmt.Sprintf(
				"hashed client secret at index %d: bcrypt cost %d is below the required minimum of %d",
				i, cost, minimumRequiredBcryptCost))
		}
	}
	if len(bcryptErrs) > 0 {
		// Invalid: some stored client secrets were not valid.
		conditions = append(conditions, &v1alpha1.Condition{
			Type:   clientSecretExists,
			Status: v1alpha1.ConditionFalse,
			Reason: reasonInvalidClientSecretFound,
			Message: fmt.Sprintf("%d stored client secrets found, but some were invalid, so none will be used: %s",
				storedClientSecretsCount, strings.Join(bcryptErrs, "; ")),
		})
		return conditions, emptyList
	}

	// Valid: has at least one client secret stored for this OIDC client, and all stored client secrets are valid.
	conditions = append(conditions, &v1alpha1.Condition{
		Type:    clientSecretExists,
		Status:  v1alpha1.ConditionTrue,
		Reason:  reasonSuccess,
		Message: fmt.Sprintf("%d client secret(s) found", storedClientSecretsCount),
	})
	return conditions, storedClientSecret.SecretHashes
}

func allowedGrantTypesContains(haystack *v1alpha1.OIDCClient, needle string) bool {
	for _, hay := range haystack.Spec.AllowedGrantTypes {
		if hay == v1alpha1.GrantType(needle) {
			return true
		}
	}
	return false
}

func allowedScopesContains(haystack *v1alpha1.OIDCClient, needle string) bool {
	for _, hay := range haystack.Spec.AllowedScopes {
		if hay == v1alpha1.Scope(needle) {
			return true
		}
	}
	return false
}
