// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcclientvalidator

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/controller/conditionsutil"
	"go.pinniped.dev/internal/oidcclientsecretstorage"
)

const (
	DefaultMinBcryptCost = 12

	clientSecretExists     = "ClientSecretExists"
	allowedGrantTypesValid = "AllowedGrantTypesValid"
	allowedScopesValid     = "AllowedScopesValid"

	reasonMissingRequiredValue     = "MissingRequiredValue"
	reasonNoClientSecretFound      = "NoClientSecretFound"
	reasonInvalidClientSecretFound = "InvalidClientSecretFound"

	allowedGrantTypesFieldName = "allowedGrantTypes"
	allowedScopesFieldName     = "allowedScopes"
)

// Validate validates the OIDCClient and its corresponding client secret storage Secret.
// When the corresponding client secret storage Secret was not found, pass nil to this function to
// get the validation error for that case. It returns a bool to indicate if the client is valid,
// along with a slice of conditions containing more details, and the list of client secrets in the
// case that the client was valid.
func Validate(oidcClient *supervisorconfigv1alpha1.OIDCClient, secret *corev1.Secret, minBcryptCost int) (bool, []*metav1.Condition, []string) {
	conds := make([]*metav1.Condition, 0, 3)

	conds, clientSecrets := validateSecret(secret, conds, minBcryptCost)
	conds = validateAllowedGrantTypes(oidcClient, conds)
	conds = validateAllowedScopes(oidcClient, conds)

	valid := true
	for _, cond := range conds {
		if cond.Status != metav1.ConditionTrue {
			valid = false
			break
		}
	}
	return valid, conds, clientSecrets
}

// validateAllowedScopes checks if allowedScopes is valid on the OIDCClient.
func validateAllowedScopes(oidcClient *supervisorconfigv1alpha1.OIDCClient, conditions []*metav1.Condition) []*metav1.Condition {
	m := make([]string, 0, 4)

	if !allowedScopesContains(oidcClient, oidcapi.ScopeOpenID) {
		m = append(m, fmt.Sprintf("%q must always be included in %q", oidcapi.ScopeOpenID, allowedScopesFieldName))
	}
	if allowedGrantTypesContains(oidcClient, oidcapi.GrantTypeRefreshToken) && !allowedScopesContains(oidcClient, oidcapi.ScopeOfflineAccess) {
		m = append(m, fmt.Sprintf("%q must be included in %q when %q is included in %q",
			oidcapi.ScopeOfflineAccess, allowedScopesFieldName, oidcapi.GrantTypeRefreshToken, allowedGrantTypesFieldName))
	}
	if allowedScopesContains(oidcClient, oidcapi.ScopeRequestAudience) &&
		(!allowedScopesContains(oidcClient, oidcapi.ScopeUsername) || !allowedScopesContains(oidcClient, oidcapi.ScopeGroups)) {
		m = append(m, fmt.Sprintf("%q and %q must be included in %q when %q is included in %q",
			oidcapi.ScopeUsername, oidcapi.ScopeGroups, allowedScopesFieldName, oidcapi.ScopeRequestAudience, allowedScopesFieldName))
	}
	if allowedGrantTypesContains(oidcClient, oidcapi.GrantTypeTokenExchange) && !allowedScopesContains(oidcClient, oidcapi.ScopeRequestAudience) {
		m = append(m, fmt.Sprintf("%q must be included in %q when %q is included in %q",
			oidcapi.ScopeRequestAudience, allowedScopesFieldName, oidcapi.GrantTypeTokenExchange, allowedGrantTypesFieldName))
	}

	if len(m) == 0 {
		conditions = append(conditions, &metav1.Condition{
			Type:    allowedScopesValid,
			Status:  metav1.ConditionTrue,
			Reason:  conditionsutil.ReasonSuccess,
			Message: fmt.Sprintf("%q is valid", allowedScopesFieldName),
		})
	} else {
		conditions = append(conditions, &metav1.Condition{
			Type:    allowedScopesValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonMissingRequiredValue,
			Message: strings.Join(m, "; "),
		})
	}

	return conditions
}

// validateAllowedGrantTypes checks if allowedGrantTypes is valid on the OIDCClient.
func validateAllowedGrantTypes(oidcClient *supervisorconfigv1alpha1.OIDCClient, conditions []*metav1.Condition) []*metav1.Condition {
	m := make([]string, 0, 3)

	if !allowedGrantTypesContains(oidcClient, oidcapi.GrantTypeAuthorizationCode) {
		m = append(m, fmt.Sprintf("%q must always be included in %q",
			oidcapi.GrantTypeAuthorizationCode, allowedGrantTypesFieldName))
	}
	if allowedScopesContains(oidcClient, oidcapi.ScopeOfflineAccess) && !allowedGrantTypesContains(oidcClient, oidcapi.GrantTypeRefreshToken) {
		m = append(m, fmt.Sprintf("%q must be included in %q when %q is included in %q",
			oidcapi.GrantTypeRefreshToken, allowedGrantTypesFieldName, oidcapi.ScopeOfflineAccess, allowedScopesFieldName))
	}
	if allowedScopesContains(oidcClient, oidcapi.ScopeRequestAudience) && !allowedGrantTypesContains(oidcClient, oidcapi.GrantTypeTokenExchange) {
		m = append(m, fmt.Sprintf("%q must be included in %q when %q is included in %q",
			oidcapi.GrantTypeTokenExchange, allowedGrantTypesFieldName, oidcapi.ScopeRequestAudience, allowedScopesFieldName))
	}

	if len(m) == 0 {
		conditions = append(conditions, &metav1.Condition{
			Type:    allowedGrantTypesValid,
			Status:  metav1.ConditionTrue,
			Reason:  conditionsutil.ReasonSuccess,
			Message: fmt.Sprintf("%q is valid", allowedGrantTypesFieldName),
		})
	} else {
		conditions = append(conditions, &metav1.Condition{
			Type:    allowedGrantTypesValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonMissingRequiredValue,
			Message: strings.Join(m, "; "),
		})
	}

	return conditions
}

// validateSecret checks if the client secret storage Secret is valid and contains at least one client secret.
// It returns the updated conditions slice along with the client secrets found in that case that it is valid.
func validateSecret(secret *corev1.Secret, conditions []*metav1.Condition, minBcryptCost int) ([]*metav1.Condition, []string) {
	emptyList := []string{}

	if secret == nil {
		// Invalid: no storage Secret found.
		conditions = append(conditions, &metav1.Condition{
			Type:    clientSecretExists,
			Status:  metav1.ConditionFalse,
			Reason:  reasonNoClientSecretFound,
			Message: "no client secret found (no Secret storage found)",
		})
		return conditions, emptyList
	}

	storedClientSecrets, err := oidcclientsecretstorage.ReadFromSecret(secret)
	if err != nil {
		// Invalid: storage Secret exists but its data could not be parsed.
		conditions = append(conditions, &metav1.Condition{
			Type:    clientSecretExists,
			Status:  metav1.ConditionFalse,
			Reason:  reasonNoClientSecretFound,
			Message: fmt.Sprintf("error reading client secret storage: %s", err.Error()),
		})
		return conditions, emptyList
	}

	// Successfully read the stored client secrets, so check if there are any stored in the list.
	storedClientSecretsCount := len(storedClientSecrets)
	if storedClientSecretsCount == 0 {
		// Invalid: no client secrets stored.
		conditions = append(conditions, &metav1.Condition{
			Type:    clientSecretExists,
			Status:  metav1.ConditionFalse,
			Reason:  reasonNoClientSecretFound,
			Message: "no client secret found (empty list in storage)",
		})
		return conditions, emptyList
	}

	// Check each hashed password's format and bcrypt cost.
	bcryptErrs := make([]string, 0, storedClientSecretsCount)
	for i, p := range storedClientSecrets {
		cost, err := bcrypt.Cost([]byte(p))
		if err != nil {
			bcryptErrs = append(bcryptErrs, fmt.Sprintf(
				"hashed client secret at index %d: %s",
				i, err.Error()))
		} else if cost < minBcryptCost {
			bcryptErrs = append(bcryptErrs, fmt.Sprintf(
				"hashed client secret at index %d: bcrypt cost %d is below the required minimum of %d",
				i, cost, minBcryptCost))
		}
	}
	if len(bcryptErrs) > 0 {
		// Invalid: some stored client secrets were not valid.
		conditions = append(conditions, &metav1.Condition{
			Type:   clientSecretExists,
			Status: metav1.ConditionFalse,
			Reason: reasonInvalidClientSecretFound,
			Message: fmt.Sprintf("%d stored client secrets found, but some were invalid, so none will be used: %s",
				storedClientSecretsCount, strings.Join(bcryptErrs, "; ")),
		})
		return conditions, emptyList
	}

	// Valid: has at least one client secret stored for this OIDC client, and all stored client secrets are valid.
	conditions = append(conditions, &metav1.Condition{
		Type:    clientSecretExists,
		Status:  metav1.ConditionTrue,
		Reason:  conditionsutil.ReasonSuccess,
		Message: fmt.Sprintf("%d client secret(s) found", storedClientSecretsCount),
	})
	return conditions, storedClientSecrets
}

func allowedGrantTypesContains(haystack *supervisorconfigv1alpha1.OIDCClient, needle string) bool {
	for _, hay := range haystack.Spec.AllowedGrantTypes {
		if hay == supervisorconfigv1alpha1.GrantType(needle) {
			return true
		}
	}
	return false
}

func allowedScopesContains(haystack *supervisorconfigv1alpha1.OIDCClient, needle string) bool {
	for _, hay := range haystack.Spec.AllowedScopes {
		if hay == supervisorconfigv1alpha1.Scope(needle) {
			return true
		}
	}
	return false
}
