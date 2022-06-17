// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcclientwatcher

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"

	"go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	configInformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/config/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/conditionsutil"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/oidcclientsecretstorage"
	"go.pinniped.dev/internal/plog"
)

const (
	clientSecretExists     = "ClientSecretExists"
	allowedGrantTypesValid = "AllowedGrantTypesValid"
	allowedScopesValid     = "AllowedScopesValid"

	reasonSuccess              = "Success"
	reasonMissingRequiredValue = "MissingRequiredValue"
	reasonNoClientSecretFound  = "NoClientSecretFound"

	authorizationCodeGrantTypeName = "authorization_code"
	refreshTokenGrantTypeName      = "refresh_token"
	tokenExchangeGrantTypeName     = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // this is not a credential

	openidScopeName          = "openid"
	offlineAccessScopeName   = "offline_access"
	requestAudienceScopeName = "pinniped:request-audience"
	usernameScopeName        = "username"
	groupsScopeName          = "groups"

	allowedGrantTypesFieldName = "allowedGrantTypes"
	allowedScopesFieldName     = "allowedScopes"

	secretTypeToObserve = "storage.pinniped.dev/oidc-client-secret" //nolint:gosec // this is not a credential
)

type oidcClientWatcherController struct {
	pinnipedClient     pinnipedclientset.Interface
	oidcClientInformer configInformers.OIDCClientInformer
	secretInformer     corev1informers.SecretInformer
}

// NewOIDCClientWatcherController returns a controllerlib.Controller that watches OIDCClients and updates
// their status with validation errors.
func NewOIDCClientWatcherController(
	pinnipedClient pinnipedclientset.Interface,
	secretInformer corev1informers.SecretInformer,
	oidcClientInformer configInformers.OIDCClientInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "OIDCClientWatcherController",
			Syncer: &oidcClientWatcherController{
				pinnipedClient:     pinnipedClient,
				secretInformer:     secretInformer,
				oidcClientInformer: oidcClientInformer,
			},
		},
		// We want to be notified when an OIDCClient's corresponding secret gets updated or deleted.
		withInformer(
			secretInformer,
			pinnipedcontroller.MatchAnySecretOfTypeFilter(secretTypeToObserve, pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
		// We want to be notified when anything happens to an OIDCClient.
		withInformer(
			oidcClientInformer,
			pinnipedcontroller.MatchAnythingFilter(pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controllerlib.Syncer.
func (c *oidcClientWatcherController) Sync(ctx controllerlib.Context) error {
	// Sync could be called on either a Secret or an OIDCClient, so to keep it simple, revalidate
	// all OIDCClients whenever anything changes.
	oidcClients, err := c.oidcClientInformer.Lister().List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to list OIDCClients: %w", err)
	}

	// We're only going to use storage to call GetName(), which happens to not need the constructor params.
	// This is because we can read the Secrets from the informer cache here, instead of doing live reads.
	storage := oidcclientsecretstorage.New(nil, nil)

	for _, oidcClient := range oidcClients {
		correspondingSecretName := storage.GetName(oidcClient.UID)

		secret, err := c.secretInformer.Lister().Secrets(oidcClient.Namespace).Get(correspondingSecretName)
		if err != nil {
			if !k8serrors.IsNotFound(err) {
				// Anything other than a NotFound error is unexpected when reading from an informer.
				return fmt.Errorf("failed to get %s/%s secret: %w", oidcClient.Namespace, correspondingSecretName, err)
			}
			// Got a NotFound error, so continue. The Secret just doesn't exist yet, which is okay.
			plog.DebugErr(
				"OIDCClientWatcherController error getting storage Secret for OIDCClient's client secrets", err,
				"oidcClientName", oidcClient.Name,
				"oidcClientNamespace", oidcClient.Namespace,
				"secretName", correspondingSecretName,
			)
			secret = nil
		}

		conditions := validateOIDCClient(oidcClient, secret)

		if err := c.updateStatus(ctx.Context, oidcClient, conditions); err != nil {
			return fmt.Errorf("cannot update OIDCClient '%s/%s': %w", oidcClient.Namespace, oidcClient.Name, err)
		}

		plog.Debug(
			"OIDCClientWatcherController Sync updated an OIDCClient",
			"oidcClientName", oidcClient.Name,
			"oidcClientNamespace", oidcClient.Namespace,
			"conditionsCount", len(conditions),
		)
	}

	return nil
}

// validateOIDCClient validates the OIDCClient and its corresponding client secret storage Secret.
// When the corresponding client secret storage Secret was not found, pass nil to this function to
// get the validation error for that case.
func validateOIDCClient(oidcClient *v1alpha1.OIDCClient, secret *v1.Secret) []*v1alpha1.Condition {
	c := validateSecret(secret, []*v1alpha1.Condition{})
	c = validateAllowedGrantTypes(oidcClient, c)
	c = validateAllowedScopes(oidcClient, c)
	return c
}

// validateAllowedScopes checks if allowedScopes is valid on the OIDCClient.
func validateAllowedScopes(oidcClient *v1alpha1.OIDCClient, conditions []*v1alpha1.Condition) []*v1alpha1.Condition {
	switch {
	case !allowedScopesContains(oidcClient, openidScopeName):
		conditions = append(conditions, &v1alpha1.Condition{
			Type:    allowedScopesValid,
			Status:  v1alpha1.ConditionFalse,
			Reason:  reasonMissingRequiredValue,
			Message: fmt.Sprintf("%q must always be included in %q", openidScopeName, allowedScopesFieldName),
		})
	case allowedGrantTypesContains(oidcClient, refreshTokenGrantTypeName) && !allowedScopesContains(oidcClient, offlineAccessScopeName):
		conditions = append(conditions, &v1alpha1.Condition{
			Type:   allowedScopesValid,
			Status: v1alpha1.ConditionFalse,
			Reason: reasonMissingRequiredValue,
			Message: fmt.Sprintf("%q must be included in %q when %q is included in %q",
				offlineAccessScopeName, allowedScopesFieldName, refreshTokenGrantTypeName, allowedGrantTypesFieldName),
		})
	case allowedScopesContains(oidcClient, requestAudienceScopeName) &&
		(!allowedScopesContains(oidcClient, usernameScopeName) || !allowedScopesContains(oidcClient, groupsScopeName)):
		conditions = append(conditions, &v1alpha1.Condition{
			Type:   allowedScopesValid,
			Status: v1alpha1.ConditionFalse,
			Reason: reasonMissingRequiredValue,
			Message: fmt.Sprintf("%q and %q must be included in %q when %q is included in %q",
				usernameScopeName, groupsScopeName, allowedScopesFieldName, requestAudienceScopeName, allowedScopesFieldName),
		})
	case allowedGrantTypesContains(oidcClient, tokenExchangeGrantTypeName) && !allowedScopesContains(oidcClient, requestAudienceScopeName):
		conditions = append(conditions, &v1alpha1.Condition{
			Type:   allowedScopesValid,
			Status: v1alpha1.ConditionFalse,
			Reason: reasonMissingRequiredValue,
			Message: fmt.Sprintf("%q must be included in %q when %q is included in %q",
				requestAudienceScopeName, allowedScopesFieldName, tokenExchangeGrantTypeName, allowedGrantTypesFieldName),
		})
	default:
		conditions = append(conditions, &v1alpha1.Condition{
			Type:    allowedScopesValid,
			Status:  v1alpha1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: fmt.Sprintf("%q is valid", allowedScopesFieldName),
		})
	}
	return conditions
}

// validateAllowedGrantTypes checks if allowedGrantTypes is valid on the OIDCClient.
func validateAllowedGrantTypes(oidcClient *v1alpha1.OIDCClient, conditions []*v1alpha1.Condition) []*v1alpha1.Condition {
	switch {
	case !allowedGrantTypesContains(oidcClient, authorizationCodeGrantTypeName):
		conditions = append(conditions, &v1alpha1.Condition{
			Type:   allowedGrantTypesValid,
			Status: v1alpha1.ConditionFalse,
			Reason: reasonMissingRequiredValue,
			Message: fmt.Sprintf("%q must always be included in %q",
				authorizationCodeGrantTypeName, allowedGrantTypesFieldName),
		})
	case allowedScopesContains(oidcClient, offlineAccessScopeName) && !allowedGrantTypesContains(oidcClient, refreshTokenGrantTypeName):
		conditions = append(conditions, &v1alpha1.Condition{
			Type:   allowedGrantTypesValid,
			Status: v1alpha1.ConditionFalse,
			Reason: reasonMissingRequiredValue,
			Message: fmt.Sprintf("%q must be included in %q when %q is included in %q",
				refreshTokenGrantTypeName, allowedGrantTypesFieldName, offlineAccessScopeName, allowedScopesFieldName),
		})
	case allowedScopesContains(oidcClient, requestAudienceScopeName) && !allowedGrantTypesContains(oidcClient, tokenExchangeGrantTypeName):
		conditions = append(conditions, &v1alpha1.Condition{
			Type:   allowedGrantTypesValid,
			Status: v1alpha1.ConditionFalse,
			Reason: reasonMissingRequiredValue,
			Message: fmt.Sprintf("%q must be included in %q when %q is included in %q",
				tokenExchangeGrantTypeName, allowedGrantTypesFieldName, requestAudienceScopeName, allowedScopesFieldName),
		})
	default:
		conditions = append(conditions, &v1alpha1.Condition{
			Type:    allowedGrantTypesValid,
			Status:  v1alpha1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: fmt.Sprintf("%q is valid", allowedGrantTypesFieldName),
		})
	}
	return conditions
}

// validateSecret checks if the client secret storage Secret is valid and contains at least one client secret.
func validateSecret(secret *v1.Secret, conditions []*v1alpha1.Condition) []*v1alpha1.Condition {
	if secret == nil {
		// Invalid: no storage Secret found.
		conditions = append(conditions, &v1alpha1.Condition{
			Type:    clientSecretExists,
			Status:  v1alpha1.ConditionFalse,
			Reason:  reasonNoClientSecretFound,
			Message: "no client secret found (no Secret storage found)",
		})
		return conditions
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
		return conditions
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
	} else {
		// Valid: has at least one client secret stored for this OIDC client.
		conditions = append(conditions, &v1alpha1.Condition{
			Type:    clientSecretExists,
			Status:  v1alpha1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: fmt.Sprintf("%d client secret(s) found", storedClientSecretsCount),
		})
	}
	return conditions
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

func (c *oidcClientWatcherController) updateStatus(ctx context.Context, upstream *v1alpha1.OIDCClient, conditions []*v1alpha1.Condition) error {
	updated := upstream.DeepCopy()

	hadErrorCondition := conditionsutil.MergeConfigConditions(conditions, upstream.Generation, &updated.Status.Conditions, plog.New())

	updated.Status.Phase = v1alpha1.PhaseReady
	if hadErrorCondition {
		updated.Status.Phase = v1alpha1.PhaseError
	}

	if equality.Semantic.DeepEqual(upstream, updated) {
		return nil
	}

	_, err := c.pinnipedClient.
		ConfigV1alpha1().
		OIDCClients(upstream.Namespace).
		UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	return err
}
