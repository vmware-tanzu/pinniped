// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	errorsutil "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/clock"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	configinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/config/v1alpha1"
	idpinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/idp/v1alpha1"
	"go.pinniped.dev/internal/celtransformer"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/conditionsutil"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/federationdomain/federationdomainproviders"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/plog"
)

const (
	typeReady                                = "Ready"
	typeIssuerURLValid                       = "IssuerURLValid"
	typeOneTLSSecretPerIssuerHostname        = "OneTLSSecretPerIssuerHostname"
	typeIssuerIsUnique                       = "IssuerIsUnique"
	typeIdentityProvidersFound               = "IdentityProvidersFound"
	typeIdentityProvidersDisplayNamesUnique  = "IdentityProvidersDisplayNamesUnique"
	typeIdentityProvidersAPIGroupSuffixValid = "IdentityProvidersObjectRefAPIGroupSuffixValid"
	typeIdentityProvidersObjectRefKindValid  = "IdentityProvidersObjectRefKindValid"
	typeTransformsConstantsNamesUnique       = "TransformsConstantsNamesUnique"
	typeTransformsExpressionsValid           = "TransformsExpressionsValid"
	typeTransformsExamplesPassed             = "TransformsExamplesPassed"

	reasonSuccess                                     = "Success"
	reasonNotReady                                    = "NotReady"
	reasonUnableToValidate                            = "UnableToValidate"
	reasonInvalidIssuerURL                            = "InvalidIssuerURL"
	reasonDuplicateIssuer                             = "DuplicateIssuer"
	reasonDifferentSecretRefsFound                    = "DifferentSecretRefsFound"
	reasonLegacyConfigurationSuccess                  = "LegacyConfigurationSuccess"
	reasonLegacyConfigurationIdentityProviderNotFound = "LegacyConfigurationIdentityProviderNotFound"
	reasonIdentityProvidersObjectRefsNotFound         = "IdentityProvidersObjectRefsNotFound"
	reasonIdentityProviderNotSpecified                = "IdentityProviderNotSpecified"
	reasonDuplicateDisplayNames                       = "DuplicateDisplayNames"
	reasonAPIGroupNameUnrecognized                    = "APIGroupUnrecognized"
	reasonKindUnrecognized                            = "KindUnrecognized"
	reasonDuplicateConstantsNames                     = "DuplicateConstantsNames"
	reasonInvalidTransformsExpressions                = "InvalidTransformsExpressions"
	reasonTransformsExamplesFailed                    = "TransformsExamplesFailed"

	kindLDAPIdentityProvider            = "LDAPIdentityProvider"
	kindOIDCIdentityProvider            = "OIDCIdentityProvider"
	kindActiveDirectoryIdentityProvider = "ActiveDirectoryIdentityProvider"

	celTransformerMaxExpressionRuntime = 5 * time.Second
)

// FederationDomainsSetter can be notified of all known valid providers with its SetFederationDomains function.
// If there are no longer any valid issuers, then it can be called with no arguments.
// Implementations of this type should be thread-safe to support calls from multiple goroutines.
type FederationDomainsSetter interface {
	SetFederationDomains(federationDomains ...*federationdomainproviders.FederationDomainIssuer)
}

type federationDomainWatcherController struct {
	federationDomainsSetter FederationDomainsSetter
	apiGroup                string
	clock                   clock.Clock
	client                  pinnipedclientset.Interface

	federationDomainInformer                configinformers.FederationDomainInformer
	oidcIdentityProviderInformer            idpinformers.OIDCIdentityProviderInformer
	ldapIdentityProviderInformer            idpinformers.LDAPIdentityProviderInformer
	activeDirectoryIdentityProviderInformer idpinformers.ActiveDirectoryIdentityProviderInformer

	celTransformer *celtransformer.CELTransformer
	allowedKinds   sets.Set[string]
}

// NewFederationDomainWatcherController creates a controllerlib.Controller that watches
// FederationDomain objects and notifies a callback object of the collection of provider configs.
func NewFederationDomainWatcherController(
	federationDomainsSetter FederationDomainsSetter,
	apiGroupSuffix string,
	clock clock.Clock,
	client pinnipedclientset.Interface,
	federationDomainInformer configinformers.FederationDomainInformer,
	oidcIdentityProviderInformer idpinformers.OIDCIdentityProviderInformer,
	ldapIdentityProviderInformer idpinformers.LDAPIdentityProviderInformer,
	activeDirectoryIdentityProviderInformer idpinformers.ActiveDirectoryIdentityProviderInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	allowedKinds := sets.New(kindActiveDirectoryIdentityProvider, kindLDAPIdentityProvider, kindOIDCIdentityProvider)
	return controllerlib.New(
		controllerlib.Config{
			Name: "FederationDomainWatcherController",
			Syncer: &federationDomainWatcherController{
				federationDomainsSetter:                 federationDomainsSetter,
				apiGroup:                                fmt.Sprintf("idp.supervisor.%s", apiGroupSuffix),
				clock:                                   clock,
				client:                                  client,
				federationDomainInformer:                federationDomainInformer,
				oidcIdentityProviderInformer:            oidcIdentityProviderInformer,
				ldapIdentityProviderInformer:            ldapIdentityProviderInformer,
				activeDirectoryIdentityProviderInformer: activeDirectoryIdentityProviderInformer,
				allowedKinds:                            allowedKinds,
			},
		},
		withInformer(
			federationDomainInformer,
			pinnipedcontroller.MatchAnythingFilter(pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
		withInformer(
			oidcIdentityProviderInformer,
			// Since this controller only cares about IDP metadata names and UIDs (immutable fields),
			// we only need to trigger Sync on creates and deletes.
			pinnipedcontroller.MatchAnythingIgnoringUpdatesFilter(pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
		withInformer(
			ldapIdentityProviderInformer,
			// Since this controller only cares about IDP metadata names and UIDs (immutable fields),
			// we only need to trigger Sync on creates and deletes.
			pinnipedcontroller.MatchAnythingIgnoringUpdatesFilter(pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
		withInformer(
			activeDirectoryIdentityProviderInformer,
			// Since this controller only cares about IDP metadata names and UIDs (immutable fields),
			// we only need to trigger Sync on creates and deletes.
			pinnipedcontroller.MatchAnythingIgnoringUpdatesFilter(pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controllerlib.Syncer.
func (c *federationDomainWatcherController) Sync(ctx controllerlib.Context) error {
	federationDomains, err := c.federationDomainInformer.Lister().List(labels.Everything())
	if err != nil {
		return err
	}

	if c.celTransformer == nil {
		c.celTransformer, err = celtransformer.NewCELTransformer(celTransformerMaxExpressionRuntime)
		if err != nil {
			return err // shouldn't really happen
		}
	}

	// Process each FederationDomain to validate its spec and to turn it into a FederationDomainIssuer.
	federationDomainIssuers, fdToConditionsMap, err := c.processAllFederationDomains(ctx.Context, federationDomains)
	if err != nil {
		return err
	}

	// Load the endpoints of every valid FederationDomain. Removes the endpoints of any
	// previous FederationDomains which no longer exist or are no longer valid.
	c.federationDomainsSetter.SetFederationDomains(federationDomainIssuers...)

	// Now that the endpoints of every valid FederationDomain are available, update the
	// statuses. This allows clients to wait for Ready without any race conditions in the
	// endpoints being available.
	var errs []error
	for federationDomain, conditions := range fdToConditionsMap {
		if err = c.updateStatus(ctx.Context, federationDomain, conditions); err != nil {
			errs = append(errs, fmt.Errorf("could not update status: %w", err))
		}
	}

	return errorsutil.NewAggregate(errs)
}

func (c *federationDomainWatcherController) processAllFederationDomains(
	ctx context.Context,
	federationDomains []*configv1alpha1.FederationDomain,
) ([]*federationdomainproviders.FederationDomainIssuer, map[*configv1alpha1.FederationDomain][]*configv1alpha1.Condition, error) {
	federationDomainIssuers := make([]*federationdomainproviders.FederationDomainIssuer, 0)
	fdToConditionsMap := map[*configv1alpha1.FederationDomain][]*configv1alpha1.Condition{}
	crossDomainConfigValidator := newCrossFederationDomainConfigValidator(federationDomains)

	for _, federationDomain := range federationDomains {
		conditions := make([]*configv1alpha1.Condition, 0)

		conditions = crossDomainConfigValidator.Validate(federationDomain, conditions)

		federationDomainIssuer, conditions, err := c.makeFederationDomainIssuer(ctx, federationDomain, conditions)
		if err != nil {
			return nil, nil, err
		}

		// Now that we have determined the conditions, save them for after the loop.
		// For a valid FederationDomain, want to update the conditions after we have
		// made the FederationDomain's endpoints available.
		fdToConditionsMap[federationDomain] = conditions

		if !hadErrorCondition(conditions) {
			// Successfully validated the FederationDomain, so allow it to be loaded.
			federationDomainIssuers = append(federationDomainIssuers, federationDomainIssuer)
		}
	}

	return federationDomainIssuers, fdToConditionsMap, nil
}

func (c *federationDomainWatcherController) makeFederationDomainIssuer(
	ctx context.Context,
	federationDomain *configv1alpha1.FederationDomain,
	conditions []*configv1alpha1.Condition,
) (*federationdomainproviders.FederationDomainIssuer, []*configv1alpha1.Condition, error) {
	var err error
	// Create the list of IDPs for this FederationDomain.
	// Don't worry if the IDP CRs themselves is phase=Ready because those which are not ready will not be loaded
	// into the provider cache, so they cannot actually be used to authenticate.
	var federationDomainIssuer *federationdomainproviders.FederationDomainIssuer
	if len(federationDomain.Spec.IdentityProviders) == 0 {
		federationDomainIssuer, conditions, err = c.makeLegacyFederationDomainIssuer(federationDomain, conditions)
		if err != nil {
			return nil, nil, err
		}
	} else {
		federationDomainIssuer, conditions, err = c.makeFederationDomainIssuerWithExplicitIDPs(ctx, federationDomain, conditions)
		if err != nil {
			return nil, nil, err
		}
	}

	return federationDomainIssuer, conditions, nil
}

func (c *federationDomainWatcherController) makeLegacyFederationDomainIssuer(
	federationDomain *configv1alpha1.FederationDomain,
	conditions []*configv1alpha1.Condition,
) (*federationdomainproviders.FederationDomainIssuer, []*configv1alpha1.Condition, error) {
	var defaultFederationDomainIdentityProvider *federationdomainproviders.FederationDomainIdentityProvider

	// When the FederationDomain does not list any IDPs, then we might be in backwards compatibility mode.
	oidcIdentityProviders, err := c.oidcIdentityProviderInformer.Lister().List(labels.Everything())
	if err != nil {
		return nil, nil, err
	}
	ldapIdentityProviders, err := c.ldapIdentityProviderInformer.Lister().List(labels.Everything())
	if err != nil {
		return nil, nil, err
	}
	activeDirectoryIdentityProviders, err := c.activeDirectoryIdentityProviderInformer.Lister().List(labels.Everything())
	if err != nil {
		return nil, nil, err
	}

	// Check if that there is exactly one IDP defined in the Supervisor namespace of any IDP CRD type.
	idpCRsCount := len(oidcIdentityProviders) + len(ldapIdentityProviders) + len(activeDirectoryIdentityProviders)

	switch {
	case idpCRsCount == 1:
		foundIDPName := ""
		// If so, default that IDP's DisplayName to be the same as its resource Name.
		defaultFederationDomainIdentityProvider = &federationdomainproviders.FederationDomainIdentityProvider{}
		switch {
		case len(oidcIdentityProviders) == 1:
			defaultFederationDomainIdentityProvider.DisplayName = oidcIdentityProviders[0].Name
			defaultFederationDomainIdentityProvider.UID = oidcIdentityProviders[0].UID
			foundIDPName = oidcIdentityProviders[0].Name
		case len(ldapIdentityProviders) == 1:
			defaultFederationDomainIdentityProvider.DisplayName = ldapIdentityProviders[0].Name
			defaultFederationDomainIdentityProvider.UID = ldapIdentityProviders[0].UID
			foundIDPName = ldapIdentityProviders[0].Name
		case len(activeDirectoryIdentityProviders) == 1:
			defaultFederationDomainIdentityProvider.DisplayName = activeDirectoryIdentityProviders[0].Name
			defaultFederationDomainIdentityProvider.UID = activeDirectoryIdentityProviders[0].UID
			foundIDPName = activeDirectoryIdentityProviders[0].Name
		}
		// Backwards compatibility mode always uses an empty identity transformation pipeline since no
		// transformations are defined on the FederationDomain.
		defaultFederationDomainIdentityProvider.Transforms = idtransform.NewTransformationPipeline()
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:   typeIdentityProvidersFound,
			Status: configv1alpha1.ConditionTrue,
			Reason: reasonLegacyConfigurationSuccess,
			Message: fmt.Sprintf("no resources were specified by .spec.identityProviders[].objectRef but exactly one "+
				"identity provider resource has been found: using %q as "+
				"identity provider: please explicitly list identity providers in .spec.identityProviders "+
				"(this legacy configuration mode may be removed in a future version of Pinniped)", foundIDPName),
		})
	case idpCRsCount > 1:
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:   typeIdentityProvidersFound,
			Status: configv1alpha1.ConditionFalse,
			Reason: reasonIdentityProviderNotSpecified, // vs LegacyConfigurationIdentityProviderNotFound as this is more specific
			Message: fmt.Sprintf("no resources were specified by .spec.identityProviders[].objectRef "+
				"and %q identity provider resources have been found: "+
				"please update .spec.identityProviders to specify which identity providers "+
				"this federation domain should use", idpCRsCount),
		})
	default:
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:   typeIdentityProvidersFound,
			Status: configv1alpha1.ConditionFalse,
			Reason: reasonLegacyConfigurationIdentityProviderNotFound,
			Message: "no resources were specified by .spec.identityProviders[].objectRef and no identity provider " +
				"resources have been found: please create an identity provider resource",
		})
	}

	// This is the constructor for the legacy backwards compatibility mode.
	federationDomainIssuer, err := federationdomainproviders.NewFederationDomainIssuerWithDefaultIDP(federationDomain.Spec.Issuer, defaultFederationDomainIdentityProvider)
	conditions = appendIssuerURLValidCondition(err, conditions)

	// These conditions can only have errors when the list of IDPs is explicitly configured,
	// and in this case there are no IDPs explicitly configured, so set these conditions all to have no errors.
	conditions = appendIdentityProviderDuplicateDisplayNamesCondition(sets.Set[string]{}, conditions)
	conditions = appendIdentityProviderObjectRefAPIGroupSuffixCondition(c.apiGroup, []string{}, conditions)
	conditions = appendIdentityProviderObjectRefKindCondition(c.sortedAllowedKinds(), []string{}, conditions)
	conditions = appendTransformsConstantsNamesUniqueCondition(sets.Set[string]{}, conditions)
	conditions = appendTransformsExpressionsValidCondition([]string{}, conditions)
	conditions = appendTransformsExamplesPassedCondition([]string{}, conditions)

	return federationDomainIssuer, conditions, nil
}

//nolint:funlen
func (c *federationDomainWatcherController) makeFederationDomainIssuerWithExplicitIDPs(
	ctx context.Context,
	federationDomain *configv1alpha1.FederationDomain,
	conditions []*configv1alpha1.Condition,
) (*federationdomainproviders.FederationDomainIssuer, []*configv1alpha1.Condition, error) {
	federationDomainIdentityProviders := []*federationdomainproviders.FederationDomainIdentityProvider{}
	idpNotFoundIndices := []int{}
	displayNames := sets.Set[string]{}
	duplicateDisplayNames := sets.Set[string]{}
	badAPIGroupNames := []string{}
	badKinds := []string{}

	for index, idp := range federationDomain.Spec.IdentityProviders {
		idpIsValid := true

		// The CRD requires the displayName field, and validates that it has at least one character,
		// so here we only need to validate that they are unique.
		if displayNames.Has(idp.DisplayName) {
			duplicateDisplayNames.Insert(idp.DisplayName)
			idpIsValid = false
		}
		displayNames.Insert(idp.DisplayName)

		// The objectRef is a required field in the CRD, so it will always exist in practice.
		// objectRef.name and objectRef.kind are required, but may be empty strings.
		// objectRef.apiGroup is not required, however, so it may be nil or empty string.
		canTryToFindIDP := true
		apiGroup := ""
		if idp.ObjectRef.APIGroup != nil {
			apiGroup = *idp.ObjectRef.APIGroup
		}
		if apiGroup != c.apiGroup {
			badAPIGroupNames = append(badAPIGroupNames, apiGroup)
			canTryToFindIDP = false
		}
		if !c.allowedKinds.Has(idp.ObjectRef.Kind) {
			badKinds = append(badKinds, idp.ObjectRef.Kind)
			canTryToFindIDP = false
		}

		// When the apiGroup and kind are valid, try to find the IDP CR.
		var idpResourceUID types.UID
		idpWasFound := false
		if canTryToFindIDP {
			var err error
			// Validate that each objectRef resolves to an existing IDP. It does not matter if the IDP itself
			// is phase=Ready, because it will not be loaded into the cache if not ready. For each objectRef
			// that does not resolve, put an error on the FederationDomain status.
			idpResourceUID, idpWasFound, err = c.findIDPsUIDByObjectRef(idp.ObjectRef, federationDomain.Namespace)
			if err != nil {
				return nil, nil, err
			}
		}
		if !canTryToFindIDP || !idpWasFound {
			idpNotFoundIndices = append(idpNotFoundIndices, index)
			idpIsValid = false
		}

		var err error
		var pipeline *idtransform.TransformationPipeline
		var allExamplesPassed bool
		pipeline, allExamplesPassed, conditions, err = c.makeTransformationPipelineAndEvaluateExamplesForIdentityProvider(ctx, idp, index, conditions)
		if err != nil {
			return nil, nil, err
		}
		if !allExamplesPassed {
			idpIsValid = false
		}

		if !idpIsValid {
			// Something about the IDP was not valid. Don't add it.
			continue
		}

		// For a valid IDP (unique displayName, valid objectRef, valid transforms), add it to the list.
		federationDomainIdentityProviders = append(federationDomainIdentityProviders, &federationdomainproviders.FederationDomainIdentityProvider{
			DisplayName: idp.DisplayName,
			UID:         idpResourceUID,
			Transforms:  pipeline,
		})
	}

	if len(idpNotFoundIndices) != 0 {
		msgs := []string{}
		for _, idpNotFoundIndex := range idpNotFoundIndices {
			msgs = append(msgs, fmt.Sprintf(".spec.identityProviders[%d] with displayName %q", idpNotFoundIndex,
				federationDomain.Spec.IdentityProviders[idpNotFoundIndex].DisplayName))
		}
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:   typeIdentityProvidersFound,
			Status: configv1alpha1.ConditionFalse,
			Reason: reasonIdentityProvidersObjectRefsNotFound,
			Message: fmt.Sprintf(".spec.identityProviders[].objectRef identifies resource(s) that cannot be found: %s",
				strings.Join(msgs, ", ")),
		})
	} else if len(federationDomain.Spec.IdentityProviders) != 0 {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeIdentityProvidersFound,
			Status:  configv1alpha1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: "the resources specified by .spec.identityProviders[].objectRef were found",
		})
	}

	// This is the constructor for any case other than the legacy case, including when there is an empty list of IDPs.
	federationDomainIssuer, err := federationdomainproviders.NewFederationDomainIssuer(federationDomain.Spec.Issuer, federationDomainIdentityProviders)
	conditions = appendIssuerURLValidCondition(err, conditions)

	conditions = appendIdentityProviderDuplicateDisplayNamesCondition(duplicateDisplayNames, conditions)
	conditions = appendIdentityProviderObjectRefAPIGroupSuffixCondition(c.apiGroup, badAPIGroupNames, conditions)
	conditions = appendIdentityProviderObjectRefKindCondition(c.sortedAllowedKinds(), badKinds, conditions)

	return federationDomainIssuer, conditions, nil
}
func (c *federationDomainWatcherController) findIDPsUIDByObjectRef(objectRef corev1.TypedLocalObjectReference, namespace string) (types.UID, bool, error) {
	var idpResourceUID types.UID
	var foundIDP metav1.Object
	var err error

	switch objectRef.Kind {
	case kindLDAPIdentityProvider:
		foundIDP, err = c.ldapIdentityProviderInformer.Lister().LDAPIdentityProviders(namespace).Get(objectRef.Name)
	case kindActiveDirectoryIdentityProvider:
		foundIDP, err = c.activeDirectoryIdentityProviderInformer.Lister().ActiveDirectoryIdentityProviders(namespace).Get(objectRef.Name)
	case kindOIDCIdentityProvider:
		foundIDP, err = c.oidcIdentityProviderInformer.Lister().OIDCIdentityProviders(namespace).Get(objectRef.Name)
	default:
		// This shouldn't happen because this helper function is not called when the kind is invalid.
		return "", false, fmt.Errorf("unexpected kind: %s", objectRef.Kind)
	}

	switch {
	case err == nil:
		idpResourceUID = foundIDP.GetUID()
	case errors.IsNotFound(err):
		return "", false, nil
	default:
		return "", false, err // unexpected error from the informer
	}
	return idpResourceUID, true, nil
}

func (c *federationDomainWatcherController) makeTransformationPipelineAndEvaluateExamplesForIdentityProvider(
	ctx context.Context,
	idp configv1alpha1.FederationDomainIdentityProvider,
	idpIndex int,
	conditions []*configv1alpha1.Condition,
) (*idtransform.TransformationPipeline, bool, []*configv1alpha1.Condition, error) {
	consts, conditions, err := c.makeTransformsConstants(idp, conditions)
	if err != nil {
		return nil, false, nil, err
	}

	pipeline, conditions, err := c.makeTransformationPipeline(idp, idpIndex, consts, conditions)
	if err != nil {
		return nil, false, nil, err
	}

	allExamplesPassed, conditions := c.evaluateExamples(ctx, idp, idpIndex, pipeline, conditions)

	return pipeline, allExamplesPassed, conditions, nil
}

func (c *federationDomainWatcherController) makeTransformsConstants(
	idp configv1alpha1.FederationDomainIdentityProvider,
	conditions []*configv1alpha1.Condition,
) (*celtransformer.TransformationConstants, []*configv1alpha1.Condition, error) {
	consts := &celtransformer.TransformationConstants{
		StringConstants:     map[string]string{},
		StringListConstants: map[string][]string{},
	}
	constNames := sets.Set[string]{}
	duplicateConstNames := sets.Set[string]{}

	// Read all the declared constants.
	for _, constant := range idp.Transforms.Constants {
		// The CRD requires the name field, and validates that it has at least one character,
		// so here we only need to validate that they are unique.
		if constNames.Has(constant.Name) {
			duplicateConstNames.Insert(constant.Name)
		}
		constNames.Insert(constant.Name)
		switch constant.Type {
		case "string":
			consts.StringConstants[constant.Name] = constant.StringValue
		case "stringList":
			consts.StringListConstants[constant.Name] = constant.StringListValue
		default:
			// This shouldn't really happen since the CRD validates it, but handle it as an error.
			return nil, nil, fmt.Errorf("one of spec.identityProvider[].transforms.constants[].type is invalid: %q", constant.Type)
		}
	}

	conditions = appendTransformsConstantsNamesUniqueCondition(duplicateConstNames, conditions)

	return consts, conditions, nil
}

func (c *federationDomainWatcherController) makeTransformationPipeline(
	idp configv1alpha1.FederationDomainIdentityProvider,
	idpIndex int,
	consts *celtransformer.TransformationConstants,
	conditions []*configv1alpha1.Condition,
) (*idtransform.TransformationPipeline, []*configv1alpha1.Condition, error) {
	pipeline := idtransform.NewTransformationPipeline()
	expressionsCompileErrors := []string{}

	// Compile all the expressions and add them to the pipeline.
	for exprIndex, expr := range idp.Transforms.Expressions {
		var rawTransform celtransformer.CELTransformation
		switch expr.Type {
		case "username/v1":
			rawTransform = &celtransformer.UsernameTransformation{Expression: expr.Expression}
		case "groups/v1":
			rawTransform = &celtransformer.GroupsTransformation{Expression: expr.Expression}
		case "policy/v1":
			rawTransform = &celtransformer.AllowAuthenticationPolicy{
				Expression:                    expr.Expression,
				RejectedAuthenticationMessage: expr.Message,
			}
		default:
			// This shouldn't really happen since the CRD validates it, but handle it as an error.
			return nil, nil, fmt.Errorf("one of spec.identityProvider[].transforms.expressions[].type is invalid: %q", expr.Type)
		}

		compiledTransform, err := c.celTransformer.CompileTransformation(rawTransform, consts)
		if err != nil {
			expressionsCompileErrors = append(expressionsCompileErrors,
				fmt.Sprintf("spec.identityProvider[%d].transforms.expressions[%d].expression was invalid:\n%s",
					idpIndex, exprIndex, err.Error()))
		}

		pipeline.AppendTransformation(compiledTransform)
	}

	conditions = appendTransformsExpressionsValidCondition(expressionsCompileErrors, conditions)

	if len(expressionsCompileErrors) > 0 {
		// One or more of the expressions did not compile, so we don't have a useful pipeline to return.
		return nil, conditions, nil
	}

	return pipeline, conditions, nil
}

func (c *federationDomainWatcherController) evaluateExamples(
	ctx context.Context,
	idp configv1alpha1.FederationDomainIdentityProvider,
	idpIndex int,
	pipeline *idtransform.TransformationPipeline,
	conditions []*configv1alpha1.Condition,
) (bool, []*configv1alpha1.Condition) {
	const errorFmt = ".spec.identityProviders[%d].transforms.examples[%d] example failed:\nexpected: %s\nactual:   %s"
	examplesErrors := []string{}

	if pipeline == nil {
		// Unable to evaluate the conditions where the pipeline of expressions was invalid.
		conditions = appendTransformsExamplesPassedCondition(nil, conditions)
		return false, conditions
	}

	// Run all the provided transform examples. If any fail, put errors on the FederationDomain status.
	for exIndex, e := range idp.Transforms.Examples {
		result, err := pipeline.Evaluate(ctx, e.Username, e.Groups)
		if err != nil {
			examplesErrors = append(examplesErrors, fmt.Sprintf(errorFmt, idpIndex, exIndex,
				"no transformation errors",
				fmt.Sprintf("transformations resulted in an unexpected error %q", err.Error())))
			continue
		}
		resultWasAuthRejected := !result.AuthenticationAllowed

		if e.Expects.Rejected && !resultWasAuthRejected {
			examplesErrors = append(examplesErrors,
				fmt.Sprintf(errorFmt, idpIndex, exIndex, "authentication to be rejected", "authentication was not rejected"))
			continue
		}

		if !e.Expects.Rejected && resultWasAuthRejected {
			examplesErrors = append(examplesErrors, fmt.Sprintf(errorFmt, idpIndex, exIndex,
				"authentication not to be rejected",
				fmt.Sprintf("authentication was rejected with message %q", result.RejectedAuthenticationMessage)))
			continue
		}

		expectedRejectionMessage := e.Expects.Message
		if len(expectedRejectionMessage) == 0 {
			expectedRejectionMessage = celtransformer.DefaultPolicyRejectedAuthMessage
		}
		if e.Expects.Rejected && resultWasAuthRejected && expectedRejectionMessage != result.RejectedAuthenticationMessage {
			examplesErrors = append(examplesErrors, fmt.Sprintf(errorFmt, idpIndex, exIndex,
				fmt.Sprintf("authentication rejection message %q", expectedRejectionMessage),
				fmt.Sprintf("authentication rejection message %q", result.RejectedAuthenticationMessage)))
			continue
		}

		if result.AuthenticationAllowed {
			// In the case where the user expected the auth to be allowed and it was allowed, then compare
			// the expected username and group names to the actual username and group names.
			if e.Expects.Username != result.Username {
				examplesErrors = append(examplesErrors, fmt.Sprintf(errorFmt, idpIndex, exIndex,
					fmt.Sprintf("username %q", e.Expects.Username),
					fmt.Sprintf("username %q", result.Username)))
			}
			expectedGroups := e.Expects.Groups
			if expectedGroups == nil {
				expectedGroups = []string{}
			}
			if !stringSetsEqual(expectedGroups, result.Groups) {
				examplesErrors = append(examplesErrors, fmt.Sprintf(errorFmt, idpIndex, exIndex,
					fmt.Sprintf("groups [%s]", strings.Join(sortAndQuote(expectedGroups), ", ")),
					fmt.Sprintf("groups [%s]", strings.Join(sortAndQuote(result.Groups), ", "))))
			}
		}
	}

	conditions = appendTransformsExamplesPassedCondition(examplesErrors, conditions)

	return len(examplesErrors) == 0, conditions
}

func (c *federationDomainWatcherController) sortedAllowedKinds() []string {
	return sortAndQuote(c.allowedKinds.UnsortedList())
}

func appendIdentityProviderObjectRefKindCondition(expectedKinds []string, badSuffixNames []string, conditions []*configv1alpha1.Condition) []*configv1alpha1.Condition {
	if len(badSuffixNames) > 0 {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:   typeIdentityProvidersObjectRefKindValid,
			Status: configv1alpha1.ConditionFalse,
			Reason: reasonKindUnrecognized,
			Message: fmt.Sprintf("the kinds specified by .spec.identityProviders[].objectRef.kind are not recognized (should be one of %s): %s",
				strings.Join(expectedKinds, ", "), strings.Join(sortAndQuote(badSuffixNames), ", ")),
		})
	} else {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeIdentityProvidersObjectRefKindValid,
			Status:  configv1alpha1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: "the kinds specified by .spec.identityProviders[].objectRef.kind are recognized",
		})
	}
	return conditions
}

func appendIdentityProviderObjectRefAPIGroupSuffixCondition(expectedSuffixName string, badSuffixNames []string, conditions []*configv1alpha1.Condition) []*configv1alpha1.Condition {
	if len(badSuffixNames) > 0 {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:   typeIdentityProvidersAPIGroupSuffixValid,
			Status: configv1alpha1.ConditionFalse,
			Reason: reasonAPIGroupNameUnrecognized,
			Message: fmt.Sprintf("the API groups specified by .spec.identityProviders[].objectRef.apiGroup are not recognized (should be %q): %s",
				expectedSuffixName, strings.Join(sortAndQuote(badSuffixNames), ", ")),
		})
	} else {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeIdentityProvidersAPIGroupSuffixValid,
			Status:  configv1alpha1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: "the API groups specified by .spec.identityProviders[].objectRef.apiGroup are recognized",
		})
	}
	return conditions
}

func appendTransformsExpressionsValidCondition(errors []string, conditions []*configv1alpha1.Condition) []*configv1alpha1.Condition {
	if len(errors) > 0 {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:   typeTransformsExpressionsValid,
			Status: configv1alpha1.ConditionFalse,
			Reason: reasonInvalidTransformsExpressions,
			Message: fmt.Sprintf("the expressions specified by .spec.identityProviders[].transforms.expressions[] were invalid:\n\n%s",
				strings.Join(errors, "\n\n")),
		})
	} else {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeTransformsExpressionsValid,
			Status:  configv1alpha1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: "the expressions specified by .spec.identityProviders[].transforms.expressions[] are valid",
		})
	}
	return conditions
}

func appendTransformsExamplesPassedCondition(errors []string, conditions []*configv1alpha1.Condition) []*configv1alpha1.Condition {
	switch {
	case errors == nil:
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeTransformsExamplesPassed,
			Status:  configv1alpha1.ConditionUnknown,
			Reason:  reasonUnableToValidate,
			Message: "unable to check if the examples specified by .spec.identityProviders[].transforms.examples[] had errors because an expression was invalid",
		})
	case len(errors) > 0:
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:   typeTransformsExamplesPassed,
			Status: configv1alpha1.ConditionFalse,
			Reason: reasonTransformsExamplesFailed,
			Message: fmt.Sprintf("the examples specified by .spec.identityProviders[].transforms.examples[] had errors:\n\n%s",
				strings.Join(errors, "\n\n")),
		})
	default:
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeTransformsExamplesPassed,
			Status:  configv1alpha1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: "the examples specified by .spec.identityProviders[].transforms.examples[] had no errors",
		})
	}
	return conditions
}

func appendIdentityProviderDuplicateDisplayNamesCondition(duplicateDisplayNames sets.Set[string], conditions []*configv1alpha1.Condition) []*configv1alpha1.Condition {
	if duplicateDisplayNames.Len() > 0 {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:   typeIdentityProvidersDisplayNamesUnique,
			Status: configv1alpha1.ConditionFalse,
			Reason: reasonDuplicateDisplayNames,
			Message: fmt.Sprintf("the names specified by .spec.identityProviders[].displayName contain duplicates: %s",
				strings.Join(sortAndQuote(duplicateDisplayNames.UnsortedList()), ", ")),
		})
	} else {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeIdentityProvidersDisplayNamesUnique,
			Status:  configv1alpha1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: "the names specified by .spec.identityProviders[].displayName are unique",
		})
	}
	return conditions
}

func appendTransformsConstantsNamesUniqueCondition(duplicateConstNames sets.Set[string], conditions []*configv1alpha1.Condition) []*configv1alpha1.Condition {
	if duplicateConstNames.Len() > 0 {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:   typeTransformsConstantsNamesUnique,
			Status: configv1alpha1.ConditionFalse,
			Reason: reasonDuplicateConstantsNames,
			Message: fmt.Sprintf("the names specified by .spec.identityProviders[].transforms.constants[].name contain duplicates: %s",
				strings.Join(sortAndQuote(duplicateConstNames.UnsortedList()), ", ")),
		})
	} else {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeTransformsConstantsNamesUnique,
			Status:  configv1alpha1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: "the names specified by .spec.identityProviders[].transforms.constants[].name are unique",
		})
	}
	return conditions
}

func appendIssuerURLValidCondition(err error, conditions []*configv1alpha1.Condition) []*configv1alpha1.Condition {
	if err != nil {
		// Note that the FederationDomainIssuer constructors only validate the Issuer URL,
		// so these are always issuer URL validation errors.
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeIssuerURLValid,
			Status:  configv1alpha1.ConditionFalse,
			Reason:  reasonInvalidIssuerURL,
			Message: err.Error(),
		})
	} else {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeIssuerURLValid,
			Status:  configv1alpha1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: "spec.issuer is a valid URL",
		})
	}
	return conditions
}

func sortAndQuote(strs []string) []string {
	quoted := make([]string, 0, len(strs))
	for _, s := range strs {
		quoted = append(quoted, fmt.Sprintf("%q", s))
	}
	sort.Strings(quoted)
	return quoted
}

func (c *federationDomainWatcherController) updateStatus(
	ctx context.Context,
	federationDomain *configv1alpha1.FederationDomain,
	conditions []*configv1alpha1.Condition,
) error {
	updated := federationDomain.DeepCopy()

	if hadErrorCondition(conditions) {
		updated.Status.Phase = configv1alpha1.FederationDomainPhaseError
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeReady,
			Status:  configv1alpha1.ConditionFalse,
			Reason:  reasonNotReady,
			Message: "the FederationDomain is not ready: see other conditions for details",
		})
	} else {
		updated.Status.Phase = configv1alpha1.FederationDomainPhaseReady
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:   typeReady,
			Status: configv1alpha1.ConditionTrue,
			Reason: reasonSuccess,
			Message: fmt.Sprintf("the FederationDomain is ready and its endpoints are available: "+
				"the discovery endpoint is %s/.well-known/openid-configuration", federationDomain.Spec.Issuer),
		})
	}

	_ = conditionsutil.MergeConfigConditions(conditions,
		federationDomain.Generation, &updated.Status.Conditions, plog.New(), metav1.NewTime(c.clock.Now()))

	if equality.Semantic.DeepEqual(federationDomain, updated) {
		return nil
	}

	_, err := c.client.
		ConfigV1alpha1().
		FederationDomains(federationDomain.Namespace).
		UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	return err
}

type crossFederationDomainConfigValidator struct {
	issuerCounts                      map[string]int
	uniqueSecretNamesPerIssuerAddress map[string]map[string]bool
}

func issuerURLToHostnameKey(issuerURL *url.URL) string {
	return lowercaseHostWithoutPort(issuerURL)
}

func issuerURLToIssuerKey(issuerURL *url.URL) string {
	return fmt.Sprintf("%s://%s%s", issuerURL.Scheme, strings.ToLower(issuerURL.Host), issuerURL.Path)
}

func (v *crossFederationDomainConfigValidator) Validate(federationDomain *configv1alpha1.FederationDomain, conditions []*configv1alpha1.Condition) []*configv1alpha1.Condition {
	issuerURL, urlParseErr := url.Parse(federationDomain.Spec.Issuer)

	if urlParseErr != nil {
		// Don't write a condition about the issuer URL being invalid because that is added elsewhere in the controller.
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeIssuerIsUnique,
			Status:  configv1alpha1.ConditionUnknown,
			Reason:  reasonUnableToValidate,
			Message: "unable to check if spec.issuer is unique among all FederationDomains because URL cannot be parsed",
		})
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeOneTLSSecretPerIssuerHostname,
			Status:  configv1alpha1.ConditionUnknown,
			Reason:  reasonUnableToValidate,
			Message: "unable to check if all FederationDomains are using the same TLS secret when using the same hostname in the spec.issuer URL because URL cannot be parsed",
		})
		return conditions
	}

	if issuerCount := v.issuerCounts[issuerURLToIssuerKey(issuerURL)]; issuerCount > 1 {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeIssuerIsUnique,
			Status:  configv1alpha1.ConditionFalse,
			Reason:  reasonDuplicateIssuer,
			Message: "multiple FederationDomains have the same spec.issuer URL: these URLs must be unique (can use different hosts or paths)",
		})
	} else {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeIssuerIsUnique,
			Status:  configv1alpha1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: "spec.issuer is unique among all FederationDomains",
		})
	}

	if len(v.uniqueSecretNamesPerIssuerAddress[issuerURLToHostnameKey(issuerURL)]) > 1 {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeOneTLSSecretPerIssuerHostname,
			Status:  configv1alpha1.ConditionFalse,
			Reason:  reasonDifferentSecretRefsFound,
			Message: "when different FederationDomains are using the same hostname in the spec.issuer URL then they must also use the same TLS secretRef: different secretRefs found",
		})
	} else {
		conditions = append(conditions, &configv1alpha1.Condition{
			Type:    typeOneTLSSecretPerIssuerHostname,
			Status:  configv1alpha1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: "all FederationDomains are using the same TLS secret when using the same hostname in the spec.issuer URL",
		})
	}

	return conditions
}

func newCrossFederationDomainConfigValidator(federationDomains []*configv1alpha1.FederationDomain) *crossFederationDomainConfigValidator {
	// Make a map of issuer strings -> count of how many times we saw that issuer string.
	// This will help us complain when there are duplicate issuer strings.
	// Also make a helper function for forming keys into this map.
	issuerCounts := make(map[string]int)

	// Make a map of issuer hostnames -> set of unique secret names. This will help us complain when
	// multiple FederationDomains have the same issuer hostname (excluding port) but specify
	// different TLS serving Secrets. Doesn't make sense to have the one address use more than one
	// TLS cert. Ignore ports because SNI information on the incoming requests is not going to include
	// port numbers. Also make a helper function for forming keys into this map.
	uniqueSecretNamesPerIssuerAddress := make(map[string]map[string]bool)

	for _, federationDomain := range federationDomains {
		issuerURL, err := url.Parse(federationDomain.Spec.Issuer)
		if err != nil {
			continue // Skip url parse errors because they will be handled in the Validate function.
		}

		issuerCounts[issuerURLToIssuerKey(issuerURL)]++

		setOfSecretNames := uniqueSecretNamesPerIssuerAddress[issuerURLToHostnameKey(issuerURL)]
		if setOfSecretNames == nil {
			setOfSecretNames = make(map[string]bool)
			uniqueSecretNamesPerIssuerAddress[issuerURLToHostnameKey(issuerURL)] = setOfSecretNames
		}
		if federationDomain.Spec.TLS != nil {
			setOfSecretNames[federationDomain.Spec.TLS.SecretName] = true
		}
	}

	return &crossFederationDomainConfigValidator{
		issuerCounts:                      issuerCounts,
		uniqueSecretNamesPerIssuerAddress: uniqueSecretNamesPerIssuerAddress,
	}
}

func hadErrorCondition(conditions []*configv1alpha1.Condition) bool {
	for _, c := range conditions {
		if c.Status != configv1alpha1.ConditionTrue {
			return true
		}
	}
	return false
}

func stringSetsEqual(a []string, b []string) bool {
	aSet := sets.New(a...)
	bSet := sets.New(b...)
	return aSet.Equal(bSet)
}
