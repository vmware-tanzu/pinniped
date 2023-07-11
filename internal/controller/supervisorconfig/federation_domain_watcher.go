// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	errorsutil "k8s.io/apimachinery/pkg/util/errors"
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
	typeReady                         = "Ready"
	typeIssuerURLValid                = "IssuerURLValid"
	typeOneTLSSecretPerIssuerHostname = "OneTLSSecretPerIssuerHostname"
	typeIssuerIsUnique                = "IssuerIsUnique"
	typeIdentityProvidersFound        = "IdentityProvidersFound"

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
	clock                   clock.Clock
	client                  pinnipedclientset.Interface

	federationDomainInformer                configinformers.FederationDomainInformer
	oidcIdentityProviderInformer            idpinformers.OIDCIdentityProviderInformer
	ldapIdentityProviderInformer            idpinformers.LDAPIdentityProviderInformer
	activeDirectoryIdentityProviderInformer idpinformers.ActiveDirectoryIdentityProviderInformer

	celTransformer *celtransformer.CELTransformer
}

// NewFederationDomainWatcherController creates a controllerlib.Controller that watches
// FederationDomain objects and notifies a callback object of the collection of provider configs.
func NewFederationDomainWatcherController(
	federationDomainsSetter FederationDomainsSetter,
	clock clock.Clock,
	client pinnipedclientset.Interface,
	federationDomainInformer configinformers.FederationDomainInformer,
	oidcIdentityProviderInformer idpinformers.OIDCIdentityProviderInformer,
	ldapIdentityProviderInformer idpinformers.LDAPIdentityProviderInformer,
	activeDirectoryIdentityProviderInformer idpinformers.ActiveDirectoryIdentityProviderInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "FederationDomainWatcherController",
			Syncer: &federationDomainWatcherController{
				federationDomainsSetter:                 federationDomainsSetter,
				clock:                                   clock,
				client:                                  client,
				federationDomainInformer:                federationDomainInformer,
				oidcIdentityProviderInformer:            oidcIdentityProviderInformer,
				ldapIdentityProviderInformer:            ldapIdentityProviderInformer,
				activeDirectoryIdentityProviderInformer: activeDirectoryIdentityProviderInformer,
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
		c.celTransformer, _ = celtransformer.NewCELTransformer(celTransformerMaxExpressionRuntime) // TODO: what is a good duration limit here?
		// TODO: handle err from NewCELTransformer() above
	}

	// Process each FederationDomain to validate its spec and to turn it into a FederationDomainIssuer.
	federationDomainIssuers, fdToConditionsMap, _ := c.processAllFederationDomains(federationDomains)
	// TODO: handle err

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
	federationDomains []*configv1alpha1.FederationDomain,
) ([]*federationdomainproviders.FederationDomainIssuer, map[*configv1alpha1.FederationDomain][]*configv1alpha1.Condition, error) {
	federationDomainIssuers := make([]*federationdomainproviders.FederationDomainIssuer, 0)
	fdToConditionsMap := map[*configv1alpha1.FederationDomain][]*configv1alpha1.Condition{}
	crossDomainConfigValidator := newCrossFederationDomainConfigValidator(federationDomains)

	for _, federationDomain := range federationDomains {
		conditions := make([]*configv1alpha1.Condition, 0)

		conditions = crossDomainConfigValidator.Validate(federationDomain, conditions)

		federationDomainIssuer, conditions, _ := c.makeFederationDomainIssuer(federationDomain, conditions)
		// TODO: handle err

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
	federationDomain *configv1alpha1.FederationDomain,
	conditions []*configv1alpha1.Condition,
) (*federationdomainproviders.FederationDomainIssuer, []*configv1alpha1.Condition, error) {
	// Create the list of IDPs for this FederationDomain.
	// Don't worry if the IDP CRs themselves is phase=Ready because those which are not ready will not be loaded
	// into the provider cache, so they cannot actually be used to authenticate.
	var federationDomainIssuer *federationdomainproviders.FederationDomainIssuer
	if len(federationDomain.Spec.IdentityProviders) == 0 {
		federationDomainIssuer, conditions, _ = c.makeLegacyFederationDomainIssuer(federationDomain, conditions)
		// TODO handle err
	} else {
		federationDomainIssuer, conditions, _ = c.makeFederationDomainIssuerWithExplicitIDPs(federationDomain, conditions)
		// TODO handle err
	}

	return federationDomainIssuer, conditions, nil
}

func (c *federationDomainWatcherController) makeLegacyFederationDomainIssuer(
	federationDomain *configv1alpha1.FederationDomain,
	conditions []*configv1alpha1.Condition,
) (*federationdomainproviders.FederationDomainIssuer, []*configv1alpha1.Condition, error) {
	var defaultFederationDomainIdentityProvider *federationdomainproviders.FederationDomainIdentityProvider

	// When the FederationDomain does not list any IDPs, then we might be in backwards compatibility mode.
	oidcIdentityProviders, _ := c.oidcIdentityProviderInformer.Lister().List(labels.Everything())
	ldapIdentityProviders, _ := c.ldapIdentityProviderInformer.Lister().List(labels.Everything())
	activeDirectoryIdentityProviders, _ := c.activeDirectoryIdentityProviderInformer.Lister().List(labels.Everything())
	// TODO handle err return value for each of the above three lines

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

	// This is the constructor for the backwards compatibility mode.
	federationDomainIssuer, err := federationdomainproviders.NewFederationDomainIssuerWithDefaultIDP(federationDomain.Spec.Issuer, defaultFederationDomainIdentityProvider)
	conditions = appendIssuerURLValidCondition(err, conditions)

	return federationDomainIssuer, conditions, nil
}

func (c *federationDomainWatcherController) makeFederationDomainIssuerWithExplicitIDPs(
	federationDomain *configv1alpha1.FederationDomain,
	conditions []*configv1alpha1.Condition,
) (*federationdomainproviders.FederationDomainIssuer, []*configv1alpha1.Condition, error) {
	var err error
	federationDomainIdentityProviders := []*federationdomainproviders.FederationDomainIdentityProvider{}
	idpNotFoundIndices := []int{}

	for index, idp := range federationDomain.Spec.IdentityProviders {
		// TODO: Validate that all displayNames are unique within this FederationDomain's spec's list of identity providers.
		// TODO: Validate that idp.ObjectRef.APIGroup is the expected APIGroup for IDP CRs "idp.supervisor.pinniped.dev"
		// Validate that each objectRef resolves to an existing IDP. It does not matter if the IDP itself
		// is phase=Ready, because it will not be loaded into the cache if not ready. For each objectRef
		// that does not resolve, put an error on the FederationDomain status.
		idpResourceUID, idpWasFound, _ := c.findIDPsUIDByObjectRef(idp.ObjectRef, federationDomain.Namespace)
		// TODO handle err
		if !idpWasFound {
			idpNotFoundIndices = append(idpNotFoundIndices, index)
		}

		pipeline, _ := c.makeTransformationPipelineForIdentityProvider(idp, federationDomain.Name)
		// TODO handle err

		// For each valid IDP (unique displayName, valid objectRef + valid transforms), add it to the list.
		federationDomainIdentityProviders = append(federationDomainIdentityProviders, &federationdomainproviders.FederationDomainIdentityProvider{
			DisplayName: idp.DisplayName,
			UID:         idpResourceUID,
			Transforms:  pipeline,
		})
		plog.Debug("loaded FederationDomain identity provider",
			"federationDomain", federationDomain.Name,
			"identityProviderDisplayName", idp.DisplayName,
			"identityProviderResourceUID", idpResourceUID,
		)
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
	return federationDomainIssuer, conditions, nil
}

func (c *federationDomainWatcherController) findIDPsUIDByObjectRef(objectRef corev1.TypedLocalObjectReference, namespace string) (types.UID, bool, error) {
	var idpResourceUID types.UID
	var foundIDP metav1.Object
	var err error

	switch objectRef.Kind {
	case "LDAPIdentityProvider":
		foundIDP, err = c.ldapIdentityProviderInformer.Lister().LDAPIdentityProviders(namespace).Get(objectRef.Name)
	case "ActiveDirectoryIdentityProvider":
		foundIDP, err = c.activeDirectoryIdentityProviderInformer.Lister().ActiveDirectoryIdentityProviders(namespace).Get(objectRef.Name)
	case "OIDCIdentityProvider":
		foundIDP, err = c.oidcIdentityProviderInformer.Lister().OIDCIdentityProviders(namespace).Get(objectRef.Name)
	default:
		// TODO: handle an IDP type that we do not understand.
	}

	switch {
	case err == nil:
		idpResourceUID = foundIDP.GetUID()
	case errors.IsNotFound(err):
		return "", false, nil
	default:
		// TODO: handle unexpected errors
	}
	return idpResourceUID, true, nil
}

func (c *federationDomainWatcherController) makeTransformationPipelineForIdentityProvider(
	idp configv1alpha1.FederationDomainIdentityProvider,
	federationDomainName string,
) (*idtransform.TransformationPipeline, error) {
	pipeline := idtransform.NewTransformationPipeline()
	consts := &celtransformer.TransformationConstants{
		StringConstants:     map[string]string{},
		StringListConstants: map[string][]string{},
	}

	// Read all the declared constants.
	for _, c := range idp.Transforms.Constants {
		switch c.Type {
		case "string":
			consts.StringConstants[c.Name] = c.StringValue
		case "stringList":
			consts.StringListConstants[c.Name] = c.StringListValue
		default:
			// TODO: this shouldn't really happen since the CRD validates it, but handle it as an error
		}
	}

	// Compile all the expressions and add them to the pipeline.
	for idx, e := range idp.Transforms.Expressions {
		var rawTransform celtransformer.CELTransformation
		switch e.Type {
		case "username/v1":
			rawTransform = &celtransformer.UsernameTransformation{Expression: e.Expression}
		case "groups/v1":
			rawTransform = &celtransformer.GroupsTransformation{Expression: e.Expression}
		case "policy/v1":
			rawTransform = &celtransformer.AllowAuthenticationPolicy{
				Expression:                    e.Expression,
				RejectedAuthenticationMessage: e.Message,
			}
		default:
			// TODO: this shouldn't really happen since the CRD validates it, but handle it as an error
		}
		compiledTransform, err := c.celTransformer.CompileTransformation(rawTransform, consts)
		if err != nil {
			// TODO: handle compile err
			plog.Error("error compiling identity transformation", err,
				"federationDomain", federationDomainName,
				"idpDisplayName", idp.DisplayName,
				"transformationIndex", idx,
				"transformationType", e.Type,
				"transformationExpression", e.Expression,
			)
		}
		pipeline.AppendTransformation(compiledTransform)
		plog.Debug("successfully compiled identity transformation expression",
			"type", e.Type,
			"expr", e.Expression,
			"policyMessage", e.Message,
		)
	}

	// Run all the provided transform examples. If any fail, put errors on the FederationDomain status.
	for idx, e := range idp.Transforms.Examples {
		// TODO: use a real context param below
		result, _ := pipeline.Evaluate(context.TODO(), e.Username, e.Groups)
		// TODO: handle err
		resultWasAuthRejected := !result.AuthenticationAllowed
		if e.Expects.Rejected && !resultWasAuthRejected { //nolint:gocritic,nestif
			// TODO: handle this failed example
			plog.Warning("FederationDomain identity provider transformations example failed: expected authentication to be rejected but it was not",
				"federationDomain", federationDomainName,
				"idpDisplayName", idp.DisplayName,
				"exampleIndex", idx,
				"expectedRejected", e.Expects.Rejected,
				"actualRejectedResult", resultWasAuthRejected,
				"expectedMessage", e.Expects.Message,
				"actualMessageResult", result.RejectedAuthenticationMessage,
			)
		} else if !e.Expects.Rejected && resultWasAuthRejected {
			// TODO: handle this failed example
			plog.Warning("FederationDomain identity provider transformations example failed: expected authentication not to be rejected but it was rejected",
				"federationDomain", federationDomainName,
				"idpDisplayName", idp.DisplayName,
				"exampleIndex", idx,
				"expectedRejected", e.Expects.Rejected,
				"actualRejectedResult", resultWasAuthRejected,
				"expectedMessage", e.Expects.Message,
				"actualMessageResult", result.RejectedAuthenticationMessage,
			)
		} else if e.Expects.Rejected && resultWasAuthRejected && e.Expects.Message != result.RejectedAuthenticationMessage {
			// TODO: when expected message is blank, then treat it like it expects the default message
			// TODO: handle this failed example
			plog.Warning("FederationDomain identity provider transformations example failed: expected a different authentication rejection message",
				"federationDomain", federationDomainName,
				"idpDisplayName", idp.DisplayName,
				"exampleIndex", idx,
				"expectedRejected", e.Expects.Rejected,
				"actualRejectedResult", resultWasAuthRejected,
				"expectedMessage", e.Expects.Message,
				"actualMessageResult", result.RejectedAuthenticationMessage,
			)
		} else if result.AuthenticationAllowed {
			// In the case where the user expected the auth to be allowed and it was allowed, then compare
			// the expected username and group names to the actual username and group names.
			// TODO: when both of these fail, put both errors onto the status (not just the first one)
			if e.Expects.Username != result.Username {
				// TODO: handle this failed example
				plog.Warning("FederationDomain identity provider transformations example failed: expected a different transformed username",
					"federationDomain", federationDomainName,
					"idpDisplayName", idp.DisplayName,
					"exampleIndex", idx,
					"expectedUsername", e.Expects.Username,
					"actualUsernameResult", result.Username,
				)
			}
			if !stringSlicesEqual(e.Expects.Groups, result.Groups) {
				// TODO: Do we need to make this insensitive to ordering, or should the transformations evaluator be changed to always return sorted group names at the end of the pipeline?
				// TODO: What happens if the user did not write any group expectation? Treat it like expecting an empty list of groups?
				// TODO: handle this failed example
				plog.Warning("FederationDomain identity provider transformations example failed: expected a different transformed groups list",
					"federationDomain", federationDomainName,
					"idpDisplayName", idp.DisplayName,
					"exampleIndex", idx,
					"expectedGroups", e.Expects.Groups,
					"actualGroupsResult", result.Groups,
				)
			}
		}
	}

	return pipeline, nil
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

func stringSlicesEqual(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, itemFromA := range a {
		if b[i] != itemFromA {
			return false
		}
	}
	return true
}
