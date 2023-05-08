// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	configinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/config/v1alpha1"
	idpinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/idp/v1alpha1"
	"go.pinniped.dev/internal/celtransformer"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
)

// ProvidersSetter can be notified of all known valid providers with its SetIssuer function.
// If there are no longer any valid issuers, then it can be called with no arguments.
// Implementations of this type should be thread-safe to support calls from multiple goroutines.
type ProvidersSetter interface {
	SetProviders(federationDomains ...*provider.FederationDomainIssuer)
}

type federationDomainWatcherController struct {
	providerSetter ProvidersSetter
	clock          clock.Clock
	client         pinnipedclientset.Interface

	federationDomainInformer                configinformers.FederationDomainInformer
	oidcIdentityProviderInformer            idpinformers.OIDCIdentityProviderInformer
	ldapIdentityProviderInformer            idpinformers.LDAPIdentityProviderInformer
	activeDirectoryIdentityProviderInformer idpinformers.ActiveDirectoryIdentityProviderInformer
}

// NewFederationDomainWatcherController creates a controllerlib.Controller that watches
// FederationDomain objects and notifies a callback object of the collection of provider configs.
func NewFederationDomainWatcherController(
	providerSetter ProvidersSetter,
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
				providerSetter:                          providerSetter,
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

	// Make a map of issuer strings -> count of how many times we saw that issuer string.
	// This will help us complain when there are duplicate issuer strings.
	// Also make a helper function for forming keys into this map.
	issuerCounts := make(map[string]int)
	issuerURLToIssuerKey := func(issuerURL *url.URL) string {
		return fmt.Sprintf("%s://%s%s", issuerURL.Scheme, strings.ToLower(issuerURL.Host), issuerURL.Path)
	}

	// Make a map of issuer hostnames -> set of unique secret names. This will help us complain when
	// multiple FederationDomains have the same issuer hostname (excluding port) but specify
	// different TLS serving Secrets. Doesn't make sense to have the one address use more than one
	// TLS cert. Ignore ports because SNI information on the incoming requests is not going to include
	// port numbers. Also make a helper function for forming keys into this map.
	uniqueSecretNamesPerIssuerAddress := make(map[string]map[string]bool)
	issuerURLToHostnameKey := lowercaseHostWithoutPort

	for _, federationDomain := range federationDomains {
		issuerURL, err := url.Parse(federationDomain.Spec.Issuer)
		if err != nil {
			continue // Skip url parse errors because they will be validated again below.
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

	var errs []error

	federationDomainIssuers := make([]*provider.FederationDomainIssuer, 0)
	for _, federationDomain := range federationDomains {
		issuerURL, urlParseErr := url.Parse(federationDomain.Spec.Issuer)

		// Skip url parse errors because they will be validated below.
		if urlParseErr == nil {
			if issuerCount := issuerCounts[issuerURLToIssuerKey(issuerURL)]; issuerCount > 1 {
				if err := c.updateStatus(
					ctx.Context,
					federationDomain.Namespace,
					federationDomain.Name,
					configv1alpha1.DuplicateFederationDomainStatusCondition,
					"Duplicate issuer: "+federationDomain.Spec.Issuer,
				); err != nil {
					errs = append(errs, fmt.Errorf("could not update status: %w", err))
				}
				continue
			}
		}

		// Skip url parse errors because they will be validated below.
		if urlParseErr == nil && len(uniqueSecretNamesPerIssuerAddress[issuerURLToHostnameKey(issuerURL)]) > 1 {
			if err := c.updateStatus(
				ctx.Context,
				federationDomain.Namespace,
				federationDomain.Name,
				configv1alpha1.SameIssuerHostMustUseSameSecretFederationDomainStatusCondition,
				"Issuers with the same DNS hostname (address not including port) must use the same secretName: "+issuerURLToHostnameKey(issuerURL),
			); err != nil {
				errs = append(errs, fmt.Errorf("could not update status: %w", err))
			}
			continue
		}

		// TODO: Move all this identity provider stuff into helper functions. This is just a sketch of how the code would
		//  work in the sense that this is not doing error handling, is not validating everything that it should, and
		//  is not updating the status of the FederationDomain with anything related to these identity providers.
		//  This code may crash on invalid inputs since it is not handling any errors. However, when given valid inputs,
		//  this correctly implements the multiple IDPs features.
		// Create the list of IDPs for this FederationDomain.
		// Don't worry if the IDP CRs themselves is phase=Ready because those which are not ready will not be loaded
		// into the provider cache, so they cannot actually be used to authenticate.
		federationDomainIdentityProviders := []*provider.FederationDomainIdentityProvider{}
		var defaultFederationDomainIdentityProvider *provider.FederationDomainIdentityProvider
		if len(federationDomain.Spec.IdentityProviders) == 0 {
			// When the FederationDomain does not list any IDPs, then we might be in backwards compatibility mode.
			oidcIdentityProviders, _ := c.oidcIdentityProviderInformer.Lister().List(labels.Everything())
			ldapIdentityProviders, _ := c.ldapIdentityProviderInformer.Lister().List(labels.Everything())
			activeDirectoryIdentityProviders, _ := c.activeDirectoryIdentityProviderInformer.Lister().List(labels.Everything())
			// TODO handle err return value for each of the above three lines

			// Check if that there is exactly one IDP defined in the Supervisor namespace of any IDP CRD type.
			idpCRsCount := len(oidcIdentityProviders) + len(ldapIdentityProviders) + len(activeDirectoryIdentityProviders)
			if idpCRsCount == 1 {
				// If so, default that IDP's DisplayName to be the same as its resource Name.
				defaultFederationDomainIdentityProvider = &provider.FederationDomainIdentityProvider{}
				switch {
				case len(oidcIdentityProviders) == 1:
					defaultFederationDomainIdentityProvider.DisplayName = oidcIdentityProviders[0].Name
					defaultFederationDomainIdentityProvider.UID = oidcIdentityProviders[0].UID
				case len(ldapIdentityProviders) == 1:
					defaultFederationDomainIdentityProvider.DisplayName = ldapIdentityProviders[0].Name
					defaultFederationDomainIdentityProvider.UID = ldapIdentityProviders[0].UID
				case len(activeDirectoryIdentityProviders) == 1:
					defaultFederationDomainIdentityProvider.DisplayName = activeDirectoryIdentityProviders[0].Name
					defaultFederationDomainIdentityProvider.UID = activeDirectoryIdentityProviders[0].UID
				}
				// Backwards compatibility mode always uses an empty identity transformation pipline since no
				// transformations are defined on the FederationDomain.
				defaultFederationDomainIdentityProvider.Transforms = idtransform.NewTransformationPipeline()
				plog.Warning("detected FederationDomain identity provider backwards compatibility mode: using the one existing identity provider for authentication",
					"federationDomain", federationDomain.Name)
			} else {
				// There are no IDP CRs or there is more than one IDP CR. Either way, we are not in the backwards
				// compatibility mode because there is not exactly one IDP CR in the namespace, despite the fact that no
				// IDPs are listed on the FederationDomain. Create a FederationDomain which has no IDPs and therefore
				// cannot actually be used to log in, but still serves endpoints.
				// TODO: Write something into the FederationDomain's status to explain what's happening and how to fix it.
				plog.Warning("FederationDomain has no identity providers listed and there is not exactly one identity provider defined in the namespace: authentication disabled",
					"federationDomain", federationDomain.Name,
					"namespace", federationDomain.Namespace,
					"identityProvidersCustomResourcesCount", idpCRsCount,
				)
			}
		}

		// If there is an explicit list of IDPs on the FederationDomain, then process the list.
		celTransformer, _ := celtransformer.NewCELTransformer(time.Second) // TODO: what is a good duration limit here?
		// TODO: handle err
		for _, idp := range federationDomain.Spec.IdentityProviders {
			var idpResourceUID types.UID
			var idpResourceName string
			// TODO: Validate that all displayNames are unique within this FederationDomain's spec's list of identity providers.
			// TODO: Validate that idp.ObjectRef.APIGroup is the expected APIGroup for IDP CRs "idp.supervisor.pinniped.dev"
			// Validate that each objectRef resolves to an existing IDP. It does not matter if the IDP itself
			// is phase=Ready, because it will not be loaded into the cache if not ready. For each objectRef
			// that does not resolve, put an error on the FederationDomain status.
			switch idp.ObjectRef.Kind {
			case "LDAPIdentityProvider":
				ldapIDP, _ := c.ldapIdentityProviderInformer.Lister().LDAPIdentityProviders(federationDomain.Namespace).Get(idp.ObjectRef.Name)
				// TODO: handle notfound err and also unexpected errors
				idpResourceName = ldapIDP.Name
				idpResourceUID = ldapIDP.UID
			case "ActiveDirectoryIdentityProvider":
				adIDP, _ := c.activeDirectoryIdentityProviderInformer.Lister().ActiveDirectoryIdentityProviders(federationDomain.Namespace).Get(idp.ObjectRef.Name)
				// TODO: handle notfound err and also unexpected errors
				idpResourceName = adIDP.Name
				idpResourceUID = adIDP.UID
			case "OIDCIdentityProvider":
				oidcIDP, _ := c.oidcIdentityProviderInformer.Lister().OIDCIdentityProviders(federationDomain.Namespace).Get(idp.ObjectRef.Name)
				// TODO: handle notfound err and also unexpected errors
				idpResourceName = oidcIDP.Name
				idpResourceUID = oidcIDP.UID
			default:
				// TODO: handle bad user input
			}
			plog.Debug("resolved identity provider object reference",
				"kind", idp.ObjectRef.Kind,
				"name", idp.ObjectRef.Name,
				"foundResourceName", idpResourceName,
				"foundResourceUID", idpResourceUID,
			)

			// Prepare the transformations.
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
				compiledTransform, err := celTransformer.CompileTransformation(rawTransform, consts)
				if err != nil {
					// TODO: handle compile err
					plog.Error("error compiling identity transformation", err,
						"federationDomain", federationDomain.Name,
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
				if e.Expects.Rejected && !resultWasAuthRejected {
					// TODO: handle this failed example
					plog.Warning("FederationDomain identity provider transformations example failed: expected authentication to be rejected but it was not",
						"federationDomain", federationDomain.Name,
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
						"federationDomain", federationDomain.Name,
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
						"federationDomain", federationDomain.Name,
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
							"federationDomain", federationDomain.Name,
							"idpDisplayName", idp.DisplayName,
							"exampleIndex", idx,
							"expectedUsername", e.Expects.Username,
							"actualUsernameResult", result.Username,
						)
					}
					if !stringSlicesEqual(e.Expects.Groups, result.Groups) {
						// TODO: Do we need to make this insensitive to ordering, or should the transformations evaluator be changed to always return sorted group names at the end of the pipeline?
						// TODO: What happens if the user did not write any group expectation? Treat it like expecting any empty list of groups?
						// TODO: handle this failed example
						plog.Warning("FederationDomain identity provider transformations example failed: expected a different transformed groups list",
							"federationDomain", federationDomain.Name,
							"idpDisplayName", idp.DisplayName,
							"exampleIndex", idx,
							"expectedGroups", e.Expects.Groups,
							"actualGroupsResult", result.Groups,
						)
					}
				}
			}
			// For each valid IDP (unique displayName, valid objectRef + valid transforms), add it to the list.
			federationDomainIdentityProviders = append(federationDomainIdentityProviders, &provider.FederationDomainIdentityProvider{
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

		// Now that we have the list of IDPs for this FederationDomain, create the issuer.
		var federationDomainIssuer *provider.FederationDomainIssuer
		err = nil
		if defaultFederationDomainIdentityProvider != nil {
			// This is the constructor for the backwards compatibility mode.
			federationDomainIssuer, err = provider.NewFederationDomainIssuerWithDefaultIDP(federationDomain.Spec.Issuer, defaultFederationDomainIdentityProvider)
		} else {
			// This is the constructor for any other case, including when there is an empty list of IDPs.
			federationDomainIssuer, err = provider.NewFederationDomainIssuer(federationDomain.Spec.Issuer, federationDomainIdentityProviders)
		}
		if err != nil {
			// Note that the FederationDomainIssuer constructors validate the Issuer URL.
			if err := c.updateStatus(
				ctx.Context,
				federationDomain.Namespace,
				federationDomain.Name,
				configv1alpha1.InvalidFederationDomainStatusCondition,
				"Invalid: "+err.Error(),
			); err != nil {
				errs = append(errs, fmt.Errorf("could not update status: %w", err))
			}
			continue
		}

		if err := c.updateStatus(
			ctx.Context,
			federationDomain.Namespace,
			federationDomain.Name,
			configv1alpha1.SuccessFederationDomainStatusCondition,
			"Provider successfully created",
		); err != nil {
			errs = append(errs, fmt.Errorf("could not update status: %w", err))
			continue
		}

		federationDomainIssuers = append(federationDomainIssuers, federationDomainIssuer)
	}

	c.providerSetter.SetProviders(federationDomainIssuers...)

	return errors.NewAggregate(errs)
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

func (c *federationDomainWatcherController) updateStatus(
	ctx context.Context,
	namespace, name string,
	status configv1alpha1.FederationDomainStatusCondition,
	message string,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		federationDomain, err := c.client.ConfigV1alpha1().FederationDomains(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get failed: %w", err)
		}

		if federationDomain.Status.Status == status && federationDomain.Status.Message == message {
			return nil
		}

		plog.Debug(
			"attempting status update",
			"federationdomain",
			klog.KRef(namespace, name),
			"status",
			status,
			"message",
			message,
		)
		federationDomain.Status.Status = status
		federationDomain.Status.Message = message
		federationDomain.Status.LastUpdateTime = timePtr(metav1.NewTime(c.clock.Now()))
		_, err = c.client.ConfigV1alpha1().FederationDomains(namespace).UpdateStatus(ctx, federationDomain, metav1.UpdateOptions{})
		return err
	})
}

func timePtr(t metav1.Time) *metav1.Time { return &t }
