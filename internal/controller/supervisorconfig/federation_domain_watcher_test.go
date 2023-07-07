// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	coretesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/federationdomain/federationdomainproviders"
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/testutil"
)

func TestFederationDomainWatcherControllerInformerFilters(t *testing.T) {
	t.Parallel()

	federationDomainInformer := pinnipedinformers.NewSharedInformerFactoryWithOptions(nil, 0).Config().V1alpha1().FederationDomains()
	oidcIdentityProviderInformer := pinnipedinformers.NewSharedInformerFactoryWithOptions(nil, 0).IDP().V1alpha1().OIDCIdentityProviders()
	ldapIdentityProviderInformer := pinnipedinformers.NewSharedInformerFactoryWithOptions(nil, 0).IDP().V1alpha1().LDAPIdentityProviders()
	adIdentityProviderInformer := pinnipedinformers.NewSharedInformerFactoryWithOptions(nil, 0).IDP().V1alpha1().ActiveDirectoryIdentityProviders()

	tests := []struct {
		name       string
		obj        metav1.Object
		informer   controllerlib.InformerGetter
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
	}{
		{
			name:       "any FederationDomain changes",
			obj:        &configv1alpha1.FederationDomain{},
			informer:   federationDomainInformer,
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name:       "any OIDCIdentityProvider adds or deletes, but updates are ignored",
			obj:        &idpv1alpha1.OIDCIdentityProvider{},
			informer:   oidcIdentityProviderInformer,
			wantAdd:    true,
			wantUpdate: false,
			wantDelete: true,
		},
		{
			name:       "any LDAPIdentityProvider adds or deletes, but updates are ignored",
			obj:        &idpv1alpha1.LDAPIdentityProvider{},
			informer:   ldapIdentityProviderInformer,
			wantAdd:    true,
			wantUpdate: false,
			wantDelete: true,
		},
		{
			name:       "any ActiveDirectoryIdentityProvider adds or deletes, but updates are ignored",
			obj:        &idpv1alpha1.ActiveDirectoryIdentityProvider{},
			informer:   adIdentityProviderInformer,
			wantAdd:    true,
			wantUpdate: false,
			wantDelete: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			withInformer := testutil.NewObservableWithInformerOption()

			NewFederationDomainWatcherController(
				nil,
				nil,
				nil,
				federationDomainInformer,
				oidcIdentityProviderInformer,
				ldapIdentityProviderInformer,
				adIdentityProviderInformer,
				withInformer.WithInformer, // make it possible to observe the behavior of the Filters
			)

			unrelatedObj := corev1.Secret{}
			filter := withInformer.GetFilterForInformer(test.informer)
			require.Equal(t, test.wantAdd, filter.Add(test.obj))
			require.Equal(t, test.wantUpdate, filter.Update(&unrelatedObj, test.obj))
			require.Equal(t, test.wantUpdate, filter.Update(test.obj, &unrelatedObj))
			require.Equal(t, test.wantDelete, filter.Delete(test.obj))
		})
	}
}

type fakeFederationDomainsSetter struct {
	SetFederationDomainsWasCalled bool
	FederationDomainsReceived     []*federationdomainproviders.FederationDomainIssuer
}

func (f *fakeFederationDomainsSetter) SetFederationDomains(federationDomains ...*federationdomainproviders.FederationDomainIssuer) {
	f.SetFederationDomainsWasCalled = true
	f.FederationDomainsReceived = federationDomains
}

func TestTestFederationDomainWatcherControllerSync(t *testing.T) {
	t.Parallel()

	const namespace = "some-namespace"

	frozenNow := time.Date(2020, time.September, 23, 7, 42, 0, 0, time.Local)
	frozenMetav1Now := metav1.NewTime(frozenNow)

	federationDomainGVR := schema.GroupVersionResource{
		Group:    configv1alpha1.SchemeGroupVersion.Group,
		Version:  configv1alpha1.SchemeGroupVersion.Version,
		Resource: "federationdomains",
	}

	identityProvider := &idpv1alpha1.OIDCIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "some-name",
			UID:  "some-uid",
		},
	}

	federationDomain1 := &configv1alpha1.FederationDomain{
		ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
		Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer1.com"},
	}

	federationDomain2 := &configv1alpha1.FederationDomain{
		ObjectMeta: metav1.ObjectMeta{Name: "config2", Namespace: namespace, Generation: 123},
		Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer2.com"},
	}

	invalidFederationDomain := &configv1alpha1.FederationDomain{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid-config", Namespace: namespace, Generation: 123},
		Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://invalid-issuer.com?some=query"},
	}

	federationDomainIssuerWithDefaultIDP := func(t *testing.T, fedDomainIssuer string, idpObjectMeta metav1.ObjectMeta) *federationdomainproviders.FederationDomainIssuer {
		fdIDP := &federationdomainproviders.FederationDomainIdentityProvider{
			DisplayName: idpObjectMeta.Name,
			UID:         idpObjectMeta.UID,
			Transforms:  idtransform.NewTransformationPipeline(),
		}
		fdIssuer, err := federationdomainproviders.NewFederationDomainIssuerWithDefaultIDP(fedDomainIssuer, fdIDP)
		require.NoError(t, err)
		return fdIssuer
	}

	happyReadyCondition := func(issuer string, time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "Ready",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message: fmt.Sprintf("the FederationDomain is ready and its endpoints are available: "+
				"the discovery endpoint is %s/.well-known/openid-configuration", issuer),
		}
	}

	sadReadyCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "Ready",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "NotReady",
			Message:            "the FederationDomain is not ready: see other conditions for details",
		}
	}

	happyIssuerIsUniqueCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IssuerIsUnique",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "spec.issuer is unique among all FederationDomains",
		}
	}

	unknownIssuerIsUniqueCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IssuerIsUnique",
			Status:             "Unknown",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToValidate",
			Message:            "unable to check if spec.issuer is unique among all FederationDomains because URL cannot be parsed",
		}
	}

	sadIssuerIsUniqueCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IssuerIsUnique",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "DuplicateIssuer",
			Message:            "multiple FederationDomains have the same spec.issuer URL: these URLs must be unique (can use different hosts or paths)",
		}
	}

	happyOneTLSSecretPerIssuerHostnameCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "OneTLSSecretPerIssuerHostname",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "all FederationDomains are using the same TLS secret when using the same hostname in the spec.issuer URL",
		}
	}

	unknownOneTLSSecretPerIssuerHostnameCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "OneTLSSecretPerIssuerHostname",
			Status:             "Unknown",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "UnableToValidate",
			Message:            "unable to check if all FederationDomains are using the same TLS secret when using the same hostname in the spec.issuer URL because URL cannot be parsed",
		}
	}

	sadOneTLSSecretPerIssuerHostnameCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "OneTLSSecretPerIssuerHostname",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "DifferentSecretRefsFound",
			Message:            "when different FederationDomains are using the same hostname in the spec.issuer URL then they must also use the same TLS secretRef: different secretRefs found",
		}
	}

	happyIssuerURLValidCondition := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IssuerURLValid",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "Success",
			Message:            "spec.issuer is a valid URL",
		}
	}

	sadIssuerURLValidConditionCannotHaveQuery := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IssuerURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidIssuerURL",
			Message:            "issuer must not have query",
		}
	}

	sadIssuerURLValidConditionCannotParse := func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IssuerURLValid",
			Status:             "False",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "InvalidIssuerURL",
			Message:            `could not parse issuer as URL: parse ":/host//path": missing protocol scheme`,
		}
	}

	happyIdentityProvidersFoundConditionLegacyConfigurationSuccess := func(idpName string, time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
		return configv1alpha1.Condition{
			Type:               "IdentityProvidersFound",
			Status:             "True",
			ObservedGeneration: observedGeneration,
			LastTransitionTime: time,
			Reason:             "LegacyConfigurationSuccess",
			Message: fmt.Sprintf("no resources were specified by .spec.identityProviders[].objectRef but exactly one "+
				"identity provider resource has been found: using %q as "+
				"identity provider: please explicitly list identity providers in .spec.identityProviders "+
				"(this legacy configuration mode may be removed in a future version of Pinniped)", idpName),
		}
	}

	// sadIdentityProvidersFoundConditionForSomeReasons := func() {}

	allHappyConditionsLegacyConfigurationSuccess := func(issuer, idpName string, time metav1.Time, observedGeneration int64) []configv1alpha1.Condition {
		return []configv1alpha1.Condition{
			// sorted alphabetically by type
			happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(idpName, time, observedGeneration),
			happyIssuerIsUniqueCondition(time, observedGeneration),
			happyIssuerURLValidCondition(time, observedGeneration),
			happyOneTLSSecretPerIssuerHostnameCondition(time, observedGeneration),
			happyReadyCondition(issuer, time, observedGeneration),
		}
	}

	invalidIssuerURL := ":/host//path"
	_, err := url.Parse(invalidIssuerURL) //nolint:staticcheck // Yes, this URL is intentionally invalid.
	require.Error(t, err)

	newCopyWithStatus := func(
		fd *configv1alpha1.FederationDomain,
		phase configv1alpha1.FederationDomainPhase,
		conditions []configv1alpha1.Condition,
	) *configv1alpha1.FederationDomain {
		fdCopy := fd.DeepCopy()
		fdCopy.Status.Phase = phase
		fdCopy.Status.Conditions = conditions
		return fdCopy
	}

	tests := []struct {
		name                        string
		inputObjects                []runtime.Object
		configPinnipedClient        func(*pinnipedfake.Clientset)
		wantErr                     string
		wantActions                 func(t *testing.T) []coretesting.Action
		wantFederationDomainIssuers func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer
	}{
		{
			name:         "when there are no FederationDomains, nothing happens",
			inputObjects: []runtime.Object{},
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				return []*federationdomainproviders.FederationDomainIssuer{}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{}
			},
		},
		{
			// TODO: fill in these conditions in my TODO blocks.
			// 			conditions = append(conditions, &configv1alpha1.Condition{
			// 	Type:    typeIssuerURLValid,
			// 	Status:  configv1alpha1.ConditionFalse,
			// 	Reason:  reasonInvalidIssuerURL,
			// 	Message: err.Error(),
			// })
			name: "legacy config: when no identity provider is specified on federation domains, but exactly one identity " +
				"provider resource exists on cluster, the controller will set a default IDP on each federation domain " +
				"matching the only identity provider found",
			inputObjects: []runtime.Object{
				federationDomain1,
				federationDomain2,
				identityProvider,
			},
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				return []*federationdomainproviders.FederationDomainIssuer{
					federationDomainIssuerWithDefaultIDP(t, federationDomain1.Spec.Issuer, identityProvider.ObjectMeta),
					federationDomainIssuerWithDefaultIDP(t, federationDomain2.Spec.Issuer, identityProvider.ObjectMeta),
				}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain1.Namespace,
						newCopyWithStatus(federationDomain1,
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditionsLegacyConfigurationSuccess(federationDomain1.Spec.Issuer, identityProvider.Name, frozenMetav1Now, 123),
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain2.Namespace,
						newCopyWithStatus(federationDomain2,
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditionsLegacyConfigurationSuccess(federationDomain2.Spec.Issuer, identityProvider.Name, frozenMetav1Now, 123),
						),
					),
				}
			},
		},
		{
			name: "when there are two valid FederationDomains, but one is already up to date, the sync loop only updates " +
				"the out-of-date FederationDomain",
			inputObjects: []runtime.Object{
				identityProvider,
				newCopyWithStatus(federationDomain1, configv1alpha1.FederationDomainPhaseReady,
					allHappyConditionsLegacyConfigurationSuccess(federationDomain1.Spec.Issuer, identityProvider.Name, frozenMetav1Now, 123),
				),
				federationDomain2,
			},
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				return []*federationdomainproviders.FederationDomainIssuer{
					federationDomainIssuerWithDefaultIDP(t, federationDomain1.Spec.Issuer, identityProvider.ObjectMeta),
					federationDomainIssuerWithDefaultIDP(t, federationDomain2.Spec.Issuer, identityProvider.ObjectMeta),
				}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain2.Namespace,
						newCopyWithStatus(federationDomain2,
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditionsLegacyConfigurationSuccess(federationDomain2.Spec.Issuer, identityProvider.Name, frozenMetav1Now, 123),
						),
					),
				}
			},
		},
		{
			name: "when there are two valid FederationDomains, but updating one fails, the status on the FederationDomain will not change",
			inputObjects: []runtime.Object{
				federationDomain1,
				federationDomain2,
				identityProvider,
			},
			configPinnipedClient: func(client *pinnipedfake.Clientset) {
				client.PrependReactor(
					"update",
					"federationdomains",
					func(action coretesting.Action) (bool, runtime.Object, error) {
						fd := action.(coretesting.UpdateAction).GetObject().(*configv1alpha1.FederationDomain)
						if fd.Name == federationDomain1.Name {
							return true, nil, errors.New("some update error")
						}
						return false, nil, nil
					},
				)
			},
			wantErr: "could not update status: some update error",
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				return []*federationdomainproviders.FederationDomainIssuer{
					// federationDomain1 is not included because it encountered an error
					federationDomainIssuerWithDefaultIDP(t, federationDomain2.Spec.Issuer, identityProvider.ObjectMeta),
				}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain1.Namespace,
						newCopyWithStatus(federationDomain1,
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditionsLegacyConfigurationSuccess(federationDomain1.Spec.Issuer, identityProvider.Name, frozenMetav1Now, 123),
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain2.Namespace,
						newCopyWithStatus(federationDomain2,
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditionsLegacyConfigurationSuccess(federationDomain2.Spec.Issuer, identityProvider.Name, frozenMetav1Now, 123),
						),
					),
				}
			},
		},
		{
			name: "when there are both valid and invalid FederationDomains, the status will be correctly set on each " +
				"FederationDomain individually",
			inputObjects: []runtime.Object{
				invalidFederationDomain,
				federationDomain2,
				identityProvider,
			},
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				return []*federationdomainproviders.FederationDomainIssuer{
					// only the valid FederationDomain
					federationDomainIssuerWithDefaultIDP(t, federationDomain2.Spec.Issuer, identityProvider.ObjectMeta),
				}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", invalidFederationDomain.Namespace,
						newCopyWithStatus(invalidFederationDomain,
							configv1alpha1.FederationDomainPhaseError,
							[]configv1alpha1.Condition{
								happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(identityProvider.Name, frozenMetav1Now, 123),
								happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
								sadIssuerURLValidConditionCannotHaveQuery(frozenMetav1Now, 123),
								happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
								sadReadyCondition(frozenMetav1Now, 123),
							},
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain2.Namespace,
						newCopyWithStatus(federationDomain2,
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditionsLegacyConfigurationSuccess(federationDomain2.Spec.Issuer, identityProvider.Name, frozenMetav1Now, 123),
						),
					),
				}
			},
		},
		{
			name: "when there are both valid and invalid FederationDomains, but updating the invalid one fails, the " +
				"existing status will be unchanged",
			inputObjects: []runtime.Object{
				invalidFederationDomain,
				federationDomain2,
				identityProvider,
			},
			configPinnipedClient: func(client *pinnipedfake.Clientset) {
				client.PrependReactor(
					"update",
					"federationdomains",
					func(action coretesting.Action) (bool, runtime.Object, error) {
						fd := action.(coretesting.UpdateAction).GetObject().(*configv1alpha1.FederationDomain)
						if fd.Name == invalidFederationDomain.Name {
							return true, nil, errors.New("some update error")
						}
						return false, nil, nil
					},
				)
			},
			wantErr: "could not update status: some update error",
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				return []*federationdomainproviders.FederationDomainIssuer{
					// only the valid FederationDomain
					federationDomainIssuerWithDefaultIDP(t, federationDomain2.Spec.Issuer, identityProvider.ObjectMeta),
				}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", invalidFederationDomain.Namespace,
						newCopyWithStatus(invalidFederationDomain,
							configv1alpha1.FederationDomainPhaseError,
							[]configv1alpha1.Condition{
								happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(identityProvider.Name, frozenMetav1Now, 123),
								happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
								sadIssuerURLValidConditionCannotHaveQuery(frozenMetav1Now, 123),
								happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
								sadReadyCondition(frozenMetav1Now, 123),
							},
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain2.Namespace,
						newCopyWithStatus(federationDomain2,
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditionsLegacyConfigurationSuccess(federationDomain2.Spec.Issuer, identityProvider.Name, frozenMetav1Now, 123),
						),
					),
				}
			},
		},
		{
			name: "when there are FederationDomains with duplicate issuer strings these particular FederationDomains " +
				"will report error on IssuerUnique conditions",
			inputObjects: []runtime.Object{
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "duplicate1", Namespace: namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://iSSueR-duPlicAte.cOm/a"},
				},
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "duplicate2", Namespace: namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer-duplicate.com/a"},
				},
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "not-duplicate", Namespace: namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer-duplicate.com/A"}, // different path (paths are case-sensitive)
				},
				identityProvider,
			},
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				return []*federationdomainproviders.FederationDomainIssuer{
					// different path (paths are case-sensitive)
					federationDomainIssuerWithDefaultIDP(t, "https://issuer-duplicate.com/A", identityProvider.ObjectMeta),
				}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", invalidFederationDomain.Namespace,
						newCopyWithStatus(
							&configv1alpha1.FederationDomain{
								ObjectMeta: metav1.ObjectMeta{Name: "duplicate1", Namespace: namespace, Generation: 123},
								Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://iSSueR-duPlicAte.cOm/a"},
							},
							configv1alpha1.FederationDomainPhaseError,
							[]configv1alpha1.Condition{
								happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(identityProvider.Name, frozenMetav1Now, 123),
								sadIssuerIsUniqueCondition(frozenMetav1Now, 123),
								happyIssuerURLValidCondition(frozenMetav1Now, 123),
								happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
								sadReadyCondition(frozenMetav1Now, 123),
							},
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", invalidFederationDomain.Namespace,
						newCopyWithStatus(
							&configv1alpha1.FederationDomain{
								ObjectMeta: metav1.ObjectMeta{Name: "duplicate2", Namespace: namespace, Generation: 123},
								Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer-duplicate.com/a"},
							},
							configv1alpha1.FederationDomainPhaseError,
							[]configv1alpha1.Condition{
								happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(identityProvider.Name, frozenMetav1Now, 123),
								sadIssuerIsUniqueCondition(frozenMetav1Now, 123),
								happyIssuerURLValidCondition(frozenMetav1Now, 123),
								happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
								sadReadyCondition(frozenMetav1Now, 123),
							},
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain2.Namespace,
						newCopyWithStatus(
							&configv1alpha1.FederationDomain{
								ObjectMeta: metav1.ObjectMeta{Name: "not-duplicate", Namespace: namespace, Generation: 123},
								Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer-duplicate.com/A"},
							},
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditionsLegacyConfigurationSuccess("https://issuer-duplicate.com/A", identityProvider.Name, frozenMetav1Now, 123),
						),
					),
				}
			},
		},
		{
			name: "when there are FederationDomains with the same issuer DNS hostname using different secretNames these " +
				"particular FederationDomains will report errors on OneTLSSecretPerIssuerHostname conditions",
			inputObjects: []runtime.Object{
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "fd1", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://iSSueR-duPlicAte-adDress.cOm/path1",
						TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
					},
				},
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "fd2", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						// Validation treats these as the same DNS hostname even though they have different port numbers,
						// because SNI information on the incoming requests is not going to include port numbers.
						Issuer: "https://issuer-duplicate-address.com:1234/path2",
						TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret2"},
					},
				},
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "differentIssuerAddressFederationDomain", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://issuer-not-duplicate.com",
						TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
					},
				},
				&configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "invalidIssuerURLFederationDomain", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: invalidIssuerURL,
						TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
					},
				},
				identityProvider,
			},
			wantFederationDomainIssuers: func(t *testing.T) []*federationdomainproviders.FederationDomainIssuer {
				return []*federationdomainproviders.FederationDomainIssuer{
					federationDomainIssuerWithDefaultIDP(t, "https://issuer-not-duplicate.com", identityProvider.ObjectMeta),
				}
			},
			wantActions: func(t *testing.T) []coretesting.Action {
				return []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", invalidFederationDomain.Namespace,
						newCopyWithStatus(
							&configv1alpha1.FederationDomain{
								ObjectMeta: metav1.ObjectMeta{Name: "fd1", Namespace: namespace, Generation: 123},
								Spec: configv1alpha1.FederationDomainSpec{
									Issuer: "https://iSSueR-duPlicAte-adDress.cOm/path1",
									TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
								},
							},
							configv1alpha1.FederationDomainPhaseError,
							[]configv1alpha1.Condition{
								happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(identityProvider.Name, frozenMetav1Now, 123),
								happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
								happyIssuerURLValidCondition(frozenMetav1Now, 123),
								sadOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
								sadReadyCondition(frozenMetav1Now, 123),
							},
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", invalidFederationDomain.Namespace,
						newCopyWithStatus(
							&configv1alpha1.FederationDomain{
								ObjectMeta: metav1.ObjectMeta{Name: "fd2", Namespace: namespace, Generation: 123},
								Spec: configv1alpha1.FederationDomainSpec{
									Issuer: "https://issuer-duplicate-address.com:1234/path2",
									TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret2"},
								},
							},
							configv1alpha1.FederationDomainPhaseError,
							[]configv1alpha1.Condition{
								happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(identityProvider.Name, frozenMetav1Now, 123),
								happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
								happyIssuerURLValidCondition(frozenMetav1Now, 123),
								sadOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
								sadReadyCondition(frozenMetav1Now, 123),
							},
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", invalidFederationDomain.Namespace,
						newCopyWithStatus(
							&configv1alpha1.FederationDomain{
								ObjectMeta: metav1.ObjectMeta{Name: "invalidIssuerURLFederationDomain", Namespace: namespace, Generation: 123},
								Spec: configv1alpha1.FederationDomainSpec{
									Issuer: invalidIssuerURL,
									TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
								},
							},
							configv1alpha1.FederationDomainPhaseError,
							[]configv1alpha1.Condition{
								happyIdentityProvidersFoundConditionLegacyConfigurationSuccess(identityProvider.Name, frozenMetav1Now, 123),
								unknownIssuerIsUniqueCondition(frozenMetav1Now, 123),
								sadIssuerURLValidConditionCannotParse(frozenMetav1Now, 123),
								unknownOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
								sadReadyCondition(frozenMetav1Now, 123),
							},
						),
					),
					coretesting.NewUpdateSubresourceAction(federationDomainGVR, "status", federationDomain2.Namespace,
						newCopyWithStatus(
							&configv1alpha1.FederationDomain{
								ObjectMeta: metav1.ObjectMeta{Name: "differentIssuerAddressFederationDomain", Namespace: namespace, Generation: 123},
								Spec: configv1alpha1.FederationDomainSpec{
									Issuer: "https://issuer-not-duplicate.com",
									TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
								},
							},
							configv1alpha1.FederationDomainPhaseReady,
							allHappyConditionsLegacyConfigurationSuccess("https://issuer-not-duplicate.com", identityProvider.Name, frozenMetav1Now, 123),
						),
					),
				}
			},
		},
		// TODO(Ben): add these additional tests to cover the new cases. There will likely also be more as we cover
		//    both the truthy as well as the falsy cases.
		// {
		// 	name:    "legacy config: no identity provider specified in federation domain and no identity providers found",
		// 	wantErr: "...please create an identity provider resource",
		// },
		// {
		// 	name:    "legacy config: no identity provider specified in federation domain and multiple identity providers found",
		// 	wantErr: "...to specify which identity providers this federation domain should use",
		// },
		// {
		// 	name:    "the federation domain specifies identity providers that cannot be found", // single and/or multiple?
		// 	wantErr: "...identifies resource(s) that cannot be found: {list.of...}",
		// },
		// {
		// 	name:    "the federation domain specifies identity providers taht exist",
		// 	wantErr: "", // n/a
		// },
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			federationDomainsSetter := &fakeFederationDomainsSetter{}
			pinnipedAPIClient := pinnipedfake.NewSimpleClientset()
			pinnipedInformerClient := pinnipedfake.NewSimpleClientset()
			for _, o := range tt.inputObjects {
				require.NoError(t, pinnipedAPIClient.Tracker().Add(o))
				require.NoError(t, pinnipedInformerClient.Tracker().Add(o))
			}
			if tt.configPinnipedClient != nil {
				tt.configPinnipedClient(pinnipedAPIClient)
			}
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(pinnipedInformerClient, 0)

			controller := NewFederationDomainWatcherController(
				federationDomainsSetter,
				clocktesting.NewFakeClock(frozenNow),
				pinnipedAPIClient,
				pinnipedInformers.Config().V1alpha1().FederationDomains(),
				pinnipedInformers.IDP().V1alpha1().OIDCIdentityProviders(),
				pinnipedInformers.IDP().V1alpha1().LDAPIdentityProviders(),
				pinnipedInformers.IDP().V1alpha1().ActiveDirectoryIdentityProviders(),
				controllerlib.WithInformer,
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			pinnipedInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: controllerlib.Key{Namespace: namespace, Name: "config-name"}}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			if tt.wantFederationDomainIssuers != nil {
				require.True(t, federationDomainsSetter.SetFederationDomainsWasCalled)
				require.ElementsMatch(t, tt.wantFederationDomainIssuers(t), federationDomainsSetter.FederationDomainsReceived)
			} else {
				require.False(t, federationDomainsSetter.SetFederationDomainsWasCalled)
			}

			if tt.wantActions != nil {
				// In this controller we don't actually care about the order of the actions, the FederationDomains
				// can be updated in any order.  Therefore, we are sorting here to make the test output easier to read.
				// Unfortunately the timezone nested in the condition still makes it pretty ugly.
				actualActions := pinnipedAPIClient.Actions()
				sortActions(t, actualActions)
				wantedActions := tt.wantActions(t)
				sortActions(t, wantedActions)
				require.Equal(t, wantedActions, actualActions)
			} else {
				require.Empty(t, pinnipedAPIClient.Actions())
			}
		})
	}
}

func sortActions(t *testing.T, actions []coretesting.Action) {
	sort.SliceStable(actions, func(prev, next int) bool {
		updateAction1, ok := actions[prev].(coretesting.UpdateAction)
		require.True(t, ok, "failed to cast an action as an coretesting.UpdateAction for sort comparison %#v", actions[prev])
		obj1, ok := updateAction1.GetObject().(metav1.Object)
		require.True(t, ok, "failed to cast an action as a metav1.Object for sort comparison %#v", actions[prev])

		updateAction2, ok := actions[next].(coretesting.UpdateAction)
		require.True(t, ok, "failed to cast an action as an coretesting.UpdateAction for sort comparison %#v", actions[next])
		obj2, ok := updateAction2.GetObject().(metav1.Object)
		require.True(t, ok, "failed to cast an action as a metav1.Object for sort comparison %#v", actions[next])

		return obj1.GetName() < obj2.GetName()
	})
}
