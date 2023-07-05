// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
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
	spec.Run(t, "Sync", func(t *testing.T, when spec.G, it spec.S) {
		const namespace = "some-namespace"

		var r *require.Assertions

		var subject controllerlib.Controller
		var pinnipedInformerClient *pinnipedfake.Clientset
		var pinnipedInformers pinnipedinformers.SharedInformerFactory
		var pinnipedAPIClient *pinnipedfake.Clientset
		var cancelContext context.Context
		var cancelContextCancelFunc context.CancelFunc
		var syncContext *controllerlib.Context
		var frozenNow time.Time
		var frozenMetav1Now metav1.Time
		var federationDomainsSetter *fakeFederationDomainsSetter
		var federationDomainGVR schema.GroupVersionResource
		var allHappyConditions func(issuer string, time metav1.Time, observedGeneration int64) []configv1alpha1.Condition
		var happyReadyCondition func(issuer string, time metav1.Time, observedGeneration int64) configv1alpha1.Condition
		var happyIssuerIsUniqueCondition,
			unknownIssuerIsUniqueCondition,
			sadIssuerIsUniqueCondition,
			happyOneTLSSecretPerIssuerHostnameCondition,
			unknownOneTLSSecretPerIssuerHostnameCondition,
			sadOneTLSSecretPerIssuerHostnameCondition,
			happyIssuerURLValidCondition,
			sadIssuerURLValidConditionCannotHaveQuery,
			sadIssuerURLValidConditionCannotParse,
			sadReadyCondition func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewFederationDomainWatcherController(
				federationDomainsSetter,
				clocktesting.NewFakeClock(frozenNow),
				pinnipedAPIClient,
				pinnipedInformers.Config().V1alpha1().FederationDomains(),
				pinnipedInformers.IDP().V1alpha1().OIDCIdentityProviders(),
				pinnipedInformers.IDP().V1alpha1().LDAPIdentityProviders(),
				pinnipedInformers.IDP().V1alpha1().ActiveDirectoryIdentityProviders(),
				controllerlib.WithInformer,
			)

			// Set this at the last second to support calling subject.Name().
			syncContext = &controllerlib.Context{
				Context: cancelContext,
				Name:    subject.Name(),
				Key: controllerlib.Key{
					Namespace: namespace,
					Name:      "config-name",
				},
			}

			// Must start informers before calling TestRunSynchronously()
			pinnipedInformers.Start(cancelContext.Done())
			controllerlib.TestRunSynchronously(t, subject)
		}

		it.Before(func() {
			r = require.New(t)

			federationDomainsSetter = &fakeFederationDomainsSetter{}
			frozenNow = time.Date(2020, time.September, 23, 7, 42, 0, 0, time.Local)

			cancelContext, cancelContextCancelFunc = context.WithCancel(context.Background())

			pinnipedInformerClient = pinnipedfake.NewSimpleClientset()
			pinnipedInformers = pinnipedinformers.NewSharedInformerFactory(pinnipedInformerClient, 0)
			pinnipedAPIClient = pinnipedfake.NewSimpleClientset()

			federationDomainGVR = schema.GroupVersionResource{
				Group:    configv1alpha1.SchemeGroupVersion.Group,
				Version:  configv1alpha1.SchemeGroupVersion.Version,
				Resource: "federationdomains",
			}

			frozenMetav1Now = metav1.NewTime(frozenNow)

			happyReadyCondition = func(issuer string, time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
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

			sadReadyCondition = func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
				return configv1alpha1.Condition{
					Type:               "Ready",
					Status:             "False",
					ObservedGeneration: observedGeneration,
					LastTransitionTime: time,
					Reason:             "NotReady",
					Message:            "the FederationDomain is not ready: see other conditions for details",
				}
			}

			happyIssuerIsUniqueCondition = func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
				return configv1alpha1.Condition{
					Type:               "IssuerIsUnique",
					Status:             "True",
					ObservedGeneration: observedGeneration,
					LastTransitionTime: time,
					Reason:             "Success",
					Message:            "spec.issuer is unique among all FederationDomains",
				}
			}

			unknownIssuerIsUniqueCondition = func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
				return configv1alpha1.Condition{
					Type:               "IssuerIsUnique",
					Status:             "Unknown",
					ObservedGeneration: observedGeneration,
					LastTransitionTime: time,
					Reason:             "UnableToValidate",
					Message:            "unable to check if spec.issuer is unique among all FederationDomains because URL cannot be parsed",
				}
			}

			sadIssuerIsUniqueCondition = func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
				return configv1alpha1.Condition{
					Type:               "IssuerIsUnique",
					Status:             "False",
					ObservedGeneration: observedGeneration,
					LastTransitionTime: time,
					Reason:             "DuplicateIssuer",
					Message:            "multiple FederationDomains have the same spec.issuer URL: these URLs must be unique (can use different hosts or paths)",
				}
			}

			happyOneTLSSecretPerIssuerHostnameCondition = func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
				return configv1alpha1.Condition{
					Type:               "OneTLSSecretPerIssuerHostname",
					Status:             "True",
					ObservedGeneration: observedGeneration,
					LastTransitionTime: time,
					Reason:             "Success",
					Message:            "all FederationDomains are using the same TLS secret when using the same hostname in the spec.issuer URL",
				}
			}

			unknownOneTLSSecretPerIssuerHostnameCondition = func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
				return configv1alpha1.Condition{
					Type:               "OneTLSSecretPerIssuerHostname",
					Status:             "Unknown",
					ObservedGeneration: observedGeneration,
					LastTransitionTime: time,
					Reason:             "UnableToValidate",
					Message:            "unable to check if all FederationDomains are using the same TLS secret when using the same hostname in the spec.issuer URL because URL cannot be parsed",
				}
			}

			sadOneTLSSecretPerIssuerHostnameCondition = func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
				return configv1alpha1.Condition{
					Type:               "OneTLSSecretPerIssuerHostname",
					Status:             "False",
					ObservedGeneration: observedGeneration,
					LastTransitionTime: time,
					Reason:             "DifferentSecretRefsFound",
					Message:            "when different FederationDomains are using the same hostname in the spec.issuer URL then they must also use the same TLS secretRef: different secretRefs found",
				}
			}

			happyIssuerURLValidCondition = func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
				return configv1alpha1.Condition{
					Type:               "IssuerURLValid",
					Status:             "True",
					ObservedGeneration: observedGeneration,
					LastTransitionTime: time,
					Reason:             "Success",
					Message:            "spec.issuer is a valid URL",
				}
			}

			sadIssuerURLValidConditionCannotHaveQuery = func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
				return configv1alpha1.Condition{
					Type:               "IssuerURLValid",
					Status:             "False",
					ObservedGeneration: observedGeneration,
					LastTransitionTime: time,
					Reason:             "InvalidIssuerURL",
					Message:            "issuer must not have query",
				}
			}

			sadIssuerURLValidConditionCannotParse = func(time metav1.Time, observedGeneration int64) configv1alpha1.Condition {
				return configv1alpha1.Condition{
					Type:               "IssuerURLValid",
					Status:             "False",
					ObservedGeneration: observedGeneration,
					LastTransitionTime: time,
					Reason:             "InvalidIssuerURL",
					Message:            `could not parse issuer as URL: parse ":/host//path": missing protocol scheme`,
				}
			}

			allHappyConditions = func(issuer string, time metav1.Time, observedGeneration int64) []configv1alpha1.Condition {
				return []configv1alpha1.Condition{
					happyIssuerIsUniqueCondition(time, observedGeneration),
					happyIssuerURLValidCondition(time, observedGeneration),
					happyOneTLSSecretPerIssuerHostnameCondition(time, observedGeneration),
					happyReadyCondition(issuer, time, observedGeneration),
				}
			}
		})

		it.After(func() {
			cancelContextCancelFunc()
		})

		when("there are some valid FederationDomains in the informer", func() {
			var (
				federationDomain1 *configv1alpha1.FederationDomain
				federationDomain2 *configv1alpha1.FederationDomain
			)

			it.Before(func() {
				federationDomain1 = &configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer1.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomain1))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomain1))

				federationDomain2 = &configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config2", Namespace: namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer2.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomain2))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomain2))
			})

			it("calls the FederationDomainsSetter", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				fd1, err := federationdomainproviders.NewFederationDomainIssuer(federationDomain1.Spec.Issuer, []*federationdomainproviders.FederationDomainIdentityProvider{})
				r.NoError(err)

				fd2, err := federationdomainproviders.NewFederationDomainIssuer(federationDomain2.Spec.Issuer, []*federationdomainproviders.FederationDomainIdentityProvider{})
				r.NoError(err)

				r.True(federationDomainsSetter.SetFederationDomainsWasCalled)
				r.ElementsMatch(
					[]*federationdomainproviders.FederationDomainIssuer{
						fd1,
						fd2,
					},
					federationDomainsSetter.FederationDomainsReceived,
				)
			})

			it("updates the status to ready in the FederationDomains", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				federationDomain1.Status.Phase = configv1alpha1.FederationDomainPhaseReady
				federationDomain1.Status.Conditions = allHappyConditions(federationDomain1.Spec.Issuer, frozenMetav1Now, 123)

				federationDomain2.Status.Phase = configv1alpha1.FederationDomainPhaseReady
				federationDomain2.Status.Conditions = allHappyConditions(federationDomain2.Spec.Issuer, frozenMetav1Now, 123)

				expectedActions := []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						federationDomain1.Namespace,
						federationDomain1,
					),
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						federationDomain2.Namespace,
						federationDomain2,
					),
				}
				r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
			})

			when("one FederationDomain is already up to date", func() {
				it.Before(func() {
					federationDomain1.Status.Phase = configv1alpha1.FederationDomainPhaseReady
					federationDomain1.Status.Conditions = allHappyConditions(federationDomain1.Spec.Issuer, frozenMetav1Now, 123)

					r.NoError(pinnipedAPIClient.Tracker().Update(federationDomainGVR, federationDomain1, federationDomain1.Namespace))
					r.NoError(pinnipedInformerClient.Tracker().Update(federationDomainGVR, federationDomain1, federationDomain1.Namespace))
				})

				it("only updates the out-of-date FederationDomain", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.NoError(err)

					federationDomain2.Status.Phase = configv1alpha1.FederationDomainPhaseReady
					federationDomain2.Status.Conditions = allHappyConditions(federationDomain2.Spec.Issuer, frozenMetav1Now, 123)

					expectedActions := []coretesting.Action{
						coretesting.NewUpdateSubresourceAction(
							federationDomainGVR,
							"status",
							federationDomain2.Namespace,
							federationDomain2,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})

				it("calls the FederationDomainsSetter with both FederationDomain's", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.NoError(err)

					fd1, err := federationdomainproviders.NewFederationDomainIssuer(federationDomain1.Spec.Issuer, []*federationdomainproviders.FederationDomainIdentityProvider{})
					r.NoError(err)

					fd2, err := federationdomainproviders.NewFederationDomainIssuer(federationDomain2.Spec.Issuer, []*federationdomainproviders.FederationDomainIdentityProvider{})
					r.NoError(err)

					r.True(federationDomainsSetter.SetFederationDomainsWasCalled)
					r.ElementsMatch(
						[]*federationdomainproviders.FederationDomainIssuer{
							fd1,
							fd2,
						},
						federationDomainsSetter.FederationDomainsReceived,
					)
				})
			})

			when("updating only one FederationDomain fails", func() {
				it.Before(func() {
					once := sync.Once{}
					pinnipedAPIClient.PrependReactor(
						"update",
						"federationdomains",
						func(_ coretesting.Action) (bool, runtime.Object, error) {
							var err error
							once.Do(func() {
								err = errors.New("some update error")
							})
							return true, nil, err
						},
					)
				})

				it("sets the FederationDomain that it could actually update in the API", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "could not update status: some update error")

					fd1, err := federationdomainproviders.NewFederationDomainIssuer(federationDomain1.Spec.Issuer, []*federationdomainproviders.FederationDomainIdentityProvider{})
					r.NoError(err)

					fd2, err := federationdomainproviders.NewFederationDomainIssuer(federationDomain2.Spec.Issuer, []*federationdomainproviders.FederationDomainIdentityProvider{})
					r.NoError(err)

					r.True(federationDomainsSetter.SetFederationDomainsWasCalled)
					r.Len(federationDomainsSetter.FederationDomainsReceived, 1)
					r.True(
						reflect.DeepEqual(federationDomainsSetter.FederationDomainsReceived[0], fd1) ||
							reflect.DeepEqual(federationDomainsSetter.FederationDomainsReceived[0], fd2),
					)
				})

				it("returns an error", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "could not update status: some update error")

					federationDomain1.Status.Phase = configv1alpha1.FederationDomainPhaseReady
					federationDomain1.Status.Conditions = allHappyConditions(federationDomain1.Spec.Issuer, frozenMetav1Now, 123)

					federationDomain2.Status.Phase = configv1alpha1.FederationDomainPhaseReady
					federationDomain2.Status.Conditions = allHappyConditions(federationDomain2.Spec.Issuer, frozenMetav1Now, 123)

					expectedActions := []coretesting.Action{
						coretesting.NewUpdateSubresourceAction(
							federationDomainGVR,
							"status",
							federationDomain1.Namespace,
							federationDomain1,
						),
						coretesting.NewUpdateSubresourceAction(
							federationDomainGVR,
							"status",
							federationDomain2.Namespace,
							federationDomain2,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are errors updating the FederationDomains", func() {
			var (
				federationDomain *configv1alpha1.FederationDomain
			)

			it.Before(func() {
				federationDomain = &configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomain))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomain))
			})

			when("updating the FederationDomain fails", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"update",
						"federationdomains",
						func(_ coretesting.Action) (bool, runtime.Object, error) {
							return true, nil, errors.New("some update error")
						},
					)
				})

				it("returns an error", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "could not update status: some update error")

					federationDomain.Status.Phase = configv1alpha1.FederationDomainPhaseReady
					federationDomain.Status.Conditions = allHappyConditions(federationDomain.Spec.Issuer, frozenMetav1Now, 123)

					expectedActions := []coretesting.Action{
						coretesting.NewUpdateSubresourceAction(
							federationDomainGVR,
							"status",
							federationDomain.Namespace,
							federationDomain,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are both valid and invalid FederationDomains in the informer", func() {
			var (
				validFederationDomain   *configv1alpha1.FederationDomain
				invalidFederationDomain *configv1alpha1.FederationDomain
			)

			it.Before(func() {
				validFederationDomain = &configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "valid-config", Namespace: namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://valid-issuer.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(validFederationDomain))
				r.NoError(pinnipedInformerClient.Tracker().Add(validFederationDomain))

				invalidFederationDomain = &configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "invalid-config", Namespace: namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://invalid-issuer.com?some=query"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(invalidFederationDomain))
				r.NoError(pinnipedInformerClient.Tracker().Add(invalidFederationDomain))
			})

			it("calls the FederationDomainsSetter with the valid FederationDomain", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				validFederationDomain, err := federationdomainproviders.NewFederationDomainIssuer(validFederationDomain.Spec.Issuer, []*federationdomainproviders.FederationDomainIdentityProvider{})
				r.NoError(err)

				r.True(federationDomainsSetter.SetFederationDomainsWasCalled)
				r.Equal(
					[]*federationdomainproviders.FederationDomainIssuer{
						validFederationDomain,
					},
					federationDomainsSetter.FederationDomainsReceived,
				)
			})

			it("updates the status in each FederationDomain", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				validFederationDomain.Status.Phase = configv1alpha1.FederationDomainPhaseReady
				validFederationDomain.Status.Conditions = allHappyConditions(validFederationDomain.Spec.Issuer, frozenMetav1Now, 123)

				invalidFederationDomain.Status.Phase = configv1alpha1.FederationDomainPhaseError
				invalidFederationDomain.Status.Conditions = []configv1alpha1.Condition{
					happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
					sadIssuerURLValidConditionCannotHaveQuery(frozenMetav1Now, 123),
					happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
					sadReadyCondition(frozenMetav1Now, 123),
				}

				expectedActions := []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						invalidFederationDomain.Namespace,
						invalidFederationDomain,
					),
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						validFederationDomain.Namespace,
						validFederationDomain,
					),
				}
				r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
			})

			when("updating only the invalid FederationDomain fails", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"update",
						"federationdomains",
						func(action coretesting.Action) (bool, runtime.Object, error) {
							updateAction := action.(coretesting.UpdateActionImpl)
							federationDomain := updateAction.Object.(*configv1alpha1.FederationDomain)
							if federationDomain.Name == validFederationDomain.Name {
								return true, nil, nil
							}

							return true, nil, errors.New("some update error")
						},
					)
				})

				it("sets the FederationDomain that it could actually update in the API", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "could not update status: some update error")

					validFederationDomain, err := federationdomainproviders.NewFederationDomainIssuer(validFederationDomain.Spec.Issuer, []*federationdomainproviders.FederationDomainIdentityProvider{})
					r.NoError(err)

					r.True(federationDomainsSetter.SetFederationDomainsWasCalled)
					r.Equal(
						[]*federationdomainproviders.FederationDomainIssuer{
							validFederationDomain,
						},
						federationDomainsSetter.FederationDomainsReceived,
					)
				})

				it("returns an error", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "could not update status: some update error")

					validFederationDomain.Status.Phase = configv1alpha1.FederationDomainPhaseReady
					validFederationDomain.Status.Conditions = allHappyConditions(validFederationDomain.Spec.Issuer, frozenMetav1Now, 123)

					invalidFederationDomain.Status.Phase = configv1alpha1.FederationDomainPhaseError
					invalidFederationDomain.Status.Conditions = []configv1alpha1.Condition{
						happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
						sadIssuerURLValidConditionCannotHaveQuery(frozenMetav1Now, 123),
						happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
						sadReadyCondition(frozenMetav1Now, 123),
					}

					expectedActions := []coretesting.Action{
						coretesting.NewUpdateSubresourceAction(
							federationDomainGVR,
							"status",
							invalidFederationDomain.Namespace,
							invalidFederationDomain,
						),
						coretesting.NewUpdateSubresourceAction(
							federationDomainGVR,
							"status",
							validFederationDomain.Namespace,
							validFederationDomain,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are FederationDomains with duplicate issuer names in the informer", func() {
			var (
				federationDomainDuplicate1 *configv1alpha1.FederationDomain
				federationDomainDuplicate2 *configv1alpha1.FederationDomain
				federationDomain           *configv1alpha1.FederationDomain
			)

			it.Before(func() {
				// Hostnames are case-insensitive, so consider them to be duplicates if they only differ by case.
				// Paths are case-sensitive, so having a path that differs only by case makes a new issuer.
				federationDomainDuplicate1 = &configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "duplicate1", Namespace: namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://iSSueR-duPlicAte.cOm/a"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomainDuplicate1))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainDuplicate1))
				federationDomainDuplicate2 = &configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "duplicate2", Namespace: namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer-duplicate.com/a"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomainDuplicate2))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainDuplicate2))

				federationDomain = &configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "not-duplicate", Namespace: namespace, Generation: 123},
					Spec:       configv1alpha1.FederationDomainSpec{Issuer: "https://issuer-duplicate.com/A"}, // different path
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomain))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomain))
			})

			it("calls the FederationDomainsSetter with the non-duplicate", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				nonDuplicateFederationDomain, err := federationdomainproviders.NewFederationDomainIssuer(federationDomain.Spec.Issuer, []*federationdomainproviders.FederationDomainIdentityProvider{})
				r.NoError(err)

				r.True(federationDomainsSetter.SetFederationDomainsWasCalled)
				r.Equal(
					[]*federationdomainproviders.FederationDomainIssuer{
						nonDuplicateFederationDomain,
					},
					federationDomainsSetter.FederationDomainsReceived,
				)
			})

			it("updates the statuses", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				federationDomain.Status.Phase = configv1alpha1.FederationDomainPhaseReady
				federationDomain.Status.Conditions = allHappyConditions(federationDomain.Spec.Issuer, frozenMetav1Now, 123)

				federationDomainDuplicate1.Status.Phase = configv1alpha1.FederationDomainPhaseError
				federationDomainDuplicate1.Status.Conditions = []configv1alpha1.Condition{
					sadIssuerIsUniqueCondition(frozenMetav1Now, 123),
					happyIssuerURLValidCondition(frozenMetav1Now, 123),
					happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
					sadReadyCondition(frozenMetav1Now, 123),
				}

				federationDomainDuplicate2.Status.Phase = configv1alpha1.FederationDomainPhaseError
				federationDomainDuplicate2.Status.Conditions = []configv1alpha1.Condition{
					sadIssuerIsUniqueCondition(frozenMetav1Now, 123),
					happyIssuerURLValidCondition(frozenMetav1Now, 123),
					happyOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
					sadReadyCondition(frozenMetav1Now, 123),
				}

				expectedActions := []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						federationDomainDuplicate1.Namespace,
						federationDomainDuplicate1,
					),
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						federationDomainDuplicate2.Namespace,
						federationDomainDuplicate2,
					),
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						federationDomain.Namespace,
						federationDomain,
					),
				}
				r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
			})
		})

		when("there are FederationDomains with the same issuer DNS hostname using different secretNames", func() {
			var (
				federationDomainSameIssuerAddress1     *configv1alpha1.FederationDomain
				federationDomainSameIssuerAddress2     *configv1alpha1.FederationDomain
				federationDomainDifferentIssuerAddress *configv1alpha1.FederationDomain
				federationDomainWithInvalidIssuerURL   *configv1alpha1.FederationDomain
			)

			it.Before(func() {
				federationDomainSameIssuerAddress1 = &configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "fd1", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://iSSueR-duPlicAte-adDress.cOm/path1",
						TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomainSameIssuerAddress1))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainSameIssuerAddress1))
				federationDomainSameIssuerAddress2 = &configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "fd2", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						// Validation treats these as the same DNS hostname even though they have different port numbers,
						// because SNI information on the incoming requests is not going to include port numbers.
						Issuer: "https://issuer-duplicate-address.com:1234/path2",
						TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret2"},
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomainSameIssuerAddress2))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainSameIssuerAddress2))

				federationDomainDifferentIssuerAddress = &configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "differentIssuerAddressFederationDomain", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: "https://issuer-not-duplicate.com",
						TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomainDifferentIssuerAddress))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainDifferentIssuerAddress))

				// Also add one with a URL that cannot be parsed to make sure that the error handling
				// for the duplicate issuers and secret names are not confused by invalid URLs.
				invalidIssuerURL := ":/host//path"
				_, err := url.Parse(invalidIssuerURL) //nolint:staticcheck // Yes, this URL is intentionally invalid.
				r.Error(err)
				federationDomainWithInvalidIssuerURL = &configv1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "invalidIssuerURLFederationDomain", Namespace: namespace, Generation: 123},
					Spec: configv1alpha1.FederationDomainSpec{
						Issuer: invalidIssuerURL,
						TLS:    &configv1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomainWithInvalidIssuerURL))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainWithInvalidIssuerURL))
			})

			it("calls the FederationDomainsSetter with the non-duplicate", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				nonDuplicateFederationDomain, err := federationdomainproviders.NewFederationDomainIssuer(federationDomainDifferentIssuerAddress.Spec.Issuer, []*federationdomainproviders.FederationDomainIdentityProvider{})
				r.NoError(err)

				r.True(federationDomainsSetter.SetFederationDomainsWasCalled)
				r.Equal(
					[]*federationdomainproviders.FederationDomainIssuer{
						nonDuplicateFederationDomain,
					},
					federationDomainsSetter.FederationDomainsReceived,
				)
			})

			it("updates the statuses", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				federationDomainDifferentIssuerAddress.Status.Phase = configv1alpha1.FederationDomainPhaseReady
				federationDomainDifferentIssuerAddress.Status.Conditions = allHappyConditions(federationDomainDifferentIssuerAddress.Spec.Issuer, frozenMetav1Now, 123)

				federationDomainSameIssuerAddress1.Status.Phase = configv1alpha1.FederationDomainPhaseError
				federationDomainSameIssuerAddress1.Status.Conditions = []configv1alpha1.Condition{
					happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
					happyIssuerURLValidCondition(frozenMetav1Now, 123),
					sadOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
					sadReadyCondition(frozenMetav1Now, 123),
				}

				federationDomainSameIssuerAddress2.Status.Phase = configv1alpha1.FederationDomainPhaseError
				federationDomainSameIssuerAddress2.Status.Conditions = []configv1alpha1.Condition{
					happyIssuerIsUniqueCondition(frozenMetav1Now, 123),
					happyIssuerURLValidCondition(frozenMetav1Now, 123),
					sadOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
					sadReadyCondition(frozenMetav1Now, 123),
				}

				federationDomainWithInvalidIssuerURL.Status.Phase = configv1alpha1.FederationDomainPhaseError
				federationDomainWithInvalidIssuerURL.Status.Conditions = []configv1alpha1.Condition{
					unknownIssuerIsUniqueCondition(frozenMetav1Now, 123),
					sadIssuerURLValidConditionCannotParse(frozenMetav1Now, 123),
					unknownOneTLSSecretPerIssuerHostnameCondition(frozenMetav1Now, 123),
					sadReadyCondition(frozenMetav1Now, 123),
				}

				expectedActions := []coretesting.Action{
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						federationDomainDifferentIssuerAddress.Namespace,
						federationDomainDifferentIssuerAddress,
					),
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						federationDomainSameIssuerAddress1.Namespace,
						federationDomainSameIssuerAddress1,
					),
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						federationDomainSameIssuerAddress2.Namespace,
						federationDomainSameIssuerAddress2,
					),
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						federationDomainWithInvalidIssuerURL.Namespace,
						federationDomainWithInvalidIssuerURL,
					),
				}
				r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
			})
		})

		when("there are no FederationDomains in the informer", func() {
			it("keeps waiting for one", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)
				r.Empty(pinnipedAPIClient.Actions())
				r.True(federationDomainsSetter.SetFederationDomainsWasCalled)
				r.Empty(federationDomainsSetter.FederationDomainsReceived)
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
