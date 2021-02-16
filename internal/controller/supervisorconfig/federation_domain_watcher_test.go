// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
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
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/clock"
	coretesting "k8s.io/client-go/testing"

	"go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/testutil"
)

func TestInformerFilters(t *testing.T) {
	spec.Run(t, "informer filters", func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions
		var observableWithInformerOption *testutil.ObservableWithInformerOption
		var configMapInformerFilter controllerlib.Filter

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = testutil.NewObservableWithInformerOption()
			federationDomainInformer := pinnipedinformers.NewSharedInformerFactoryWithOptions(nil, 0).Config().V1alpha1().FederationDomains()
			_ = NewFederationDomainWatcherController(
				nil,
				nil,
				nil,
				federationDomainInformer,
				observableWithInformerOption.WithInformer, // make it possible to observe the behavior of the Filters
			)
			configMapInformerFilter = observableWithInformerOption.GetFilterForInformer(federationDomainInformer)
		})

		when("watching FederationDomain objects", func() {
			var subject controllerlib.Filter
			var target, otherNamespace, otherName *v1alpha1.FederationDomain

			it.Before(func() {
				subject = configMapInformerFilter
				target = &v1alpha1.FederationDomain{ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"}}
				otherNamespace = &v1alpha1.FederationDomain{ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "other-namespace"}}
				otherName = &v1alpha1.FederationDomain{ObjectMeta: metav1.ObjectMeta{Name: "other-name", Namespace: "some-namespace"}}
			})

			when("any FederationDomain changes", func() {
				it("returns true to trigger the sync method", func() {
					r.True(subject.Add(target))
					r.True(subject.Add(otherName))
					r.True(subject.Add(otherNamespace))
					r.True(subject.Update(target, otherName))
					r.True(subject.Update(otherName, otherName))
					r.True(subject.Update(otherNamespace, otherName))
					r.True(subject.Update(otherName, target))
					r.True(subject.Update(otherName, otherName))
					r.True(subject.Update(otherName, otherNamespace))
					r.True(subject.Delete(target))
					r.True(subject.Delete(otherName))
					r.True(subject.Delete(otherNamespace))
				})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}

type fakeProvidersSetter struct {
	SetProvidersWasCalled     bool
	FederationDomainsReceived []*provider.FederationDomainIssuer
}

func (f *fakeProvidersSetter) SetProviders(federationDomains ...*provider.FederationDomainIssuer) {
	f.SetProvidersWasCalled = true
	f.FederationDomainsReceived = federationDomains
}

func TestSync(t *testing.T) {
	spec.Run(t, "Sync", func(t *testing.T, when spec.G, it spec.S) {
		const namespace = "some-namespace"

		var r *require.Assertions

		var subject controllerlib.Controller
		var federationDomainInformerClient *pinnipedfake.Clientset
		var federationDomainInformers pinnipedinformers.SharedInformerFactory
		var pinnipedAPIClient *pinnipedfake.Clientset
		var timeoutContext context.Context
		var timeoutContextCancel context.CancelFunc
		var syncContext *controllerlib.Context
		var frozenNow time.Time
		var providersSetter *fakeProvidersSetter
		var federationDomainGVR schema.GroupVersionResource

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewFederationDomainWatcherController(
				providersSetter,
				clock.NewFakeClock(frozenNow),
				pinnipedAPIClient,
				federationDomainInformers.Config().V1alpha1().FederationDomains(),
				controllerlib.WithInformer,
			)

			// Set this at the last second to support calling subject.Name().
			syncContext = &controllerlib.Context{
				Context: timeoutContext,
				Name:    subject.Name(),
				Key: controllerlib.Key{
					Namespace: namespace,
					Name:      "config-name",
				},
			}

			// Must start informers before calling TestRunSynchronously()
			federationDomainInformers.Start(timeoutContext.Done())
			controllerlib.TestRunSynchronously(t, subject)
		}

		it.Before(func() {
			r = require.New(t)

			providersSetter = &fakeProvidersSetter{}
			frozenNow = time.Date(2020, time.September, 23, 7, 42, 0, 0, time.Local)

			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)

			federationDomainInformerClient = pinnipedfake.NewSimpleClientset()
			federationDomainInformers = pinnipedinformers.NewSharedInformerFactory(federationDomainInformerClient, 0)
			pinnipedAPIClient = pinnipedfake.NewSimpleClientset()

			federationDomainGVR = schema.GroupVersionResource{
				Group:    v1alpha1.SchemeGroupVersion.Group,
				Version:  v1alpha1.SchemeGroupVersion.Version,
				Resource: "federationdomains",
			}
		})

		it.After(func() {
			timeoutContextCancel()
		})

		when("there are some valid FederationDomains in the informer", func() {
			var (
				federationDomain1 *v1alpha1.FederationDomain
				federationDomain2 *v1alpha1.FederationDomain
			)

			it.Before(func() {
				federationDomain1 = &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace},
					Spec:       v1alpha1.FederationDomainSpec{Issuer: "https://issuer1.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomain1))
				r.NoError(federationDomainInformerClient.Tracker().Add(federationDomain1))

				federationDomain2 = &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config2", Namespace: namespace},
					Spec:       v1alpha1.FederationDomainSpec{Issuer: "https://issuer2.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomain2))
				r.NoError(federationDomainInformerClient.Tracker().Add(federationDomain2))
			})

			it("calls the ProvidersSetter", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				provider1, err := provider.NewFederationDomainIssuer(federationDomain1.Spec.Issuer)
				r.NoError(err)

				provider2, err := provider.NewFederationDomainIssuer(federationDomain2.Spec.Issuer)
				r.NoError(err)

				r.True(providersSetter.SetProvidersWasCalled)
				r.ElementsMatch(
					[]*provider.FederationDomainIssuer{
						provider1,
						provider2,
					},
					providersSetter.FederationDomainsReceived,
				)
			})

			it("updates the status to success in the FederationDomains", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				federationDomain1.Status.Status = v1alpha1.SuccessFederationDomainStatusCondition
				federationDomain1.Status.Message = "Provider successfully created"
				federationDomain1.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				federationDomain2.Status.Status = v1alpha1.SuccessFederationDomainStatusCondition
				federationDomain2.Status.Message = "Provider successfully created"
				federationDomain2.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				expectedActions := []coretesting.Action{
					coretesting.NewGetAction(
						federationDomainGVR,
						federationDomain1.Namespace,
						federationDomain1.Name,
					),
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						federationDomain1.Namespace,
						federationDomain1,
					),
					coretesting.NewGetAction(
						federationDomainGVR,
						federationDomain2.Namespace,
						federationDomain2.Name,
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
					federationDomain1.Status.Status = v1alpha1.SuccessFederationDomainStatusCondition
					federationDomain1.Status.Message = "Provider successfully created"
					federationDomain1.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					r.NoError(pinnipedAPIClient.Tracker().Update(federationDomainGVR, federationDomain1, federationDomain1.Namespace))
					r.NoError(federationDomainInformerClient.Tracker().Update(federationDomainGVR, federationDomain1, federationDomain1.Namespace))
				})

				it("only updates the out-of-date FederationDomain", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.NoError(err)

					federationDomain2.Status.Status = v1alpha1.SuccessFederationDomainStatusCondition
					federationDomain2.Status.Message = "Provider successfully created"
					federationDomain2.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							federationDomainGVR,
							federationDomain1.Namespace,
							federationDomain1.Name,
						),
						coretesting.NewGetAction(
							federationDomainGVR,
							federationDomain2.Namespace,
							federationDomain2.Name,
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

				it("calls the ProvidersSetter with both FederationDomain's", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.NoError(err)

					provider1, err := provider.NewFederationDomainIssuer(federationDomain1.Spec.Issuer)
					r.NoError(err)

					provider2, err := provider.NewFederationDomainIssuer(federationDomain2.Spec.Issuer)
					r.NoError(err)

					r.True(providersSetter.SetProvidersWasCalled)
					r.ElementsMatch(
						[]*provider.FederationDomainIssuer{
							provider1,
							provider2,
						},
						providersSetter.FederationDomainsReceived,
					)
				})
			})

			when("updating only one FederationDomain fails for a reason other than conflict", func() {
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

				it("sets the provider that it could actually update in the API", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "could not update status: some update error")

					provider1, err := provider.NewFederationDomainIssuer(federationDomain1.Spec.Issuer)
					r.NoError(err)

					provider2, err := provider.NewFederationDomainIssuer(federationDomain2.Spec.Issuer)
					r.NoError(err)

					r.True(providersSetter.SetProvidersWasCalled)
					r.Len(providersSetter.FederationDomainsReceived, 1)
					r.True(
						reflect.DeepEqual(providersSetter.FederationDomainsReceived[0], provider1) ||
							reflect.DeepEqual(providersSetter.FederationDomainsReceived[0], provider2),
					)
				})

				it("returns an error", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "could not update status: some update error")

					federationDomain1.Status.Status = v1alpha1.SuccessFederationDomainStatusCondition
					federationDomain1.Status.Message = "Provider successfully created"
					federationDomain1.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					federationDomain2.Status.Status = v1alpha1.SuccessFederationDomainStatusCondition
					federationDomain2.Status.Message = "Provider successfully created"
					federationDomain2.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							federationDomainGVR,
							federationDomain1.Namespace,
							federationDomain1.Name,
						),
						coretesting.NewUpdateSubresourceAction(
							federationDomainGVR,
							"status",
							federationDomain1.Namespace,
							federationDomain1,
						),
						coretesting.NewGetAction(
							federationDomainGVR,
							federationDomain2.Namespace,
							federationDomain2.Name,
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
				federationDomain *v1alpha1.FederationDomain
			)

			it.Before(func() {
				federationDomain = &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: namespace},
					Spec:       v1alpha1.FederationDomainSpec{Issuer: "https://issuer.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomain))
				r.NoError(federationDomainInformerClient.Tracker().Add(federationDomain))
			})

			when("there is a conflict while updating an FederationDomain", func() {
				it.Before(func() {
					once := sync.Once{}
					pinnipedAPIClient.PrependReactor(
						"update",
						"federationdomains",
						func(_ coretesting.Action) (bool, runtime.Object, error) {
							var err error
							once.Do(func() {
								err = k8serrors.NewConflict(schema.GroupResource{}, "", nil)
							})
							return true, nil, err
						},
					)
				})

				it("retries updating the FederationDomain", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.NoError(err)

					federationDomain.Status.Status = v1alpha1.SuccessFederationDomainStatusCondition
					federationDomain.Status.Message = "Provider successfully created"
					federationDomain.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							federationDomainGVR,
							federationDomain.Namespace,
							federationDomain.Name,
						),
						coretesting.NewUpdateSubresourceAction(
							federationDomainGVR,
							"status",
							federationDomain.Namespace,
							federationDomain,
						),
						coretesting.NewGetAction(
							federationDomainGVR,
							federationDomain.Namespace,
							federationDomain.Name,
						),
						coretesting.NewUpdateSubresourceAction(
							federationDomainGVR,
							"status",
							federationDomain.Namespace,
							federationDomain,
						),
					}
					r.Equal(expectedActions, pinnipedAPIClient.Actions())
				})
			})

			when("updating the FederationDomain fails for a reason other than conflict", func() {
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

					federationDomain.Status.Status = v1alpha1.SuccessFederationDomainStatusCondition
					federationDomain.Status.Message = "Provider successfully created"
					federationDomain.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							federationDomainGVR,
							federationDomain.Namespace,
							federationDomain.Name,
						),
						coretesting.NewUpdateSubresourceAction(
							federationDomainGVR,
							"status",
							federationDomain.Namespace,
							federationDomain,
						),
					}
					r.Equal(expectedActions, pinnipedAPIClient.Actions())
				})
			})

			when("there is an error when getting the FederationDomain", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"get",
						"federationdomains",
						func(_ coretesting.Action) (bool, runtime.Object, error) {
							return true, nil, errors.New("some get error")
						},
					)
				})

				it("returns the get error", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "could not update status: get failed: some get error")

					federationDomain.Status.Status = v1alpha1.SuccessFederationDomainStatusCondition
					federationDomain.Status.Message = "Provider successfully created"
					federationDomain.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							federationDomainGVR,
							federationDomain.Namespace,
							federationDomain.Name,
						),
					}
					r.Equal(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are both valid and invalid FederationDomains in the informer", func() {
			var (
				validFederationDomain   *v1alpha1.FederationDomain
				invalidFederationDomain *v1alpha1.FederationDomain
			)

			it.Before(func() {
				validFederationDomain = &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "valid-config", Namespace: namespace},
					Spec:       v1alpha1.FederationDomainSpec{Issuer: "https://valid-issuer.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(validFederationDomain))
				r.NoError(federationDomainInformerClient.Tracker().Add(validFederationDomain))

				invalidFederationDomain = &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "invalid-config", Namespace: namespace},
					Spec:       v1alpha1.FederationDomainSpec{Issuer: "https://invalid-issuer.com?some=query"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(invalidFederationDomain))
				r.NoError(federationDomainInformerClient.Tracker().Add(invalidFederationDomain))
			})

			it("calls the ProvidersSetter with the valid provider", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				validProvider, err := provider.NewFederationDomainIssuer(validFederationDomain.Spec.Issuer)
				r.NoError(err)

				r.True(providersSetter.SetProvidersWasCalled)
				r.Equal(
					[]*provider.FederationDomainIssuer{
						validProvider,
					},
					providersSetter.FederationDomainsReceived,
				)
			})

			it("updates the status to success/invalid in the FederationDomains", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				validFederationDomain.Status.Status = v1alpha1.SuccessFederationDomainStatusCondition
				validFederationDomain.Status.Message = "Provider successfully created"
				validFederationDomain.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				invalidFederationDomain.Status.Status = v1alpha1.InvalidFederationDomainStatusCondition
				invalidFederationDomain.Status.Message = "Invalid: issuer must not have query"
				invalidFederationDomain.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				expectedActions := []coretesting.Action{
					coretesting.NewGetAction(
						federationDomainGVR,
						invalidFederationDomain.Namespace,
						invalidFederationDomain.Name,
					),
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						invalidFederationDomain.Namespace,
						invalidFederationDomain,
					),
					coretesting.NewGetAction(
						federationDomainGVR,
						validFederationDomain.Namespace,
						validFederationDomain.Name,
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

			when("updating only the invalid FederationDomain fails for a reason other than conflict", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"update",
						"federationdomains",
						func(action coretesting.Action) (bool, runtime.Object, error) {
							updateAction := action.(coretesting.UpdateActionImpl)
							federationDomain := updateAction.Object.(*v1alpha1.FederationDomain)
							if federationDomain.Name == validFederationDomain.Name {
								return true, nil, nil
							}

							return true, nil, errors.New("some update error")
						},
					)
				})

				it("sets the provider that it could actually update in the API", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "could not update status: some update error")

					validProvider, err := provider.NewFederationDomainIssuer(validFederationDomain.Spec.Issuer)
					r.NoError(err)

					r.True(providersSetter.SetProvidersWasCalled)
					r.Equal(
						[]*provider.FederationDomainIssuer{
							validProvider,
						},
						providersSetter.FederationDomainsReceived,
					)
				})

				it("returns an error", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "could not update status: some update error")

					validFederationDomain.Status.Status = v1alpha1.SuccessFederationDomainStatusCondition
					validFederationDomain.Status.Message = "Provider successfully created"
					validFederationDomain.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					invalidFederationDomain.Status.Status = v1alpha1.InvalidFederationDomainStatusCondition
					invalidFederationDomain.Status.Message = "Invalid: issuer must not have query"
					invalidFederationDomain.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							federationDomainGVR,
							invalidFederationDomain.Namespace,
							invalidFederationDomain.Name,
						),
						coretesting.NewUpdateSubresourceAction(
							federationDomainGVR,
							"status",
							invalidFederationDomain.Namespace,
							invalidFederationDomain,
						),
						coretesting.NewGetAction(
							federationDomainGVR,
							validFederationDomain.Namespace,
							validFederationDomain.Name,
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
				federationDomainDuplicate1 *v1alpha1.FederationDomain
				federationDomainDuplicate2 *v1alpha1.FederationDomain
				federationDomain           *v1alpha1.FederationDomain
			)

			it.Before(func() {
				// Hostnames are case-insensitive, so consider them to be duplicates if they only differ by case.
				// Paths are case-sensitive, so having a path that differs only by case makes a new issuer.
				federationDomainDuplicate1 = &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "duplicate1", Namespace: namespace},
					Spec:       v1alpha1.FederationDomainSpec{Issuer: "https://iSSueR-duPlicAte.cOm/a"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomainDuplicate1))
				r.NoError(federationDomainInformerClient.Tracker().Add(federationDomainDuplicate1))
				federationDomainDuplicate2 = &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "duplicate2", Namespace: namespace},
					Spec:       v1alpha1.FederationDomainSpec{Issuer: "https://issuer-duplicate.com/a"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomainDuplicate2))
				r.NoError(federationDomainInformerClient.Tracker().Add(federationDomainDuplicate2))

				federationDomain = &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "not-duplicate", Namespace: namespace},
					Spec:       v1alpha1.FederationDomainSpec{Issuer: "https://issuer-duplicate.com/A"}, // different path
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomain))
				r.NoError(federationDomainInformerClient.Tracker().Add(federationDomain))
			})

			it("calls the ProvidersSetter with the non-duplicate", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				nonDuplicateProvider, err := provider.NewFederationDomainIssuer(federationDomain.Spec.Issuer)
				r.NoError(err)

				r.True(providersSetter.SetProvidersWasCalled)
				r.Equal(
					[]*provider.FederationDomainIssuer{
						nonDuplicateProvider,
					},
					providersSetter.FederationDomainsReceived,
				)
			})

			it("updates the statuses", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				federationDomain.Status.Status = v1alpha1.SuccessFederationDomainStatusCondition
				federationDomain.Status.Message = "Provider successfully created"
				federationDomain.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				federationDomainDuplicate1.Status.Status = v1alpha1.DuplicateFederationDomainStatusCondition
				federationDomainDuplicate1.Status.Message = "Duplicate issuer: https://iSSueR-duPlicAte.cOm/a"
				federationDomainDuplicate1.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				federationDomainDuplicate2.Status.Status = v1alpha1.DuplicateFederationDomainStatusCondition
				federationDomainDuplicate2.Status.Message = "Duplicate issuer: https://issuer-duplicate.com/a"
				federationDomainDuplicate2.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				expectedActions := []coretesting.Action{
					coretesting.NewGetAction(
						federationDomainGVR,
						federationDomainDuplicate1.Namespace,
						federationDomainDuplicate1.Name,
					),
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						federationDomainDuplicate1.Namespace,
						federationDomainDuplicate1,
					),
					coretesting.NewGetAction(
						federationDomainGVR,
						federationDomainDuplicate2.Namespace,
						federationDomainDuplicate2.Name,
					),
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						federationDomainDuplicate2.Namespace,
						federationDomainDuplicate2,
					),
					coretesting.NewGetAction(
						federationDomainGVR,
						federationDomain.Namespace,
						federationDomain.Name,
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

			when("we cannot talk to the API", func() {
				var count int
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"get",
						"federationdomains",
						func(_ coretesting.Action) (bool, runtime.Object, error) {
							count++
							return true, nil, fmt.Errorf("some get error %d", count)
						},
					)
				})

				it("returns the get errors", func() {
					expectedError := here.Doc(`[could not update status: get failed: some get error 1, could not update status: get failed: some get error 2, could not update status: get failed: some get error 3]`)
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, expectedError)

					federationDomain.Status.Status = v1alpha1.SuccessFederationDomainStatusCondition
					federationDomain.Status.Message = "Provider successfully created"
					federationDomain.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							federationDomainGVR,
							federationDomainDuplicate1.Namespace,
							federationDomainDuplicate1.Name,
						),
						coretesting.NewGetAction(
							federationDomainGVR,
							federationDomainDuplicate2.Namespace,
							federationDomainDuplicate2.Name,
						),
						coretesting.NewGetAction(
							federationDomainGVR,
							federationDomain.Namespace,
							federationDomain.Name,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are FederationDomains with the same issuer DNS hostname using different secretNames", func() {
			var (
				federationDomainSameIssuerAddress1     *v1alpha1.FederationDomain
				federationDomainSameIssuerAddress2     *v1alpha1.FederationDomain
				federationDomainDifferentIssuerAddress *v1alpha1.FederationDomain
				federationDomainWithInvalidIssuerURL   *v1alpha1.FederationDomain
			)

			it.Before(func() {
				federationDomainSameIssuerAddress1 = &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "provider1", Namespace: namespace},
					Spec: v1alpha1.FederationDomainSpec{
						Issuer: "https://iSSueR-duPlicAte-adDress.cOm/path1",
						TLS:    &v1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomainSameIssuerAddress1))
				r.NoError(federationDomainInformerClient.Tracker().Add(federationDomainSameIssuerAddress1))
				federationDomainSameIssuerAddress2 = &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "provider2", Namespace: namespace},
					Spec: v1alpha1.FederationDomainSpec{
						// Validation treats these as the same DNS hostname even though they have different port numbers,
						// because SNI information on the incoming requests is not going to include port numbers.
						Issuer: "https://issuer-duplicate-address.com:1234/path2",
						TLS:    &v1alpha1.FederationDomainTLSSpec{SecretName: "secret2"},
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomainSameIssuerAddress2))
				r.NoError(federationDomainInformerClient.Tracker().Add(federationDomainSameIssuerAddress2))

				federationDomainDifferentIssuerAddress = &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "differentIssuerAddressProvider", Namespace: namespace},
					Spec: v1alpha1.FederationDomainSpec{
						Issuer: "https://issuer-not-duplicate.com",
						TLS:    &v1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomainDifferentIssuerAddress))
				r.NoError(federationDomainInformerClient.Tracker().Add(federationDomainDifferentIssuerAddress))

				// Also add one with a URL that cannot be parsed to make sure that the error handling
				// for the duplicate issuers and secret names are not confused by invalid URLs.
				invalidIssuerURL := ":/host//path"
				_, err := url.Parse(invalidIssuerURL) //nolint:staticcheck // Yes, this URL is intentionally invalid.
				r.Error(err)
				federationDomainWithInvalidIssuerURL = &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{Name: "invalidIssuerURLProvider", Namespace: namespace},
					Spec: v1alpha1.FederationDomainSpec{
						Issuer: invalidIssuerURL,
						TLS:    &v1alpha1.FederationDomainTLSSpec{SecretName: "secret1"},
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(federationDomainWithInvalidIssuerURL))
				r.NoError(federationDomainInformerClient.Tracker().Add(federationDomainWithInvalidIssuerURL))
			})

			it("calls the ProvidersSetter with the non-duplicate", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				nonDuplicateProvider, err := provider.NewFederationDomainIssuer(federationDomainDifferentIssuerAddress.Spec.Issuer)
				r.NoError(err)

				r.True(providersSetter.SetProvidersWasCalled)
				r.Equal(
					[]*provider.FederationDomainIssuer{
						nonDuplicateProvider,
					},
					providersSetter.FederationDomainsReceived,
				)
			})

			it("updates the statuses", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				federationDomainDifferentIssuerAddress.Status.Status = v1alpha1.SuccessFederationDomainStatusCondition
				federationDomainDifferentIssuerAddress.Status.Message = "Provider successfully created"
				federationDomainDifferentIssuerAddress.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				federationDomainSameIssuerAddress1.Status.Status = v1alpha1.SameIssuerHostMustUseSameSecretFederationDomainStatusCondition
				federationDomainSameIssuerAddress1.Status.Message = "Issuers with the same DNS hostname (address not including port) must use the same secretName: issuer-duplicate-address.com"
				federationDomainSameIssuerAddress1.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				federationDomainSameIssuerAddress2.Status.Status = v1alpha1.SameIssuerHostMustUseSameSecretFederationDomainStatusCondition
				federationDomainSameIssuerAddress2.Status.Message = "Issuers with the same DNS hostname (address not including port) must use the same secretName: issuer-duplicate-address.com"
				federationDomainSameIssuerAddress2.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				federationDomainWithInvalidIssuerURL.Status.Status = v1alpha1.InvalidFederationDomainStatusCondition
				federationDomainWithInvalidIssuerURL.Status.Message = `Invalid: could not parse issuer as URL: parse ":/host//path": missing protocol scheme`
				federationDomainWithInvalidIssuerURL.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				expectedActions := []coretesting.Action{
					coretesting.NewGetAction(
						federationDomainGVR,
						federationDomainSameIssuerAddress1.Namespace,
						federationDomainSameIssuerAddress1.Name,
					),
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						federationDomainSameIssuerAddress1.Namespace,
						federationDomainSameIssuerAddress1,
					),
					coretesting.NewGetAction(
						federationDomainGVR,
						federationDomainSameIssuerAddress2.Namespace,
						federationDomainSameIssuerAddress2.Name,
					),
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						federationDomainSameIssuerAddress2.Namespace,
						federationDomainSameIssuerAddress2,
					),
					coretesting.NewGetAction(
						federationDomainGVR,
						federationDomainDifferentIssuerAddress.Namespace,
						federationDomainDifferentIssuerAddress.Name,
					),
					coretesting.NewUpdateSubresourceAction(
						federationDomainGVR,
						"status",
						federationDomainDifferentIssuerAddress.Namespace,
						federationDomainDifferentIssuerAddress,
					),
					coretesting.NewGetAction(
						federationDomainGVR,
						federationDomainWithInvalidIssuerURL.Namespace,
						federationDomainWithInvalidIssuerURL.Name,
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

			when("we cannot talk to the API", func() {
				var count int
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"get",
						"federationdomains",
						func(_ coretesting.Action) (bool, runtime.Object, error) {
							count++
							return true, nil, fmt.Errorf("some get error %d", count)
						},
					)
				})

				it("returns the get errors", func() {
					expectedError := here.Doc(`[could not update status: get failed: some get error 1, could not update status: get failed: some get error 2, could not update status: get failed: some get error 3, could not update status: get failed: some get error 4]`)
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, expectedError)

					federationDomainDifferentIssuerAddress.Status.Status = v1alpha1.SuccessFederationDomainStatusCondition
					federationDomainDifferentIssuerAddress.Status.Message = "Provider successfully created"
					federationDomainDifferentIssuerAddress.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							federationDomainGVR,
							federationDomainSameIssuerAddress1.Namespace,
							federationDomainSameIssuerAddress1.Name,
						),
						coretesting.NewGetAction(
							federationDomainGVR,
							federationDomainSameIssuerAddress2.Namespace,
							federationDomainSameIssuerAddress2.Name,
						),
						coretesting.NewGetAction(
							federationDomainGVR,
							federationDomainDifferentIssuerAddress.Namespace,
							federationDomainDifferentIssuerAddress.Name,
						),
						coretesting.NewGetAction(
							federationDomainGVR,
							federationDomainWithInvalidIssuerURL.Namespace,
							federationDomainWithInvalidIssuerURL.Name,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are no FederationDomains in the informer", func() {
			it("keeps waiting for one", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)
				r.Empty(pinnipedAPIClient.Actions())
				r.True(providersSetter.SetProvidersWasCalled)
				r.Empty(providersSetter.FederationDomainsReceived)
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
