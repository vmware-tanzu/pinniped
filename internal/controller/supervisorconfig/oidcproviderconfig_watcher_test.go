// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"errors"
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

	"go.pinniped.dev/generated/1.19/apis/supervisor/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/1.19/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/1.19/client/supervisor/informers/externalversions"
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
			opcInformer := pinnipedinformers.NewSharedInformerFactoryWithOptions(nil, 0).Config().V1alpha1().OIDCProviders()
			_ = NewOIDCProviderWatcherController(
				nil,
				nil,
				nil,
				opcInformer,
				observableWithInformerOption.WithInformer, // make it possible to observe the behavior of the Filters
			)
			configMapInformerFilter = observableWithInformerOption.GetFilterForInformer(opcInformer)
		})

		when("watching OIDCProvider objects", func() {
			var subject controllerlib.Filter
			var target, otherNamespace, otherName *v1alpha1.OIDCProvider

			it.Before(func() {
				subject = configMapInformerFilter
				target = &v1alpha1.OIDCProvider{ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"}}
				otherNamespace = &v1alpha1.OIDCProvider{ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "other-namespace"}}
				otherName = &v1alpha1.OIDCProvider{ObjectMeta: metav1.ObjectMeta{Name: "other-name", Namespace: "some-namespace"}}
			})

			when("any OIDCProvider changes", func() {
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
	SetProvidersWasCalled bool
	OIDCProvidersReceived []*provider.OIDCProvider
}

func (f *fakeProvidersSetter) SetProviders(oidcProviders ...*provider.OIDCProvider) {
	f.SetProvidersWasCalled = true
	f.OIDCProvidersReceived = oidcProviders
}

func TestSync(t *testing.T) {
	spec.Run(t, "Sync", func(t *testing.T, when spec.G, it spec.S) {
		const namespace = "some-namespace"

		var r *require.Assertions

		var subject controllerlib.Controller
		var opcInformerClient *pinnipedfake.Clientset
		var opcInformers pinnipedinformers.SharedInformerFactory
		var pinnipedAPIClient *pinnipedfake.Clientset
		var timeoutContext context.Context
		var timeoutContextCancel context.CancelFunc
		var syncContext *controllerlib.Context
		var frozenNow time.Time
		var providersSetter *fakeProvidersSetter
		var oidcProviderGVR schema.GroupVersionResource

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewOIDCProviderWatcherController(
				providersSetter,
				clock.NewFakeClock(frozenNow),
				pinnipedAPIClient,
				opcInformers.Config().V1alpha1().OIDCProviders(),
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
			opcInformers.Start(timeoutContext.Done())
			controllerlib.TestRunSynchronously(t, subject)
		}

		it.Before(func() {
			r = require.New(t)

			providersSetter = &fakeProvidersSetter{}
			frozenNow = time.Date(2020, time.September, 23, 7, 42, 0, 0, time.Local)

			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)

			opcInformerClient = pinnipedfake.NewSimpleClientset()
			opcInformers = pinnipedinformers.NewSharedInformerFactory(opcInformerClient, 0)
			pinnipedAPIClient = pinnipedfake.NewSimpleClientset()

			oidcProviderGVR = schema.GroupVersionResource{
				Group:    v1alpha1.SchemeGroupVersion.Group,
				Version:  v1alpha1.SchemeGroupVersion.Version,
				Resource: "oidcproviders",
			}
		})

		it.After(func() {
			timeoutContextCancel()
		})

		when("there are some valid OIDCProviders in the informer", func() {
			var (
				oidcProvider1 *v1alpha1.OIDCProvider
				oidcProvider2 *v1alpha1.OIDCProvider
			)

			it.Before(func() {
				oidcProvider1 = &v1alpha1.OIDCProvider{
					ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderSpec{Issuer: "https://issuer1.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProvider1))
				r.NoError(opcInformerClient.Tracker().Add(oidcProvider1))

				oidcProvider2 = &v1alpha1.OIDCProvider{
					ObjectMeta: metav1.ObjectMeta{Name: "config2", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderSpec{Issuer: "https://issuer2.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProvider2))
				r.NoError(opcInformerClient.Tracker().Add(oidcProvider2))
			})

			it("calls the ProvidersSetter", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				provider1, err := provider.NewOIDCProvider(oidcProvider1.Spec.Issuer)
				r.NoError(err)

				provider2, err := provider.NewOIDCProvider(oidcProvider2.Spec.Issuer)
				r.NoError(err)

				r.True(providersSetter.SetProvidersWasCalled)
				r.ElementsMatch(
					[]*provider.OIDCProvider{
						provider1,
						provider2,
					},
					providersSetter.OIDCProvidersReceived,
				)
			})

			it("updates the status to success in the OIDCProviders", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				oidcProvider1.Status.Status = v1alpha1.SuccessOIDCProviderStatusCondition
				oidcProvider1.Status.Message = "Provider successfully created"
				oidcProvider1.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				oidcProvider2.Status.Status = v1alpha1.SuccessOIDCProviderStatusCondition
				oidcProvider2.Status.Message = "Provider successfully created"
				oidcProvider2.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				expectedActions := []coretesting.Action{
					coretesting.NewGetAction(
						oidcProviderGVR,
						oidcProvider1.Namespace,
						oidcProvider1.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderGVR,
						oidcProvider1.Namespace,
						oidcProvider1,
					),
					coretesting.NewGetAction(
						oidcProviderGVR,
						oidcProvider2.Namespace,
						oidcProvider2.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderGVR,
						oidcProvider2.Namespace,
						oidcProvider2,
					),
				}
				r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
			})

			when("one OIDCProvider is already up to date", func() {
				it.Before(func() {
					oidcProvider1.Status.Status = v1alpha1.SuccessOIDCProviderStatusCondition
					oidcProvider1.Status.Message = "Provider successfully created"
					oidcProvider1.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					r.NoError(pinnipedAPIClient.Tracker().Update(oidcProviderGVR, oidcProvider1, oidcProvider1.Namespace))
					r.NoError(opcInformerClient.Tracker().Update(oidcProviderGVR, oidcProvider1, oidcProvider1.Namespace))
				})

				it("only updates the out-of-date OIDCProvider", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.NoError(err)

					oidcProvider2.Status.Status = v1alpha1.SuccessOIDCProviderStatusCondition
					oidcProvider2.Status.Message = "Provider successfully created"
					oidcProvider2.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderGVR,
							oidcProvider1.Namespace,
							oidcProvider1.Name,
						),
						coretesting.NewGetAction(
							oidcProviderGVR,
							oidcProvider2.Namespace,
							oidcProvider2.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderGVR,
							oidcProvider2.Namespace,
							oidcProvider2,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})

				it("calls the ProvidersSetter with both OIDCProvider's", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.NoError(err)

					provider1, err := provider.NewOIDCProvider(oidcProvider1.Spec.Issuer)
					r.NoError(err)

					provider2, err := provider.NewOIDCProvider(oidcProvider2.Spec.Issuer)
					r.NoError(err)

					r.True(providersSetter.SetProvidersWasCalled)
					r.ElementsMatch(
						[]*provider.OIDCProvider{
							provider1,
							provider2,
						},
						providersSetter.OIDCProvidersReceived,
					)
				})
			})

			when("updating only one OIDCProvider fails for a reason other than conflict", func() {
				it.Before(func() {
					once := sync.Once{}
					pinnipedAPIClient.PrependReactor(
						"update",
						"oidcproviders",
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
					r.EqualError(err, "1 error(s):\n- could not update status: some update error")

					provider1, err := provider.NewOIDCProvider(oidcProvider1.Spec.Issuer)
					r.NoError(err)

					provider2, err := provider.NewOIDCProvider(oidcProvider2.Spec.Issuer)
					r.NoError(err)

					r.True(providersSetter.SetProvidersWasCalled)
					r.Len(providersSetter.OIDCProvidersReceived, 1)
					r.True(
						reflect.DeepEqual(providersSetter.OIDCProvidersReceived[0], provider1) ||
							reflect.DeepEqual(providersSetter.OIDCProvidersReceived[0], provider2),
					)
				})

				it("returns an error", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "1 error(s):\n- could not update status: some update error")

					oidcProvider1.Status.Status = v1alpha1.SuccessOIDCProviderStatusCondition
					oidcProvider1.Status.Message = "Provider successfully created"
					oidcProvider1.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					oidcProvider2.Status.Status = v1alpha1.SuccessOIDCProviderStatusCondition
					oidcProvider2.Status.Message = "Provider successfully created"
					oidcProvider2.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderGVR,
							oidcProvider1.Namespace,
							oidcProvider1.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderGVR,
							oidcProvider1.Namespace,
							oidcProvider1,
						),
						coretesting.NewGetAction(
							oidcProviderGVR,
							oidcProvider2.Namespace,
							oidcProvider2.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderGVR,
							oidcProvider2.Namespace,
							oidcProvider2,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are errors updating the OIDCProviders", func() {
			var (
				oidcProvider *v1alpha1.OIDCProvider
			)

			it.Before(func() {
				oidcProvider = &v1alpha1.OIDCProvider{
					ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderSpec{Issuer: "https://issuer.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProvider))
				r.NoError(opcInformerClient.Tracker().Add(oidcProvider))
			})

			when("there is a conflict while updating an OIDCProvider", func() {
				it.Before(func() {
					once := sync.Once{}
					pinnipedAPIClient.PrependReactor(
						"update",
						"oidcproviders",
						func(_ coretesting.Action) (bool, runtime.Object, error) {
							var err error
							once.Do(func() {
								err = k8serrors.NewConflict(schema.GroupResource{}, "", nil)
							})
							return true, nil, err
						},
					)
				})

				it("retries updating the OIDCProvider", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.NoError(err)

					oidcProvider.Status.Status = v1alpha1.SuccessOIDCProviderStatusCondition
					oidcProvider.Status.Message = "Provider successfully created"
					oidcProvider.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderGVR,
							oidcProvider.Namespace,
							oidcProvider.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderGVR,
							oidcProvider.Namespace,
							oidcProvider,
						),
						coretesting.NewGetAction(
							oidcProviderGVR,
							oidcProvider.Namespace,
							oidcProvider.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderGVR,
							oidcProvider.Namespace,
							oidcProvider,
						),
					}
					r.Equal(expectedActions, pinnipedAPIClient.Actions())
				})
			})

			when("updating the OIDCProvider fails for a reason other than conflict", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"update",
						"oidcproviders",
						func(_ coretesting.Action) (bool, runtime.Object, error) {
							return true, nil, errors.New("some update error")
						},
					)
				})

				it("returns an error", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "1 error(s):\n- could not update status: some update error")

					oidcProvider.Status.Status = v1alpha1.SuccessOIDCProviderStatusCondition
					oidcProvider.Status.Message = "Provider successfully created"
					oidcProvider.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderGVR,
							oidcProvider.Namespace,
							oidcProvider.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderGVR,
							oidcProvider.Namespace,
							oidcProvider,
						),
					}
					r.Equal(expectedActions, pinnipedAPIClient.Actions())
				})
			})

			when("there is an error when getting the OIDCProvider", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"get",
						"oidcproviders",
						func(_ coretesting.Action) (bool, runtime.Object, error) {
							return true, nil, errors.New("some get error")
						},
					)
				})

				it("returns the get error", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "1 error(s):\n- could not update status: get failed: some get error")

					oidcProvider.Status.Status = v1alpha1.SuccessOIDCProviderStatusCondition
					oidcProvider.Status.Message = "Provider successfully created"
					oidcProvider.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderGVR,
							oidcProvider.Namespace,
							oidcProvider.Name,
						),
					}
					r.Equal(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are both valid and invalid OIDCProviders in the informer", func() {
			var (
				validOIDCProvider   *v1alpha1.OIDCProvider
				invalidOIDCProvider *v1alpha1.OIDCProvider
			)

			it.Before(func() {
				validOIDCProvider = &v1alpha1.OIDCProvider{
					ObjectMeta: metav1.ObjectMeta{Name: "valid-config", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderSpec{Issuer: "https://valid-issuer.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(validOIDCProvider))
				r.NoError(opcInformerClient.Tracker().Add(validOIDCProvider))

				invalidOIDCProvider = &v1alpha1.OIDCProvider{
					ObjectMeta: metav1.ObjectMeta{Name: "invalid-config", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderSpec{Issuer: "https://invalid-issuer.com?some=query"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(invalidOIDCProvider))
				r.NoError(opcInformerClient.Tracker().Add(invalidOIDCProvider))
			})

			it("calls the ProvidersSetter with the valid provider", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				validProvider, err := provider.NewOIDCProvider(validOIDCProvider.Spec.Issuer)
				r.NoError(err)

				r.True(providersSetter.SetProvidersWasCalled)
				r.Equal(
					[]*provider.OIDCProvider{
						validProvider,
					},
					providersSetter.OIDCProvidersReceived,
				)
			})

			it("updates the status to success/invalid in the OIDCProviders", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				validOIDCProvider.Status.Status = v1alpha1.SuccessOIDCProviderStatusCondition
				validOIDCProvider.Status.Message = "Provider successfully created"
				validOIDCProvider.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				invalidOIDCProvider.Status.Status = v1alpha1.InvalidOIDCProviderStatusCondition
				invalidOIDCProvider.Status.Message = "Invalid: issuer must not have query"
				invalidOIDCProvider.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				expectedActions := []coretesting.Action{
					coretesting.NewGetAction(
						oidcProviderGVR,
						invalidOIDCProvider.Namespace,
						invalidOIDCProvider.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderGVR,
						invalidOIDCProvider.Namespace,
						invalidOIDCProvider,
					),
					coretesting.NewGetAction(
						oidcProviderGVR,
						validOIDCProvider.Namespace,
						validOIDCProvider.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderGVR,
						validOIDCProvider.Namespace,
						validOIDCProvider,
					),
				}
				r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
			})

			when("updating only the invalid OIDCProvider fails for a reason other than conflict", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"update",
						"oidcproviders",
						func(action coretesting.Action) (bool, runtime.Object, error) {
							updateAction := action.(coretesting.UpdateActionImpl)
							opc := updateAction.Object.(*v1alpha1.OIDCProvider)
							if opc.Name == validOIDCProvider.Name {
								return true, nil, nil
							}

							return true, nil, errors.New("some update error")
						},
					)
				})

				it("sets the provider that it could actually update in the API", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "1 error(s):\n- could not update status: some update error")

					validProvider, err := provider.NewOIDCProvider(validOIDCProvider.Spec.Issuer)
					r.NoError(err)

					r.True(providersSetter.SetProvidersWasCalled)
					r.Equal(
						[]*provider.OIDCProvider{
							validProvider,
						},
						providersSetter.OIDCProvidersReceived,
					)
				})

				it("returns an error", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "1 error(s):\n- could not update status: some update error")

					validOIDCProvider.Status.Status = v1alpha1.SuccessOIDCProviderStatusCondition
					validOIDCProvider.Status.Message = "Provider successfully created"
					validOIDCProvider.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					invalidOIDCProvider.Status.Status = v1alpha1.InvalidOIDCProviderStatusCondition
					invalidOIDCProvider.Status.Message = "Invalid: issuer must not have query"
					invalidOIDCProvider.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderGVR,
							invalidOIDCProvider.Namespace,
							invalidOIDCProvider.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderGVR,
							invalidOIDCProvider.Namespace,
							invalidOIDCProvider,
						),
						coretesting.NewGetAction(
							oidcProviderGVR,
							validOIDCProvider.Namespace,
							validOIDCProvider.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderGVR,
							validOIDCProvider.Namespace,
							validOIDCProvider,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are OIDCProviders with duplicate issuer names in the informer", func() {
			var (
				oidcProviderDuplicate1 *v1alpha1.OIDCProvider
				oidcProviderDuplicate2 *v1alpha1.OIDCProvider
				oidcProvider           *v1alpha1.OIDCProvider
			)

			it.Before(func() {
				// Hostnames are case-insensitive, so consider them to be duplicates if they only differ by case.
				// Paths are case-sensitive, so having a path that differs only by case makes a new issuer.
				oidcProviderDuplicate1 = &v1alpha1.OIDCProvider{
					ObjectMeta: metav1.ObjectMeta{Name: "duplicate1", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderSpec{Issuer: "https://iSSueR-duPlicAte.cOm/a"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderDuplicate1))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderDuplicate1))
				oidcProviderDuplicate2 = &v1alpha1.OIDCProvider{
					ObjectMeta: metav1.ObjectMeta{Name: "duplicate2", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderSpec{Issuer: "https://issuer-duplicate.com/a"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderDuplicate2))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderDuplicate2))

				oidcProvider = &v1alpha1.OIDCProvider{
					ObjectMeta: metav1.ObjectMeta{Name: "not-duplicate", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderSpec{Issuer: "https://issuer-duplicate.com/A"}, // different path
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProvider))
				r.NoError(opcInformerClient.Tracker().Add(oidcProvider))
			})

			it("calls the ProvidersSetter with the non-duplicate", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				nonDuplicateProvider, err := provider.NewOIDCProvider(oidcProvider.Spec.Issuer)
				r.NoError(err)

				r.True(providersSetter.SetProvidersWasCalled)
				r.Equal(
					[]*provider.OIDCProvider{
						nonDuplicateProvider,
					},
					providersSetter.OIDCProvidersReceived,
				)
			})

			it("updates the statuses", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				oidcProvider.Status.Status = v1alpha1.SuccessOIDCProviderStatusCondition
				oidcProvider.Status.Message = "Provider successfully created"
				oidcProvider.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				oidcProviderDuplicate1.Status.Status = v1alpha1.DuplicateOIDCProviderStatusCondition
				oidcProviderDuplicate1.Status.Message = "Duplicate issuer: https://iSSueR-duPlicAte.cOm/a"
				oidcProviderDuplicate1.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				oidcProviderDuplicate2.Status.Status = v1alpha1.DuplicateOIDCProviderStatusCondition
				oidcProviderDuplicate2.Status.Message = "Duplicate issuer: https://issuer-duplicate.com/a"
				oidcProviderDuplicate2.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				expectedActions := []coretesting.Action{
					coretesting.NewGetAction(
						oidcProviderGVR,
						oidcProviderDuplicate1.Namespace,
						oidcProviderDuplicate1.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderGVR,
						oidcProviderDuplicate1.Namespace,
						oidcProviderDuplicate1,
					),
					coretesting.NewGetAction(
						oidcProviderGVR,
						oidcProviderDuplicate2.Namespace,
						oidcProviderDuplicate2.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderGVR,
						oidcProviderDuplicate2.Namespace,
						oidcProviderDuplicate2,
					),
					coretesting.NewGetAction(
						oidcProviderGVR,
						oidcProvider.Namespace,
						oidcProvider.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderGVR,
						oidcProvider.Namespace,
						oidcProvider,
					),
				}
				r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
			})

			when("we cannot talk to the API", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"get",
						"oidcproviders",
						func(_ coretesting.Action) (bool, runtime.Object, error) {
							return true, nil, errors.New("some get error")
						},
					)
				})

				it("returns the get errors", func() {
					expectedError := here.Doc(`
						3 error(s):
						- could not update status: get failed: some get error
						- could not update status: get failed: some get error
						- could not update status: get failed: some get error`)
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, expectedError)

					oidcProvider.Status.Status = v1alpha1.SuccessOIDCProviderStatusCondition
					oidcProvider.Status.Message = "Provider successfully created"
					oidcProvider.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderGVR,
							oidcProviderDuplicate1.Namespace,
							oidcProviderDuplicate1.Name,
						),
						coretesting.NewGetAction(
							oidcProviderGVR,
							oidcProviderDuplicate2.Namespace,
							oidcProviderDuplicate2.Name,
						),
						coretesting.NewGetAction(
							oidcProviderGVR,
							oidcProvider.Namespace,
							oidcProvider.Name,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are OIDCProviders with the same issuer DNS hostname using different secretNames", func() {
			var (
				oidcProviderSameIssuerAddress1     *v1alpha1.OIDCProvider
				oidcProviderSameIssuerAddress2     *v1alpha1.OIDCProvider
				oidcProviderDifferentIssuerAddress *v1alpha1.OIDCProvider
				oidcProviderWithInvalidIssuerURL   *v1alpha1.OIDCProvider
			)

			it.Before(func() {
				oidcProviderSameIssuerAddress1 = &v1alpha1.OIDCProvider{
					ObjectMeta: metav1.ObjectMeta{Name: "provider1", Namespace: namespace},
					Spec: v1alpha1.OIDCProviderSpec{
						Issuer:                   "https://iSSueR-duPlicAte-adDress.cOm/path1",
						SNICertificateSecretName: "secret1",
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderSameIssuerAddress1))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderSameIssuerAddress1))
				oidcProviderSameIssuerAddress2 = &v1alpha1.OIDCProvider{
					ObjectMeta: metav1.ObjectMeta{Name: "provider2", Namespace: namespace},
					Spec: v1alpha1.OIDCProviderSpec{
						// Validation treats these as the same DNS hostname even though they have different port numbers,
						// because SNI information on the incoming requests is not going to include port numbers.
						Issuer:                   "https://issuer-duplicate-address.com:1234/path2",
						SNICertificateSecretName: "secret2",
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderSameIssuerAddress2))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderSameIssuerAddress2))

				oidcProviderDifferentIssuerAddress = &v1alpha1.OIDCProvider{
					ObjectMeta: metav1.ObjectMeta{Name: "differentIssuerAddressProvider", Namespace: namespace},
					Spec: v1alpha1.OIDCProviderSpec{
						Issuer:                   "https://issuer-not-duplicate.com",
						SNICertificateSecretName: "secret1",
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderDifferentIssuerAddress))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderDifferentIssuerAddress))

				// Also add one with a URL that cannot be parsed to make sure that the error handling
				// for the duplicate issuers and secret names are not confused by invalid URLs.
				invalidIssuerURL := ":/host//path"
				_, err := url.Parse(invalidIssuerURL) //nolint:staticcheck // Yes, this URL is intentionally invalid.
				r.Error(err)
				oidcProviderWithInvalidIssuerURL = &v1alpha1.OIDCProvider{
					ObjectMeta: metav1.ObjectMeta{Name: "invalidIssuerURLProvider", Namespace: namespace},
					Spec: v1alpha1.OIDCProviderSpec{
						Issuer:                   invalidIssuerURL,
						SNICertificateSecretName: "secret1",
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderWithInvalidIssuerURL))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderWithInvalidIssuerURL))
			})

			it("calls the ProvidersSetter with the non-duplicate", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				nonDuplicateProvider, err := provider.NewOIDCProvider(oidcProviderDifferentIssuerAddress.Spec.Issuer)
				r.NoError(err)

				r.True(providersSetter.SetProvidersWasCalled)
				r.Equal(
					[]*provider.OIDCProvider{
						nonDuplicateProvider,
					},
					providersSetter.OIDCProvidersReceived,
				)
			})

			it("updates the statuses", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				oidcProviderDifferentIssuerAddress.Status.Status = v1alpha1.SuccessOIDCProviderStatusCondition
				oidcProviderDifferentIssuerAddress.Status.Message = "Provider successfully created"
				oidcProviderDifferentIssuerAddress.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				oidcProviderSameIssuerAddress1.Status.Status = v1alpha1.SameIssuerHostMustUseSameSecretOIDCProviderStatusCondition
				oidcProviderSameIssuerAddress1.Status.Message = "Issuers with the same DNS hostname (address not including port) must use the same secretName: issuer-duplicate-address.com"
				oidcProviderSameIssuerAddress1.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				oidcProviderSameIssuerAddress2.Status.Status = v1alpha1.SameIssuerHostMustUseSameSecretOIDCProviderStatusCondition
				oidcProviderSameIssuerAddress2.Status.Message = "Issuers with the same DNS hostname (address not including port) must use the same secretName: issuer-duplicate-address.com"
				oidcProviderSameIssuerAddress2.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				oidcProviderWithInvalidIssuerURL.Status.Status = v1alpha1.InvalidOIDCProviderStatusCondition
				oidcProviderWithInvalidIssuerURL.Status.Message = `Invalid: could not parse issuer as URL: parse ":/host//path": missing protocol scheme`
				oidcProviderWithInvalidIssuerURL.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				expectedActions := []coretesting.Action{
					coretesting.NewGetAction(
						oidcProviderGVR,
						oidcProviderSameIssuerAddress1.Namespace,
						oidcProviderSameIssuerAddress1.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderGVR,
						oidcProviderSameIssuerAddress1.Namespace,
						oidcProviderSameIssuerAddress1,
					),
					coretesting.NewGetAction(
						oidcProviderGVR,
						oidcProviderSameIssuerAddress2.Namespace,
						oidcProviderSameIssuerAddress2.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderGVR,
						oidcProviderSameIssuerAddress2.Namespace,
						oidcProviderSameIssuerAddress2,
					),
					coretesting.NewGetAction(
						oidcProviderGVR,
						oidcProviderDifferentIssuerAddress.Namespace,
						oidcProviderDifferentIssuerAddress.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderGVR,
						oidcProviderDifferentIssuerAddress.Namespace,
						oidcProviderDifferentIssuerAddress,
					),
					coretesting.NewGetAction(
						oidcProviderGVR,
						oidcProviderWithInvalidIssuerURL.Namespace,
						oidcProviderWithInvalidIssuerURL.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderGVR,
						oidcProviderWithInvalidIssuerURL.Namespace,
						oidcProviderWithInvalidIssuerURL,
					),
				}
				r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
			})

			when("we cannot talk to the API", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"get",
						"oidcproviders",
						func(_ coretesting.Action) (bool, runtime.Object, error) {
							return true, nil, errors.New("some get error")
						},
					)
				})

				it("returns the get errors", func() {
					expectedError := here.Doc(`
						4 error(s):
						- could not update status: get failed: some get error
						- could not update status: get failed: some get error
						- could not update status: get failed: some get error
						- could not update status: get failed: some get error`)
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, expectedError)

					oidcProviderDifferentIssuerAddress.Status.Status = v1alpha1.SuccessOIDCProviderStatusCondition
					oidcProviderDifferentIssuerAddress.Status.Message = "Provider successfully created"
					oidcProviderDifferentIssuerAddress.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderGVR,
							oidcProviderSameIssuerAddress1.Namespace,
							oidcProviderSameIssuerAddress1.Name,
						),
						coretesting.NewGetAction(
							oidcProviderGVR,
							oidcProviderSameIssuerAddress2.Namespace,
							oidcProviderSameIssuerAddress2.Name,
						),
						coretesting.NewGetAction(
							oidcProviderGVR,
							oidcProviderDifferentIssuerAddress.Namespace,
							oidcProviderDifferentIssuerAddress.Name,
						),
						coretesting.NewGetAction(
							oidcProviderGVR,
							oidcProviderWithInvalidIssuerURL.Namespace,
							oidcProviderWithInvalidIssuerURL.Name,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are no OIDCProviders in the informer", func() {
			it("keeps waiting for one", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)
				r.Empty(pinnipedAPIClient.Actions())
				r.True(providersSetter.SetProvidersWasCalled)
				r.Empty(providersSetter.OIDCProvidersReceived)
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
