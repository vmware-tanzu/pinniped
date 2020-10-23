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

	"go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/1.19/client/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/1.19/client/informers/externalversions"
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
			opcInformer := pinnipedinformers.NewSharedInformerFactoryWithOptions(nil, 0).Config().V1alpha1().OIDCProviderConfigs()
			_ = NewOIDCProviderConfigWatcherController(
				nil,
				nil,
				nil,
				opcInformer,
				observableWithInformerOption.WithInformer, // make it possible to observe the behavior of the Filters
			)
			configMapInformerFilter = observableWithInformerOption.GetFilterForInformer(opcInformer)
		})

		when("watching OIDCProviderConfig objects", func() {
			var subject controllerlib.Filter
			var target, otherNamespace, otherName *v1alpha1.OIDCProviderConfig

			it.Before(func() {
				subject = configMapInformerFilter
				target = &v1alpha1.OIDCProviderConfig{ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"}}
				otherNamespace = &v1alpha1.OIDCProviderConfig{ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "other-namespace"}}
				otherName = &v1alpha1.OIDCProviderConfig{ObjectMeta: metav1.ObjectMeta{Name: "other-name", Namespace: "some-namespace"}}
			})

			when("any OIDCProviderConfig changes", func() {
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
		var oidcProviderConfigGVR schema.GroupVersionResource

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewOIDCProviderConfigWatcherController(
				providersSetter,
				clock.NewFakeClock(frozenNow),
				pinnipedAPIClient,
				opcInformers.Config().V1alpha1().OIDCProviderConfigs(),
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

			oidcProviderConfigGVR = schema.GroupVersionResource{
				Group:    v1alpha1.SchemeGroupVersion.Group,
				Version:  v1alpha1.SchemeGroupVersion.Version,
				Resource: "oidcproviderconfigs",
			}
		})

		it.After(func() {
			timeoutContextCancel()
		})

		when("there are some valid OIDCProviderConfigs in the informer", func() {
			var (
				oidcProviderConfig1 *v1alpha1.OIDCProviderConfig
				oidcProviderConfig2 *v1alpha1.OIDCProviderConfig
			)

			it.Before(func() {
				oidcProviderConfig1 = &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderConfigSpec{Issuer: "https://issuer1.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderConfig1))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderConfig1))

				oidcProviderConfig2 = &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "config2", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderConfigSpec{Issuer: "https://issuer2.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderConfig2))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderConfig2))
			})

			it("calls the ProvidersSetter", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				provider1, err := provider.NewOIDCProvider(oidcProviderConfig1.Spec.Issuer)
				r.NoError(err)

				provider2, err := provider.NewOIDCProvider(oidcProviderConfig2.Spec.Issuer)
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

			it("updates the status to success in the OIDCProviderConfigs", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				oidcProviderConfig1.Status.Status = v1alpha1.SuccessOIDCProviderStatus
				oidcProviderConfig1.Status.Message = "Provider successfully created"
				oidcProviderConfig1.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				oidcProviderConfig2.Status.Status = v1alpha1.SuccessOIDCProviderStatus
				oidcProviderConfig2.Status.Message = "Provider successfully created"
				oidcProviderConfig2.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				expectedActions := []coretesting.Action{
					coretesting.NewGetAction(
						oidcProviderConfigGVR,
						oidcProviderConfig1.Namespace,
						oidcProviderConfig1.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderConfigGVR,
						oidcProviderConfig1.Namespace,
						oidcProviderConfig1,
					),
					coretesting.NewGetAction(
						oidcProviderConfigGVR,
						oidcProviderConfig2.Namespace,
						oidcProviderConfig2.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderConfigGVR,
						oidcProviderConfig2.Namespace,
						oidcProviderConfig2,
					),
				}
				r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
			})

			when("one OIDCProviderConfig is already up to date", func() {
				it.Before(func() {
					oidcProviderConfig1.Status.Status = v1alpha1.SuccessOIDCProviderStatus
					oidcProviderConfig1.Status.Message = "Provider successfully created"
					oidcProviderConfig1.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					r.NoError(pinnipedAPIClient.Tracker().Update(oidcProviderConfigGVR, oidcProviderConfig1, oidcProviderConfig1.Namespace))
					r.NoError(opcInformerClient.Tracker().Update(oidcProviderConfigGVR, oidcProviderConfig1, oidcProviderConfig1.Namespace))
				})

				it("only updates the out-of-date OIDCProviderConfig", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.NoError(err)

					oidcProviderConfig2.Status.Status = v1alpha1.SuccessOIDCProviderStatus
					oidcProviderConfig2.Status.Message = "Provider successfully created"
					oidcProviderConfig2.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							oidcProviderConfig1.Namespace,
							oidcProviderConfig1.Name,
						),
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							oidcProviderConfig2.Namespace,
							oidcProviderConfig2.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderConfigGVR,
							oidcProviderConfig2.Namespace,
							oidcProviderConfig2,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})

				it("calls the ProvidersSetter with both OIDCProviderConfig's", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.NoError(err)

					provider1, err := provider.NewOIDCProvider(oidcProviderConfig1.Spec.Issuer)
					r.NoError(err)

					provider2, err := provider.NewOIDCProvider(oidcProviderConfig2.Spec.Issuer)
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

			when("updating only one OIDCProviderConfig fails for a reason other than conflict", func() {
				it.Before(func() {
					once := sync.Once{}
					pinnipedAPIClient.PrependReactor(
						"update",
						"oidcproviderconfigs",
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

					provider1, err := provider.NewOIDCProvider(oidcProviderConfig1.Spec.Issuer)
					r.NoError(err)

					provider2, err := provider.NewOIDCProvider(oidcProviderConfig2.Spec.Issuer)
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

					oidcProviderConfig1.Status.Status = v1alpha1.SuccessOIDCProviderStatus
					oidcProviderConfig1.Status.Message = "Provider successfully created"
					oidcProviderConfig1.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					oidcProviderConfig2.Status.Status = v1alpha1.SuccessOIDCProviderStatus
					oidcProviderConfig2.Status.Message = "Provider successfully created"
					oidcProviderConfig2.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							oidcProviderConfig1.Namespace,
							oidcProviderConfig1.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderConfigGVR,
							oidcProviderConfig1.Namespace,
							oidcProviderConfig1,
						),
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							oidcProviderConfig2.Namespace,
							oidcProviderConfig2.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderConfigGVR,
							oidcProviderConfig2.Namespace,
							oidcProviderConfig2,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are errors updating the OIDCProviderConfigs", func() {
			var (
				oidcProviderConfig *v1alpha1.OIDCProviderConfig
			)

			it.Before(func() {
				oidcProviderConfig = &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderConfigSpec{Issuer: "https://issuer.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderConfig))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderConfig))
			})

			when("there is a conflict while updating an OIDCProviderConfig", func() {
				it.Before(func() {
					once := sync.Once{}
					pinnipedAPIClient.PrependReactor(
						"update",
						"oidcproviderconfigs",
						func(_ coretesting.Action) (bool, runtime.Object, error) {
							var err error
							once.Do(func() {
								err = k8serrors.NewConflict(schema.GroupResource{}, "", nil)
							})
							return true, nil, err
						},
					)
				})

				it("retries updating the OIDCProviderConfig", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.NoError(err)

					oidcProviderConfig.Status.Status = v1alpha1.SuccessOIDCProviderStatus
					oidcProviderConfig.Status.Message = "Provider successfully created"
					oidcProviderConfig.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							oidcProviderConfig.Namespace,
							oidcProviderConfig.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderConfigGVR,
							oidcProviderConfig.Namespace,
							oidcProviderConfig,
						),
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							oidcProviderConfig.Namespace,
							oidcProviderConfig.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderConfigGVR,
							oidcProviderConfig.Namespace,
							oidcProviderConfig,
						),
					}
					r.Equal(expectedActions, pinnipedAPIClient.Actions())
				})
			})

			when("updating the OIDCProviderConfig fails for a reason other than conflict", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"update",
						"oidcproviderconfigs",
						func(_ coretesting.Action) (bool, runtime.Object, error) {
							return true, nil, errors.New("some update error")
						},
					)
				})

				it("returns an error", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "1 error(s):\n- could not update status: some update error")

					oidcProviderConfig.Status.Status = v1alpha1.SuccessOIDCProviderStatus
					oidcProviderConfig.Status.Message = "Provider successfully created"
					oidcProviderConfig.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							oidcProviderConfig.Namespace,
							oidcProviderConfig.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderConfigGVR,
							oidcProviderConfig.Namespace,
							oidcProviderConfig,
						),
					}
					r.Equal(expectedActions, pinnipedAPIClient.Actions())
				})
			})

			when("there is an error when getting the OIDCProviderConfig", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"get",
						"oidcproviderconfigs",
						func(_ coretesting.Action) (bool, runtime.Object, error) {
							return true, nil, errors.New("some get error")
						},
					)
				})

				it("returns the get error", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "1 error(s):\n- could not update status: get failed: some get error")

					oidcProviderConfig.Status.Status = v1alpha1.SuccessOIDCProviderStatus
					oidcProviderConfig.Status.Message = "Provider successfully created"
					oidcProviderConfig.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							oidcProviderConfig.Namespace,
							oidcProviderConfig.Name,
						),
					}
					r.Equal(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are both valid and invalid OIDCProviderConfigs in the informer", func() {
			var (
				validOIDCProviderConfig   *v1alpha1.OIDCProviderConfig
				invalidOIDCProviderConfig *v1alpha1.OIDCProviderConfig
			)

			it.Before(func() {
				validOIDCProviderConfig = &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "valid-config", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderConfigSpec{Issuer: "https://valid-issuer.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(validOIDCProviderConfig))
				r.NoError(opcInformerClient.Tracker().Add(validOIDCProviderConfig))

				invalidOIDCProviderConfig = &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "invalid-config", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderConfigSpec{Issuer: "https://invalid-issuer.com?some=query"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(invalidOIDCProviderConfig))
				r.NoError(opcInformerClient.Tracker().Add(invalidOIDCProviderConfig))
			})

			it("calls the ProvidersSetter with the valid provider", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				validProvider, err := provider.NewOIDCProvider(validOIDCProviderConfig.Spec.Issuer)
				r.NoError(err)

				r.True(providersSetter.SetProvidersWasCalled)
				r.Equal(
					[]*provider.OIDCProvider{
						validProvider,
					},
					providersSetter.OIDCProvidersReceived,
				)
			})

			it("updates the status to success/invalid in the OIDCProviderConfigs", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				validOIDCProviderConfig.Status.Status = v1alpha1.SuccessOIDCProviderStatus
				validOIDCProviderConfig.Status.Message = "Provider successfully created"
				validOIDCProviderConfig.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				invalidOIDCProviderConfig.Status.Status = v1alpha1.InvalidOIDCProviderStatus
				invalidOIDCProviderConfig.Status.Message = "Invalid: issuer must not have query"
				invalidOIDCProviderConfig.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				expectedActions := []coretesting.Action{
					coretesting.NewGetAction(
						oidcProviderConfigGVR,
						invalidOIDCProviderConfig.Namespace,
						invalidOIDCProviderConfig.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderConfigGVR,
						invalidOIDCProviderConfig.Namespace,
						invalidOIDCProviderConfig,
					),
					coretesting.NewGetAction(
						oidcProviderConfigGVR,
						validOIDCProviderConfig.Namespace,
						validOIDCProviderConfig.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderConfigGVR,
						validOIDCProviderConfig.Namespace,
						validOIDCProviderConfig,
					),
				}
				r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
			})

			when("updating only the invalid OIDCProviderConfig fails for a reason other than conflict", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"update",
						"oidcproviderconfigs",
						func(action coretesting.Action) (bool, runtime.Object, error) {
							updateAction := action.(coretesting.UpdateActionImpl)
							opc := updateAction.Object.(*v1alpha1.OIDCProviderConfig)
							if opc.Name == validOIDCProviderConfig.Name {
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

					validProvider, err := provider.NewOIDCProvider(validOIDCProviderConfig.Spec.Issuer)
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

					validOIDCProviderConfig.Status.Status = v1alpha1.SuccessOIDCProviderStatus
					validOIDCProviderConfig.Status.Message = "Provider successfully created"
					validOIDCProviderConfig.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					invalidOIDCProviderConfig.Status.Status = v1alpha1.InvalidOIDCProviderStatus
					invalidOIDCProviderConfig.Status.Message = "Invalid: issuer must not have query"
					invalidOIDCProviderConfig.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							invalidOIDCProviderConfig.Namespace,
							invalidOIDCProviderConfig.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderConfigGVR,
							invalidOIDCProviderConfig.Namespace,
							invalidOIDCProviderConfig,
						),
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							validOIDCProviderConfig.Namespace,
							validOIDCProviderConfig.Name,
						),
						coretesting.NewUpdateAction(
							oidcProviderConfigGVR,
							validOIDCProviderConfig.Namespace,
							validOIDCProviderConfig,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are OIDCProviderConfigs with duplicate issuer names in the informer", func() {
			var (
				oidcProviderConfigDuplicate1 *v1alpha1.OIDCProviderConfig
				oidcProviderConfigDuplicate2 *v1alpha1.OIDCProviderConfig
				oidcProviderConfig           *v1alpha1.OIDCProviderConfig
			)

			it.Before(func() {
				// Hostnames are case-insensitive, so consider them to be duplicates if they only differ by case.
				// Paths are case-sensitive, so having a path that differs only by case makes a new issuer.
				oidcProviderConfigDuplicate1 = &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "duplicate1", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderConfigSpec{Issuer: "https://iSSueR-duPlicAte.cOm/a"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderConfigDuplicate1))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderConfigDuplicate1))
				oidcProviderConfigDuplicate2 = &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "duplicate2", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderConfigSpec{Issuer: "https://issuer-duplicate.com/a"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderConfigDuplicate2))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderConfigDuplicate2))

				oidcProviderConfig = &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "not-duplicate", Namespace: namespace},
					Spec:       v1alpha1.OIDCProviderConfigSpec{Issuer: "https://issuer-duplicate.com/A"}, // different path
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderConfig))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderConfig))
			})

			it("calls the ProvidersSetter with the non-duplicate", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				nonDuplicateProvider, err := provider.NewOIDCProvider(oidcProviderConfig.Spec.Issuer)
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

				oidcProviderConfig.Status.Status = v1alpha1.SuccessOIDCProviderStatus
				oidcProviderConfig.Status.Message = "Provider successfully created"
				oidcProviderConfig.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				oidcProviderConfigDuplicate1.Status.Status = v1alpha1.DuplicateOIDCProviderStatus
				oidcProviderConfigDuplicate1.Status.Message = "Duplicate issuer: https://iSSueR-duPlicAte.cOm/a"
				oidcProviderConfigDuplicate1.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				oidcProviderConfigDuplicate2.Status.Status = v1alpha1.DuplicateOIDCProviderStatus
				oidcProviderConfigDuplicate2.Status.Message = "Duplicate issuer: https://issuer-duplicate.com/a"
				oidcProviderConfigDuplicate2.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				expectedActions := []coretesting.Action{
					coretesting.NewGetAction(
						oidcProviderConfigGVR,
						oidcProviderConfigDuplicate1.Namespace,
						oidcProviderConfigDuplicate1.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderConfigGVR,
						oidcProviderConfigDuplicate1.Namespace,
						oidcProviderConfigDuplicate1,
					),
					coretesting.NewGetAction(
						oidcProviderConfigGVR,
						oidcProviderConfigDuplicate2.Namespace,
						oidcProviderConfigDuplicate2.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderConfigGVR,
						oidcProviderConfigDuplicate2.Namespace,
						oidcProviderConfigDuplicate2,
					),
					coretesting.NewGetAction(
						oidcProviderConfigGVR,
						oidcProviderConfig.Namespace,
						oidcProviderConfig.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderConfigGVR,
						oidcProviderConfig.Namespace,
						oidcProviderConfig,
					),
				}
				r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
			})

			when("we cannot talk to the API", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"get",
						"oidcproviderconfigs",
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

					oidcProviderConfig.Status.Status = v1alpha1.SuccessOIDCProviderStatus
					oidcProviderConfig.Status.Message = "Provider successfully created"
					oidcProviderConfig.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							oidcProviderConfigDuplicate1.Namespace,
							oidcProviderConfigDuplicate1.Name,
						),
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							oidcProviderConfigDuplicate2.Namespace,
							oidcProviderConfigDuplicate2.Name,
						),
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							oidcProviderConfig.Namespace,
							oidcProviderConfig.Name,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are OIDCProviderConfigs with the same issuer address using different secretNames", func() {
			var (
				oidcProviderConfigSameIssuerAddress1     *v1alpha1.OIDCProviderConfig
				oidcProviderConfigSameIssuerAddress2     *v1alpha1.OIDCProviderConfig
				oidcProviderConfigDifferentIssuerAddress *v1alpha1.OIDCProviderConfig
				oidcProviderConfigWithInvalidIssuerURL   *v1alpha1.OIDCProviderConfig
			)

			it.Before(func() {
				oidcProviderConfigSameIssuerAddress1 = &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "provider1", Namespace: namespace},
					Spec: v1alpha1.OIDCProviderConfigSpec{
						Issuer:     "https://iSSueR-duPlicAte-adDress.cOm/path1",
						SecretName: "secret1",
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderConfigSameIssuerAddress1))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderConfigSameIssuerAddress1))
				oidcProviderConfigSameIssuerAddress2 = &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "provider2", Namespace: namespace},
					Spec: v1alpha1.OIDCProviderConfigSpec{
						Issuer:     "https://issuer-duplicate-address.com/path2",
						SecretName: "secret2",
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderConfigSameIssuerAddress2))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderConfigSameIssuerAddress2))

				oidcProviderConfigDifferentIssuerAddress = &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "differentIssuerAddressProvider", Namespace: namespace},
					Spec: v1alpha1.OIDCProviderConfigSpec{
						Issuer:     "https://issuer-not-duplicate.com",
						SecretName: "secret1",
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderConfigDifferentIssuerAddress))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderConfigDifferentIssuerAddress))

				// Also add one with a URL that cannot be parsed to make sure that the error handling
				// for the duplicate issuers and secret names are not confused by invalid URLs.
				invalidIssuerURL := ":/host//path"
				_, err := url.Parse(invalidIssuerURL) //nolint:staticcheck // Yes, this URL is intentionally invalid.
				r.Error(err)
				oidcProviderConfigWithInvalidIssuerURL = &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "invalidIssuerURLProvider", Namespace: namespace},
					Spec: v1alpha1.OIDCProviderConfigSpec{
						Issuer:     invalidIssuerURL,
						SecretName: "secret1",
					},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderConfigWithInvalidIssuerURL))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderConfigWithInvalidIssuerURL))
			})

			it("calls the ProvidersSetter with the non-duplicate", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				nonDuplicateProvider, err := provider.NewOIDCProvider(oidcProviderConfigDifferentIssuerAddress.Spec.Issuer)
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

				oidcProviderConfigDifferentIssuerAddress.Status.Status = v1alpha1.SuccessOIDCProviderStatus
				oidcProviderConfigDifferentIssuerAddress.Status.Message = "Provider successfully created"
				oidcProviderConfigDifferentIssuerAddress.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				oidcProviderConfigSameIssuerAddress1.Status.Status = v1alpha1.SameIssuerHostMustUseSameSecretOIDCProviderStatus
				oidcProviderConfigSameIssuerAddress1.Status.Message = "Issuers with the same address must use the same secretName: issuer-duplicate-address.com"
				oidcProviderConfigSameIssuerAddress1.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				oidcProviderConfigSameIssuerAddress2.Status.Status = v1alpha1.SameIssuerHostMustUseSameSecretOIDCProviderStatus
				oidcProviderConfigSameIssuerAddress2.Status.Message = "Issuers with the same address must use the same secretName: issuer-duplicate-address.com"
				oidcProviderConfigSameIssuerAddress2.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				oidcProviderConfigWithInvalidIssuerURL.Status.Status = v1alpha1.InvalidOIDCProviderStatus
				oidcProviderConfigWithInvalidIssuerURL.Status.Message = `Invalid: could not parse issuer as URL: parse ":/host//path": missing protocol scheme`
				oidcProviderConfigWithInvalidIssuerURL.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

				expectedActions := []coretesting.Action{
					coretesting.NewGetAction(
						oidcProviderConfigGVR,
						oidcProviderConfigSameIssuerAddress1.Namespace,
						oidcProviderConfigSameIssuerAddress1.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderConfigGVR,
						oidcProviderConfigSameIssuerAddress1.Namespace,
						oidcProviderConfigSameIssuerAddress1,
					),
					coretesting.NewGetAction(
						oidcProviderConfigGVR,
						oidcProviderConfigSameIssuerAddress2.Namespace,
						oidcProviderConfigSameIssuerAddress2.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderConfigGVR,
						oidcProviderConfigSameIssuerAddress2.Namespace,
						oidcProviderConfigSameIssuerAddress2,
					),
					coretesting.NewGetAction(
						oidcProviderConfigGVR,
						oidcProviderConfigDifferentIssuerAddress.Namespace,
						oidcProviderConfigDifferentIssuerAddress.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderConfigGVR,
						oidcProviderConfigDifferentIssuerAddress.Namespace,
						oidcProviderConfigDifferentIssuerAddress,
					),
					coretesting.NewGetAction(
						oidcProviderConfigGVR,
						oidcProviderConfigWithInvalidIssuerURL.Namespace,
						oidcProviderConfigWithInvalidIssuerURL.Name,
					),
					coretesting.NewUpdateAction(
						oidcProviderConfigGVR,
						oidcProviderConfigWithInvalidIssuerURL.Namespace,
						oidcProviderConfigWithInvalidIssuerURL,
					),
				}
				r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
			})

			when("we cannot talk to the API", func() {
				it.Before(func() {
					pinnipedAPIClient.PrependReactor(
						"get",
						"oidcproviderconfigs",
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

					oidcProviderConfigDifferentIssuerAddress.Status.Status = v1alpha1.SuccessOIDCProviderStatus
					oidcProviderConfigDifferentIssuerAddress.Status.Message = "Provider successfully created"
					oidcProviderConfigDifferentIssuerAddress.Status.LastUpdateTime = timePtr(metav1.NewTime(frozenNow))

					expectedActions := []coretesting.Action{
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							oidcProviderConfigSameIssuerAddress1.Namespace,
							oidcProviderConfigSameIssuerAddress1.Name,
						),
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							oidcProviderConfigSameIssuerAddress2.Namespace,
							oidcProviderConfigSameIssuerAddress2.Name,
						),
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							oidcProviderConfigDifferentIssuerAddress.Namespace,
							oidcProviderConfigDifferentIssuerAddress.Name,
						),
						coretesting.NewGetAction(
							oidcProviderConfigGVR,
							oidcProviderConfigWithInvalidIssuerURL.Namespace,
							oidcProviderConfigWithInvalidIssuerURL.Name,
						),
					}
					r.ElementsMatch(expectedActions, pinnipedAPIClient.Actions())
				})
			})
		})

		when("there are no OIDCProviderConfigs in the informer", func() {
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
