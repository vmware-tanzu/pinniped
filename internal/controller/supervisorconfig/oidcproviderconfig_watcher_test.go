// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/clock"

	"go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/1.19/client/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/1.19/client/informers/externalversions"
	"go.pinniped.dev/internal/controllerlib"
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
					Namespace: "some-namespace",
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
		})

		it.After(func() {
			timeoutContextCancel()
		})

		when("there are some valid OIDCProviderConfigs in the informer", func() {
			it.Before(func() {
				oidcProviderConfig1 := &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "config1", Namespace: "some-namespace"},
					Spec:       v1alpha1.OIDCProviderConfigSpec{Issuer: "https://issuer1.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderConfig1))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderConfig1))

				oidcProviderConfig2 := &v1alpha1.OIDCProviderConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "config2", Namespace: "some-namespace"},
					Spec:       v1alpha1.OIDCProviderConfigSpec{Issuer: "https://issuer2.com"},
				}
				r.NoError(pinnipedAPIClient.Tracker().Add(oidcProviderConfig2))
				r.NoError(opcInformerClient.Tracker().Add(oidcProviderConfig2))
			})

			it("calls the ProvidersSetter and updates the OIDCProviderConfigs", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				r.True(providersSetter.SetProvidersWasCalled)
				r.Len(providersSetter.OIDCProvidersReceived, 2)

				// TODO make more assertions about the OIDCProvidersReceived
				// TODO make assertions about the expected pinnipedAPIClient.Actions()
			})

			when("there is a conflict while updating an OIDCProviderConfig", func() {
				// TODO write this test
			})
		})

		when("there are both valid and invalid OIDCProviderConfigs in the informer", func() {
			// TODO write this test
		})

		when("they there are OIDCProviderConfigs with duplicate issuer names in the informer", func() {
			// TODO write this test
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
