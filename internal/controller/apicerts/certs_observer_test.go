// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apicerts

import (
	"context"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"

	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/provider"
	"go.pinniped.dev/internal/testutil"
)

func TestObserverControllerInformerFilters(t *testing.T) {
	spec.Run(t, "informer filters", func(t *testing.T, when spec.G, it spec.S) {
		const installedInNamespace = "some-namespace"

		var r *require.Assertions
		var observableWithInformerOption *testutil.ObservableWithInformerOption
		var secretsInformerFilter controllerlib.Filter

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = testutil.NewObservableWithInformerOption()
			secretsInformer := kubeinformers.NewSharedInformerFactory(nil, 0).Core().V1().Secrets()
			_ = NewCertsObserverController(
				installedInNamespace,
				nil,
				secretsInformer,
				observableWithInformerOption.WithInformer, // make it possible to observe the behavior of the Filters
			)
			secretsInformerFilter = observableWithInformerOption.GetFilterForInformer(secretsInformer)
		})

		when("watching Secret objects", func() {
			var subject controllerlib.Filter
			var target, wrongNamespace, wrongName, unrelated *corev1.Secret

			it.Before(func() {
				subject = secretsInformerFilter
				target = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "api-serving-cert", Namespace: installedInNamespace}}
				wrongNamespace = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "api-serving-cert", Namespace: "wrong-namespace"}}
				wrongName = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: installedInNamespace}}
				unrelated = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: "wrong-namespace"}}
			})

			when("the target Secret changes", func() {
				it("returns true to trigger the sync method", func() {
					r.True(subject.Add(target))
					r.True(subject.Update(target, unrelated))
					r.True(subject.Update(unrelated, target))
					r.True(subject.Delete(target))
				})
			})

			when("a Secret from another namespace changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(wrongNamespace))
					r.False(subject.Update(wrongNamespace, unrelated))
					r.False(subject.Update(unrelated, wrongNamespace))
					r.False(subject.Delete(wrongNamespace))
				})
			})

			when("a Secret with a different name changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(wrongName))
					r.False(subject.Update(wrongName, unrelated))
					r.False(subject.Update(unrelated, wrongName))
					r.False(subject.Delete(wrongName))
				})
			})

			when("a Secret with a different name and a different namespace changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(unrelated))
					r.False(subject.Update(unrelated, unrelated))
					r.False(subject.Delete(unrelated))
				})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}

func TestObserverControllerSync(t *testing.T) {
	spec.Run(t, "Sync", func(t *testing.T, when spec.G, it spec.S) {
		const installedInNamespace = "some-namespace"

		var r *require.Assertions

		var subject controllerlib.Controller
		var kubeInformerClient *kubernetesfake.Clientset
		var kubeInformers kubeinformers.SharedInformerFactory
		var timeoutContext context.Context
		var timeoutContextCancel context.CancelFunc
		var syncContext *controllerlib.Context
		var dynamicCertProvider provider.DynamicTLSServingCertProvider

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewCertsObserverController(
				installedInNamespace,
				dynamicCertProvider,
				kubeInformers.Core().V1().Secrets(),
				controllerlib.WithInformer,
			)

			// Set this at the last second to support calling subject.Name().
			syncContext = &controllerlib.Context{
				Context: timeoutContext,
				Name:    subject.Name(),
				Key: controllerlib.Key{
					Namespace: installedInNamespace,
					Name:      "api-serving-cert",
				},
			}

			// Must start informers before calling TestRunSynchronously()
			kubeInformers.Start(timeoutContext.Done())
			controllerlib.TestRunSynchronously(t, subject)
		}

		it.Before(func() {
			r = require.New(t)

			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)

			kubeInformerClient = kubernetesfake.NewSimpleClientset()
			kubeInformers = kubeinformers.NewSharedInformerFactory(kubeInformerClient, 0)
			dynamicCertProvider = provider.NewDynamicTLSServingCertProvider()
		})

		it.After(func() {
			timeoutContextCancel()
		})

		when("there is not yet an api-serving-cert Secret in the installation namespace or it was deleted", func() {
			it.Before(func() {
				unrelatedSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "some other secret",
						Namespace: installedInNamespace,
					},
				}
				err := kubeInformerClient.Tracker().Add(unrelatedSecret)
				r.NoError(err)

				dynamicCertProvider.Set([]byte("some cert"), []byte("some private key"))
			})

			it("sets the dynamicCertProvider's cert and key to nil", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				actualCertChain, actualKey := dynamicCertProvider.CurrentCertKeyContent()
				r.Nil(actualCertChain)
				r.Nil(actualKey)
			})
		})

		when("there is an api-serving-cert Secret with the expected keys already in the installation namespace", func() {
			it.Before(func() {
				apiServingCertSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "api-serving-cert",
						Namespace: installedInNamespace,
					},
					Data: map[string][]byte{
						"caCertificate":       []byte("fake cert"),
						"tlsPrivateKey":       []byte("fake private key"),
						"tlsCertificateChain": []byte("fake cert chain"),
					},
				}
				err := kubeInformerClient.Tracker().Add(apiServingCertSecret)
				r.NoError(err)

				dynamicCertProvider.Set(nil, nil)
			})

			it("updates the dynamicCertProvider's cert and key", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				actualCertChain, actualKey := dynamicCertProvider.CurrentCertKeyContent()
				r.Equal("fake cert chain", string(actualCertChain))
				r.Equal("fake private key", string(actualKey))
			})
		})

		when("the api-serving-cert Secret exists but is missing the expected keys", func() {
			it.Before(func() {
				apiServingCertSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "api-serving-cert",
						Namespace: installedInNamespace,
					},
					Data: map[string][]byte{},
				}
				err := kubeInformerClient.Tracker().Add(apiServingCertSecret)
				r.NoError(err)

				dynamicCertProvider.Set(nil, nil)
			})

			it("set the missing values in the dynamicCertProvider as nil", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				actualCertChain, actualKey := dynamicCertProvider.CurrentCertKeyContent()
				r.Nil(actualCertChain)
				r.Nil(actualKey)
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
