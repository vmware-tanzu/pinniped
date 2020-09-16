/*
Copyright 2020 the Pinniped contributors. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package apicerts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"

	"github.com/suzerain-io/pinniped/internal/controllerlib"
	"github.com/suzerain-io/pinniped/internal/testutil"
)

func TestManagerControllerOptions(t *testing.T) {
	spec.Run(t, "options", func(t *testing.T, when spec.G, it spec.S) {
		const installedInNamespace = "some-namespace"

		var r *require.Assertions
		var observableWithInformerOption *testutil.ObservableWithInformerOption
		var observableWithInitialEventOption *testutil.ObservableWithInitialEventOption
		var secretsInformerFilter controllerlib.Filter

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = testutil.NewObservableWithInformerOption()
			observableWithInitialEventOption = testutil.NewObservableWithInitialEventOption()
			secretsInformer := kubeinformers.NewSharedInformerFactory(nil, 0).Core().V1().Secrets()
			_ = NewCertsManagerController(installedInNamespace, nil, secretsInformer, observableWithInformerOption.WithInformer, observableWithInitialEventOption.WithInitialEvent, 0, "Pinniped CA", "pinniped-api")
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

		when("starting up", func() {
			it("asks for an initial event because the Secret may not exist yet and it needs to run anyway", func() {
				r.Equal(controllerlib.Key{
					Namespace: installedInNamespace,
					Name:      "api-serving-cert",
				}, observableWithInitialEventOption.GetInitialEventKey())
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}

func TestManagerControllerSync(t *testing.T) {
	spec.Run(t, "Sync", func(t *testing.T, when spec.G, it spec.S) {
		const installedInNamespace = "some-namespace"
		const certDuration = 12345678 * time.Second

		var r *require.Assertions

		var subject controllerlib.Controller
		var kubeAPIClient *kubernetesfake.Clientset
		var kubeInformerClient *kubernetesfake.Clientset
		var kubeInformers kubeinformers.SharedInformerFactory
		var timeoutContext context.Context
		var timeoutContextCancel context.CancelFunc
		var syncContext *controllerlib.Context

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewCertsManagerController(
				installedInNamespace,
				kubeAPIClient,
				kubeInformers.Core().V1().Secrets(),
				controllerlib.WithInformer,
				controllerlib.WithInitialEvent,
				certDuration,
				"Pinniped CA",
				"pinniped-api",
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
			kubeAPIClient = kubernetesfake.NewSimpleClientset()
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
			})

			it("creates the api-serving-cert Secret", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				// Check all the relevant fields from the create Secret action
				r.Len(kubeAPIClient.Actions(), 1)
				actualAction := kubeAPIClient.Actions()[0].(coretesting.CreateActionImpl)
				r.Equal(schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}, actualAction.GetResource())
				r.Equal(installedInNamespace, actualAction.GetNamespace())
				actualSecret := actualAction.GetObject().(*corev1.Secret)
				r.Equal("api-serving-cert", actualSecret.Name)
				r.Equal(installedInNamespace, actualSecret.Namespace)
				actualCACert := actualSecret.StringData["caCertificate"]
				actualPrivateKey := actualSecret.StringData["tlsPrivateKey"]
				actualCertChain := actualSecret.StringData["tlsCertificateChain"]
				r.NotEmpty(actualCACert)
				r.NotEmpty(actualPrivateKey)
				r.NotEmpty(actualCertChain)

				// Validate the created CA's lifetime.
				validCACert := testutil.ValidateCertificate(t, actualCACert, actualCACert)
				validCACert.RequireLifetime(time.Now(), time.Now().Add(certDuration), 6*time.Minute)

				// Validate the created cert using the CA, and also validate the cert's hostname
				validCert := testutil.ValidateCertificate(t, actualCACert, actualCertChain)
				validCert.RequireDNSName("pinniped-api." + installedInNamespace + ".svc")
				validCert.RequireLifetime(time.Now(), time.Now().Add(certDuration), 6*time.Minute)
				validCert.RequireMatchesPrivateKey(actualPrivateKey)
			})

			when("creating the Secret fails", func() {
				it.Before(func() {
					kubeAPIClient.PrependReactor(
						"create",
						"secrets",
						func(_ coretesting.Action) (bool, runtime.Object, error) {
							return true, nil, errors.New("create failed")
						},
					)
				})

				it("returns the create error", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.EqualError(err, "could not create secret: create failed")
				})
			})
		})

		when("there is an api-serving-cert Secret already in the installation namespace", func() {
			it.Before(func() {
				apiServingCertSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "api-serving-cert",
						Namespace: installedInNamespace,
					},
				}
				err := kubeInformerClient.Tracker().Add(apiServingCertSecret)
				r.NoError(err)
			})

			it("does not need to make any API calls with its API client", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)
				r.Empty(kubeAPIClient.Actions())
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
