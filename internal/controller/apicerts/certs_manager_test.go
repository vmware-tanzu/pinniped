/*
Copyright 2020 VMware, Inc.
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
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	aggregatorfake "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"

	"github.com/suzerain-io/controller-go"
	pinnipedv1alpha1 "github.com/suzerain-io/pinniped/generated/1.19/apis/pinniped/v1alpha1"
	"github.com/suzerain-io/pinniped/internal/testutil"
)

func TestManagerControllerOptions(t *testing.T) {
	spec.Run(t, "options", func(t *testing.T, when spec.G, it spec.S) {
		const installedInNamespace = "some-namespace"

		var r *require.Assertions
		var observableWithInformerOption *testutil.ObservableWithInformerOption
		var observableWithInitialEventOption *testutil.ObservableWithInitialEventOption
		var secretsInformerFilter controller.Filter

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = testutil.NewObservableWithInformerOption()
			observableWithInitialEventOption = testutil.NewObservableWithInitialEventOption()
			secretsInformer := kubeinformers.NewSharedInformerFactory(nil, 0).Core().V1().Secrets()
			_ = NewCertsManagerController(
				installedInNamespace,
				nil,
				nil,
				secretsInformer,
				observableWithInformerOption.WithInformer,         // make it possible to observe the behavior of the Filters
				observableWithInitialEventOption.WithInitialEvent, // make it possible to observe the behavior of the initial event
				0, // certDuration, not needed for this test
			)
			secretsInformerFilter = observableWithInformerOption.GetFilterForInformer(secretsInformer)
		})

		when("watching Secret objects", func() {
			var subject controller.Filter
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
				r.Equal(controller.Key{
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

		var subject controller.Controller
		var kubeAPIClient *kubernetesfake.Clientset
		var aggregatorAPIClient *aggregatorfake.Clientset
		var kubeInformerClient *kubernetesfake.Clientset
		var kubeInformers kubeinformers.SharedInformerFactory
		var timeoutContext context.Context
		var timeoutContextCancel context.CancelFunc
		var syncContext *controller.Context

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewCertsManagerController(
				installedInNamespace,
				kubeAPIClient,
				aggregatorAPIClient,
				kubeInformers.Core().V1().Secrets(),
				controller.WithInformer,
				controller.WithInitialEvent,
				certDuration,
			)

			// Set this at the last second to support calling subject.Name().
			syncContext = &controller.Context{
				Context: timeoutContext,
				Name:    subject.Name(),
				Key: controller.Key{
					Namespace: installedInNamespace,
					Name:      "api-serving-cert",
				},
			}

			// Must start informers before calling TestRunSynchronously()
			kubeInformers.Start(timeoutContext.Done())
			controller.TestRunSynchronously(t, subject)
		}

		it.Before(func() {
			r = require.New(t)

			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)

			kubeInformerClient = kubernetesfake.NewSimpleClientset()
			kubeInformers = kubeinformers.NewSharedInformerFactory(kubeInformerClient, 0)
			kubeAPIClient = kubernetesfake.NewSimpleClientset()
			aggregatorAPIClient = aggregatorfake.NewSimpleClientset()
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

			when("the APIService exists", func() {
				it.Before(func() {
					apiService := &apiregistrationv1.APIService{
						ObjectMeta: metav1.ObjectMeta{
							Name: pinnipedv1alpha1.SchemeGroupVersion.Version + "." + pinnipedv1alpha1.GroupName,
						},
						Spec: apiregistrationv1.APIServiceSpec{
							CABundle:        nil,
							VersionPriority: 1234,
						},
					}
					err := aggregatorAPIClient.Tracker().Add(apiService)
					r.NoError(err)
				})

				it("creates the api-serving-cert Secret and updates the APIService's ca bundle", func() {
					startInformersAndController()
					err := controller.TestSync(t, subject, *syncContext)
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

					// Make sure we updated the APIService caBundle and left it otherwise unchanged
					r.Len(aggregatorAPIClient.Actions(), 2)
					r.Equal("get", aggregatorAPIClient.Actions()[0].GetVerb())
					expectedAPIServiceName := pinnipedv1alpha1.SchemeGroupVersion.Version + "." + pinnipedv1alpha1.GroupName
					expectedUpdateAction := coretesting.NewUpdateAction(
						schema.GroupVersionResource{
							Group:    apiregistrationv1.GroupName,
							Version:  "v1",
							Resource: "apiservices",
						},
						"",
						&apiregistrationv1.APIService{
							ObjectMeta: metav1.ObjectMeta{
								Name:      expectedAPIServiceName,
								Namespace: "",
							},
							Spec: apiregistrationv1.APIServiceSpec{
								VersionPriority: 1234, // only the CABundle is updated, this other field is left unchanged
								CABundle:        []byte(actualCACert),
							},
						},
					)
					r.Equal(expectedUpdateAction, aggregatorAPIClient.Actions()[1])
				})

				when("updating the APIService fails", func() {
					it.Before(func() {
						aggregatorAPIClient.PrependReactor(
							"update",
							"apiservices",
							func(_ coretesting.Action) (bool, runtime.Object, error) {
								return true, nil, errors.New("update failed")
							},
						)
					})

					it("returns the update error", func() {
						startInformersAndController()
						err := controller.TestSync(t, subject, *syncContext)
						r.EqualError(err, "could not update the API service: could not update API service: update failed")
					})
				})
			})

			when("the APIService does not exist", func() {
				it.Before(func() {
					unrelatedAPIService := &apiregistrationv1.APIService{
						ObjectMeta: metav1.ObjectMeta{Name: "some other api service"},
						Spec:       apiregistrationv1.APIServiceSpec{},
					}
					err := aggregatorAPIClient.Tracker().Add(unrelatedAPIService)
					r.NoError(err)
				})

				it("returns an error", func() {
					startInformersAndController()
					err := controller.TestSync(t, subject, *syncContext)
					r.Error(err)
					r.Regexp("could not get existing version of API service: .* not found", err.Error())
				})
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

				it("returns the create error and does not update the APIService", func() {
					startInformersAndController()
					err := controller.TestSync(t, subject, *syncContext)
					r.EqualError(err, "could not create secret: create failed")
					r.Empty(aggregatorAPIClient.Actions())
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

			it("does not need to make any API calls with its API clients", func() {
				startInformersAndController()
				err := controller.TestSync(t, subject, *syncContext)
				r.NoError(err)
				r.Empty(kubeAPIClient.Actions())
				r.Empty(aggregatorAPIClient.Actions())
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
