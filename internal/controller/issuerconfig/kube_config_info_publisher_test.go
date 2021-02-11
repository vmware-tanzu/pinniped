// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package issuerconfig

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

	configv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned/fake"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/testutil"
)

func TestInformerFilters(t *testing.T) {
	spec.Run(t, "informer filters", func(t *testing.T, when spec.G, it spec.S) {
		const credentialIssuerResourceName = "some-resource-name"

		var r *require.Assertions
		var observableWithInformerOption *testutil.ObservableWithInformerOption
		var configMapInformerFilter controllerlib.Filter

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = testutil.NewObservableWithInformerOption()
			configMapInformer := kubeinformers.NewSharedInformerFactory(nil, 0).Core().V1().ConfigMaps()
			_ = NewKubeConfigInfoPublisherController(
				credentialIssuerResourceName,
				map[string]string{},
				nil,
				nil,
				configMapInformer,
				observableWithInformerOption.WithInformer, // make it possible to observe the behavior of the Filters
			)
			configMapInformerFilter = observableWithInformerOption.GetFilterForInformer(configMapInformer)
		})

		when("watching ConfigMap objects", func() {
			var subject controllerlib.Filter
			var target, wrongNamespace, wrongName, unrelated *corev1.ConfigMap

			it.Before(func() {
				subject = configMapInformerFilter
				target = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cluster-info", Namespace: "kube-public"}}
				wrongNamespace = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cluster-info", Namespace: "wrong-namespace"}}
				wrongName = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: "kube-public"}}
				unrelated = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: "wrong-namespace"}}
			})

			when("the target ConfigMap changes", func() {
				it("returns true to trigger the sync method", func() {
					r.True(subject.Add(target))
					r.True(subject.Update(target, unrelated))
					r.True(subject.Update(unrelated, target))
					r.True(subject.Delete(target))
				})
			})

			when("a ConfigMap from another namespace changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(wrongNamespace))
					r.False(subject.Update(wrongNamespace, unrelated))
					r.False(subject.Update(unrelated, wrongNamespace))
					r.False(subject.Delete(wrongNamespace))
				})
			})

			when("a ConfigMap with a different name changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(wrongName))
					r.False(subject.Update(wrongName, unrelated))
					r.False(subject.Update(unrelated, wrongName))
					r.False(subject.Delete(wrongName))
				})
			})

			when("a ConfigMap with a different name and a different namespace changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(unrelated))
					r.False(subject.Update(unrelated, unrelated))
					r.False(subject.Delete(unrelated))
				})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}

func TestSync(t *testing.T) {
	spec.Run(t, "Sync", func(t *testing.T, when spec.G, it spec.S) {
		const credentialIssuerResourceName = "some-resource-name"

		var r *require.Assertions

		var subject controllerlib.Controller
		var serverOverride *string
		var kubeInformerClient *kubernetesfake.Clientset
		var kubeInformers kubeinformers.SharedInformerFactory
		var pinnipedAPIClient *pinnipedfake.Clientset
		var timeoutContext context.Context
		var timeoutContextCancel context.CancelFunc
		var syncContext *controllerlib.Context

		var expectedCredentialIssuer = func(expectedServerURL, expectedCAData string) (schema.GroupVersionResource, *configv1alpha1.CredentialIssuer, *configv1alpha1.CredentialIssuer) {
			expectedCredentialIssuerGVR := schema.GroupVersionResource{
				Group:    configv1alpha1.GroupName,
				Version:  "v1alpha1",
				Resource: "credentialissuers",
			}

			expectedCreateCredentialIssuer := &configv1alpha1.CredentialIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name: credentialIssuerResourceName,
					Labels: map[string]string{
						"myLabelKey1": "myLabelValue1",
						"myLabelKey2": "myLabelValue2",
					},
				},
			}

			expectedCredentialIssuer := &configv1alpha1.CredentialIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name: credentialIssuerResourceName,
					Labels: map[string]string{
						"myLabelKey1": "myLabelValue1",
						"myLabelKey2": "myLabelValue2",
					},
				},
				Status: configv1alpha1.CredentialIssuerStatus{
					KubeConfigInfo: &configv1alpha1.CredentialIssuerKubeConfigInfo{
						Server:                   expectedServerURL,
						CertificateAuthorityData: expectedCAData,
					},
				},
			}
			return expectedCredentialIssuerGVR, expectedCreateCredentialIssuer, expectedCredentialIssuer
		}

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewKubeConfigInfoPublisherController(
				credentialIssuerResourceName,
				map[string]string{
					"myLabelKey1": "myLabelValue1",
					"myLabelKey2": "myLabelValue2",
				},
				serverOverride,
				pinnipedAPIClient,
				kubeInformers.Core().V1().ConfigMaps(),
				controllerlib.WithInformer,
			)

			// Set this at the last second to support calling subject.Name().
			syncContext = &controllerlib.Context{
				Context: timeoutContext,
				Name:    subject.Name(),
				Key: controllerlib.Key{
					Namespace: "kube-public",
					Name:      "cluster-info",
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
			pinnipedAPIClient = pinnipedfake.NewSimpleClientset()
		})

		it.After(func() {
			timeoutContextCancel()
		})

		when("there is a cluster-info ConfigMap in the kube-public namespace", func() {
			const caData = "c29tZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YQo=" // "some-certificate-authority-data" base64 encoded
			const kubeServerURL = "https://some-server"

			when("the ConfigMap has the expected `kubeconfig` top-level data key", func() {
				it.Before(func() {
					clusterInfoConfigMap := &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Name: "cluster-info", Namespace: "kube-public"},
						// Note that go fmt puts tabs in our file, which we must remove from our configmap yaml below.
						Data: map[string]string{
							"kubeconfig": here.Docf(`
								kind: Config
								apiVersion: v1
								clusters:
								- name: ""
								  cluster:
									certificate-authority-data: "%s"
									server: "%s"`,
								caData, kubeServerURL),
							"uninteresting-key": "uninteresting-value",
						},
					}
					err := kubeInformerClient.Tracker().Add(clusterInfoConfigMap)
					r.NoError(err)
				})

				when("the CredentialIssuer does not already exist", func() {
					it("creates a CredentialIssuer", func() {
						startInformersAndController()
						err := controllerlib.TestSync(t, subject, *syncContext)
						r.NoError(err)

						expectedCredentialIssuerGVR, expectedCreateCredentialIssuer, expectedCredentialIssuer := expectedCredentialIssuer(
							kubeServerURL,
							caData,
						)

						r.Equal(
							[]coretesting.Action{
								coretesting.NewRootGetAction(expectedCredentialIssuerGVR, expectedCreateCredentialIssuer.Name),
								coretesting.NewRootCreateAction(
									expectedCredentialIssuerGVR,
									expectedCreateCredentialIssuer,
								),
								coretesting.NewRootUpdateSubresourceAction(
									expectedCredentialIssuerGVR,
									"status",
									expectedCredentialIssuer,
								),
							},
							pinnipedAPIClient.Actions(),
						)
					})

					when("creating the CredentialIssuer fails", func() {
						it.Before(func() {
							pinnipedAPIClient.PrependReactor(
								"create",
								"credentialissuers",
								func(_ coretesting.Action) (bool, runtime.Object, error) {
									return true, nil, errors.New("create failed")
								},
							)
						})

						it("returns the create error", func() {
							startInformersAndController()
							err := controllerlib.TestSync(t, subject, *syncContext)
							r.EqualError(err, "could not create or update credentialissuer: create failed: create failed")
						})
					})

					when("a server override is passed to the controller", func() {
						it("uses the server override field", func() {
							serverOverride = new(string)
							*serverOverride = "https://some-server-override"

							startInformersAndController()
							err := controllerlib.TestSync(t, subject, *syncContext)
							r.NoError(err)

							expectedCredentialIssuerGVR, expectedCreateCredentialIssuer, expectedCredentialIssuer := expectedCredentialIssuer(
								kubeServerURL,
								caData,
							)
							expectedCredentialIssuer.Status.KubeConfigInfo.Server = "https://some-server-override"

							r.Equal(
								[]coretesting.Action{
									coretesting.NewRootGetAction(expectedCredentialIssuerGVR, expectedCreateCredentialIssuer.Name),
									coretesting.NewRootCreateAction(
										expectedCredentialIssuerGVR,
										expectedCreateCredentialIssuer,
									),
									coretesting.NewRootUpdateSubresourceAction(
										expectedCredentialIssuerGVR,
										"status",
										expectedCredentialIssuer,
									),
								},
								pinnipedAPIClient.Actions(),
							)
						})
					})
				})

				when("the CredentialIssuer already exists", func() {
					when("the CredentialIssuer is already up to date according to the data in the ConfigMap", func() {
						var credentialIssuerGVR schema.GroupVersionResource
						var credentialIssuer *configv1alpha1.CredentialIssuer

						it.Before(func() {
							credentialIssuerGVR, _, credentialIssuer = expectedCredentialIssuer(
								kubeServerURL,
								caData,
							)
							err := pinnipedAPIClient.Tracker().Add(credentialIssuer)
							r.NoError(err)
						})

						it("does not update the CredentialIssuer to avoid unnecessary etcd writes/api calls", func() {
							startInformersAndController()
							err := controllerlib.TestSync(t, subject, *syncContext)
							r.NoError(err)

							r.Equal(
								[]coretesting.Action{
									coretesting.NewRootGetAction(credentialIssuerGVR, credentialIssuer.Name),
								},
								pinnipedAPIClient.Actions(),
							)
						})
					})

					when("the CredentialIssuer is stale compared to the data in the ConfigMap", func() {
						it.Before(func() {
							_, _, expectedCredentialIssuer := expectedCredentialIssuer(
								kubeServerURL,
								caData,
							)
							expectedCredentialIssuer.Status.KubeConfigInfo.Server = "https://some-other-server"
							r.NoError(pinnipedAPIClient.Tracker().Add(expectedCredentialIssuer))
						})

						it("updates the existing CredentialIssuer", func() {
							startInformersAndController()
							err := controllerlib.TestSync(t, subject, *syncContext)
							r.NoError(err)

							expectedCredentialIssuerGVR, _, expectedCredentialIssuer := expectedCredentialIssuer(
								kubeServerURL,
								caData,
							)
							expectedActions := []coretesting.Action{
								coretesting.NewRootGetAction(expectedCredentialIssuerGVR, expectedCredentialIssuer.Name),
								coretesting.NewRootUpdateSubresourceAction(
									expectedCredentialIssuerGVR,
									"status",
									expectedCredentialIssuer,
								),
							}
							r.Equal(expectedActions, pinnipedAPIClient.Actions())
						})

						when("updating the CredentialIssuer fails", func() {
							it.Before(func() {
								pinnipedAPIClient.PrependReactor(
									"update",
									"credentialissuers",
									func(_ coretesting.Action) (bool, runtime.Object, error) {
										return true, nil, errors.New("update failed")
									},
								)
							})

							it("returns the update error", func() {
								startInformersAndController()
								err := controllerlib.TestSync(t, subject, *syncContext)
								r.EqualError(err, "could not create or update credentialissuer: update failed")
							})
						})
					})
				})
			})

			when("the ConfigMap is missing the expected `kubeconfig` top-level data key", func() {
				it.Before(func() {
					clusterInfoConfigMap := &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Name: "cluster-info", Namespace: "kube-public"},
						Data: map[string]string{
							"these are not the droids you're looking for": "uninteresting-value",
						},
					}
					err := kubeInformerClient.Tracker().Add(clusterInfoConfigMap)
					r.NoError(err)
				})

				it("keeps waiting for it to exist", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.NoError(err)
					r.Empty(pinnipedAPIClient.Actions())
				})
			})

			when("the ConfigMap does not have a valid kubeconfig", func() {
				it.Before(func() {
					clusterInfoConfigMap := &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Name: "cluster-info", Namespace: "kube-public"},
						Data: map[string]string{
							"kubeconfig": "this is an invalid kubeconfig",
						},
					}
					err := kubeInformerClient.Tracker().Add(clusterInfoConfigMap)
					r.NoError(err)
				})

				it("keeps waiting for it to be properly formatted", func() {
					startInformersAndController()
					err := controllerlib.TestSync(t, subject, *syncContext)
					r.NoError(err)
					r.Empty(pinnipedAPIClient.Actions())
				})
			})
		})

		when("there is not a cluster-info ConfigMap in the kube-public namespace", func() {
			it.Before(func() {
				unrelatedConfigMap := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "oops this is not the cluster-info ConfigMap",
						Namespace: "kube-public",
					},
				}
				err := kubeInformerClient.Tracker().Add(unrelatedConfigMap)
				r.NoError(err)
			})

			it("keeps waiting for one", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)
				r.Empty(pinnipedAPIClient.Actions())
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
