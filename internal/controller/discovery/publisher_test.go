/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package discovery

import (
	"context"
	"errors"
	"strings"
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

	"github.com/suzerain-io/controller-go"
	"github.com/suzerain-io/pinniped/internal/testutil"
	crdpinnipedv1alpha1 "github.com/suzerain-io/pinniped/kubernetes/1.19/api/apis/crdpinniped/v1alpha1"
	pinnipedfake "github.com/suzerain-io/pinniped/kubernetes/1.19/client-go/clientset/versioned/fake"
	pinnipedinformers "github.com/suzerain-io/pinniped/kubernetes/1.19/client-go/informers/externalversions"
)

func TestInformerFilters(t *testing.T) {
	spec.Run(t, "informer filters", func(t *testing.T, when spec.G, it spec.S) {
		const installedInNamespace = "some-namespace"

		var r *require.Assertions
		var observableWithInformerOption *testutil.ObservableWithInformerOption
		var configMapInformerFilter controller.Filter
		var pinnipedDiscoveryInfoInformerFilter controller.Filter

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = testutil.NewObservableWithInformerOption()
			configMapInformer := kubeinformers.NewSharedInformerFactory(nil, 0).Core().V1().ConfigMaps()
			pinnipedDiscoveryInfoInformer := pinnipedinformers.NewSharedInformerFactory(nil, 0).Crd().V1alpha1().PinnipedDiscoveryInfos()
			_ = NewPublisherController(
				installedInNamespace,
				nil,
				nil,
				configMapInformer,
				pinnipedDiscoveryInfoInformer,
				observableWithInformerOption.WithInformer, // make it possible to observe the behavior of the Filters
			)
			configMapInformerFilter = observableWithInformerOption.GetFilterForInformer(configMapInformer)
			pinnipedDiscoveryInfoInformerFilter = observableWithInformerOption.GetFilterForInformer(pinnipedDiscoveryInfoInformer)
		})

		when("watching ConfigMap objects", func() {
			var subject controller.Filter
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

		when("watching PinnipedDiscoveryInfo objects", func() {
			var subject controller.Filter
			var target, wrongNamespace, wrongName, unrelated *crdpinnipedv1alpha1.PinnipedDiscoveryInfo

			it.Before(func() {
				subject = pinnipedDiscoveryInfoInformerFilter
				target = &crdpinnipedv1alpha1.PinnipedDiscoveryInfo{
					ObjectMeta: metav1.ObjectMeta{Name: "pinniped-config", Namespace: installedInNamespace},
				}
				wrongNamespace = &crdpinnipedv1alpha1.PinnipedDiscoveryInfo{
					ObjectMeta: metav1.ObjectMeta{Name: "pinniped-config", Namespace: "wrong-namespace"},
				}
				wrongName = &crdpinnipedv1alpha1.PinnipedDiscoveryInfo{
					ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: installedInNamespace},
				}
				unrelated = &crdpinnipedv1alpha1.PinnipedDiscoveryInfo{
					ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: "wrong-namespace"},
				}
			})

			when("the target PinnipedDiscoveryInfo changes", func() {
				it("returns true to trigger the sync method", func() {
					r.True(subject.Add(target))
					r.True(subject.Update(target, unrelated))
					r.True(subject.Update(unrelated, target))
					r.True(subject.Delete(target))
				})
			})

			when("a PinnipedDiscoveryInfo from another namespace changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(wrongNamespace))
					r.False(subject.Update(wrongNamespace, unrelated))
					r.False(subject.Update(unrelated, wrongNamespace))
					r.False(subject.Delete(wrongNamespace))
				})
			})

			when("a PinnipedDiscoveryInfo with a different name changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(wrongName))
					r.False(subject.Update(wrongName, unrelated))
					r.False(subject.Update(unrelated, wrongName))
					r.False(subject.Delete(wrongName))
				})
			})

			when("a PinnipedDiscoveryInfo with a different name and a different namespace changes", func() {
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
		const installedInNamespace = "some-namespace"

		var r *require.Assertions

		var subject controller.Controller
		var serverOverride *string
		var kubeInformerClient *kubernetesfake.Clientset
		var pinnipedInformerClient *pinnipedfake.Clientset
		var kubeInformers kubeinformers.SharedInformerFactory
		var pinnipedInformers pinnipedinformers.SharedInformerFactory
		var pinnipedAPIClient *pinnipedfake.Clientset
		var timeoutContext context.Context
		var timeoutContextCancel context.CancelFunc
		var syncContext *controller.Context

		var expectedPinnipedDiscoveryInfo = func(expectedNamespace, expectedServerURL, expectedCAData string) (schema.GroupVersionResource, *crdpinnipedv1alpha1.PinnipedDiscoveryInfo) {
			expectedPinnipedDiscoveryInfoGVR := schema.GroupVersionResource{
				Group:    crdpinnipedv1alpha1.GroupName,
				Version:  "v1alpha1",
				Resource: "pinnipeddiscoveryinfos",
			}
			expectedPinnipedDiscoveryInfo := &crdpinnipedv1alpha1.PinnipedDiscoveryInfo{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pinniped-config",
					Namespace: expectedNamespace,
				},
				Spec: crdpinnipedv1alpha1.PinnipedDiscoveryInfoSpec{
					Server:                   expectedServerURL,
					CertificateAuthorityData: expectedCAData,
				},
			}
			return expectedPinnipedDiscoveryInfoGVR, expectedPinnipedDiscoveryInfo
		}

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewPublisherController(
				installedInNamespace,
				serverOverride,
				pinnipedAPIClient,
				kubeInformers.Core().V1().ConfigMaps(),
				pinnipedInformers.Crd().V1alpha1().PinnipedDiscoveryInfos(),
				controller.WithInformer,
			)

			// Set this at the last second to support calling subject.Name().
			syncContext = &controller.Context{
				Context: timeoutContext,
				Name:    subject.Name(),
				Key: controller.Key{
					Namespace: "kube-public",
					Name:      "cluster-info",
				},
			}

			// Must start informers before calling TestRunSynchronously()
			kubeInformers.Start(timeoutContext.Done())
			pinnipedInformers.Start(timeoutContext.Done())
			controller.TestRunSynchronously(t, subject)
		}

		it.Before(func() {
			r = require.New(t)

			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)

			kubeInformerClient = kubernetesfake.NewSimpleClientset()
			kubeInformers = kubeinformers.NewSharedInformerFactory(kubeInformerClient, 0)
			pinnipedAPIClient = pinnipedfake.NewSimpleClientset()
			pinnipedInformerClient = pinnipedfake.NewSimpleClientset()
			pinnipedInformers = pinnipedinformers.NewSharedInformerFactory(pinnipedInformerClient, 0)
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
							"kubeconfig": strings.ReplaceAll(`
							kind: Config
							apiVersion: v1
							clusters:
							- name: ""
							  cluster:
							    certificate-authority-data: "`+caData+`"
							    server: "`+kubeServerURL+`"`, "\t", "  "),
							"uninteresting-key": "uninteresting-value",
						},
					}
					err := kubeInformerClient.Tracker().Add(clusterInfoConfigMap)
					r.NoError(err)
				})

				when("the PinnipedDiscoveryInfo does not already exist", func() {
					it("creates a PinnipedDiscoveryInfo", func() {
						startInformersAndController()
						err := controller.TestSync(t, subject, *syncContext)
						r.NoError(err)

						expectedPinnipedDiscoveryInfoGVR, expectedPinnipedDiscoveryInfo := expectedPinnipedDiscoveryInfo(
							installedInNamespace,
							kubeServerURL,
							caData,
						)

						r.Equal(
							[]coretesting.Action{
								coretesting.NewCreateAction(
									expectedPinnipedDiscoveryInfoGVR,
									installedInNamespace,
									expectedPinnipedDiscoveryInfo,
								),
							},
							pinnipedAPIClient.Actions(),
						)
					})

					when("creating the PinnipedDiscoveryInfo fails", func() {
						it.Before(func() {
							pinnipedAPIClient.PrependReactor(
								"create",
								"pinnipeddiscoveryinfos",
								func(_ coretesting.Action) (bool, runtime.Object, error) {
									return true, nil, errors.New("create failed")
								},
							)
						})

						it("returns the create error", func() {
							startInformersAndController()
							err := controller.TestSync(t, subject, *syncContext)
							r.EqualError(err, "could not create pinnipeddiscoveryinfo: create failed")
						})
					})

					when("a server override is passed to the controller", func() {
						it("uses the server override field", func() {
							serverOverride = new(string)
							*serverOverride = "https://some-server-override"

							startInformersAndController()
							err := controller.TestSync(t, subject, *syncContext)
							r.NoError(err)

							expectedPinnipedDiscoveryInfoGVR, expectedPinnipedDiscoveryInfo := expectedPinnipedDiscoveryInfo(
								installedInNamespace,
								kubeServerURL,
								caData,
							)
							expectedPinnipedDiscoveryInfo.Spec.Server = "https://some-server-override"

							r.Equal(
								[]coretesting.Action{
									coretesting.NewCreateAction(
										expectedPinnipedDiscoveryInfoGVR,
										installedInNamespace,
										expectedPinnipedDiscoveryInfo,
									),
								},
								pinnipedAPIClient.Actions(),
							)
						})
					})
				})

				when("the PinnipedDiscoveryInfo already exists", func() {
					when("the PinnipedDiscoveryInfo is already up to date according to the data in the ConfigMap", func() {
						it.Before(func() {
							_, expectedPinnipedDiscoveryInfo := expectedPinnipedDiscoveryInfo(
								installedInNamespace,
								kubeServerURL,
								caData,
							)
							err := pinnipedInformerClient.Tracker().Add(expectedPinnipedDiscoveryInfo)
							r.NoError(err)
						})

						it("does not update the PinnipedDiscoveryInfo to avoid unnecessary etcd writes/api calls", func() {
							startInformersAndController()
							err := controller.TestSync(t, subject, *syncContext)
							r.NoError(err)

							r.Empty(pinnipedAPIClient.Actions())
						})
					})

					when("the PinnipedDiscoveryInfo is stale compared to the data in the ConfigMap", func() {
						it.Before(func() {
							_, expectedPinnipedDiscoveryInfo := expectedPinnipedDiscoveryInfo(
								installedInNamespace,
								kubeServerURL,
								caData,
							)
							expectedPinnipedDiscoveryInfo.Spec.Server = "https://some-other-server"
							r.NoError(pinnipedInformerClient.Tracker().Add(expectedPinnipedDiscoveryInfo))
							r.NoError(pinnipedAPIClient.Tracker().Add(expectedPinnipedDiscoveryInfo))
						})

						it("updates the existing PinnipedDiscoveryInfo", func() {
							startInformersAndController()
							err := controller.TestSync(t, subject, *syncContext)
							r.NoError(err)

							expectedPinnipedDiscoveryInfoGVR, expectedPinnipedDiscoveryInfo := expectedPinnipedDiscoveryInfo(
								installedInNamespace,
								kubeServerURL,
								caData,
							)
							expectedActions := []coretesting.Action{
								coretesting.NewUpdateAction(
									expectedPinnipedDiscoveryInfoGVR,
									installedInNamespace,
									expectedPinnipedDiscoveryInfo,
								),
							}
							r.Equal(expectedActions, pinnipedAPIClient.Actions())
						})

						when("updating the PinnipedDiscoveryInfo fails", func() {
							it.Before(func() {
								pinnipedAPIClient.PrependReactor(
									"update",
									"pinnipeddiscoveryinfos",
									func(_ coretesting.Action) (bool, runtime.Object, error) {
										return true, nil, errors.New("update failed")
									},
								)
							})

							it("returns the update error", func() {
								startInformersAndController()
								err := controller.TestSync(t, subject, *syncContext)
								r.EqualError(err, "could not update pinnipeddiscoveryinfo: update failed")
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
					err := controller.TestSync(t, subject, *syncContext)
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
				err := controller.TestSync(t, subject, *syncContext)
				r.NoError(err)
				r.Empty(pinnipedAPIClient.Actions())
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
