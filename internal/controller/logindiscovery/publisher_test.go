/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package logindiscovery

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
	crdsplaceholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/crdsplaceholder/v1alpha1"
	placeholderfake "github.com/suzerain-io/placeholder-name/kubernetes/1.19/client-go/clientset/versioned/fake"
	placeholderinformers "github.com/suzerain-io/placeholder-name/kubernetes/1.19/client-go/informers/externalversions"
)

type ObservableWithInformerOption struct {
	InformerToFilterMap map[controller.InformerGetter]controller.Filter
}

func NewObservableWithInformerOption() *ObservableWithInformerOption {
	return &ObservableWithInformerOption{
		InformerToFilterMap: make(map[controller.InformerGetter]controller.Filter),
	}
}

func (owi *ObservableWithInformerOption) WithInformer(
	getter controller.InformerGetter,
	filter controller.Filter,
	opt controller.InformerOption) controller.Option {
	owi.InformerToFilterMap[getter] = filter
	return controller.WithInformer(getter, filter, opt)
}

func TestInformerFilters(t *testing.T) {
	spec.Run(t, "informer filters", func(t *testing.T, when spec.G, it spec.S) {
		const installedInNamespace = "some-namespace"

		var r *require.Assertions
		var observableWithInformerOption *ObservableWithInformerOption
		var configMapInformerFilter controller.Filter
		var loginDiscoveryConfigInformerFilter controller.Filter

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = NewObservableWithInformerOption()
			configMapInformer := kubeinformers.NewSharedInformerFactory(nil, 0).Core().V1().ConfigMaps()
			loginDiscoveryConfigInformer := placeholderinformers.NewSharedInformerFactory(nil, 0).Crds().V1alpha1().LoginDiscoveryConfigs()
			_ = NewPublisherController(
				installedInNamespace,
				nil,
				nil,
				configMapInformer,
				loginDiscoveryConfigInformer,
				observableWithInformerOption.WithInformer, // make it possible to observe the behavior of the Filters
			)
			configMapInformerFilter = observableWithInformerOption.InformerToFilterMap[configMapInformer]
			loginDiscoveryConfigInformerFilter = observableWithInformerOption.InformerToFilterMap[loginDiscoveryConfigInformer]
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

		when("watching LoginDiscoveryConfig objects", func() {
			var subject controller.Filter
			var target, wrongNamespace, wrongName, unrelated *crdsplaceholderv1alpha1.LoginDiscoveryConfig

			it.Before(func() {
				subject = loginDiscoveryConfigInformerFilter
				target = &crdsplaceholderv1alpha1.LoginDiscoveryConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "placeholder-name-config", Namespace: installedInNamespace},
				}
				wrongNamespace = &crdsplaceholderv1alpha1.LoginDiscoveryConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "placeholder-name-config", Namespace: "wrong-namespace"},
				}
				wrongName = &crdsplaceholderv1alpha1.LoginDiscoveryConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: installedInNamespace},
				}
				unrelated = &crdsplaceholderv1alpha1.LoginDiscoveryConfig{
					ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: "wrong-namespace"},
				}
			})

			when("the target LoginDiscoveryConfig changes", func() {
				it("returns true to trigger the sync method", func() {
					r.True(subject.Add(target))
					r.True(subject.Update(target, unrelated))
					r.True(subject.Update(unrelated, target))
					r.True(subject.Delete(target))
				})
			})

			when("a LoginDiscoveryConfig from another namespace changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(wrongNamespace))
					r.False(subject.Update(wrongNamespace, unrelated))
					r.False(subject.Update(unrelated, wrongNamespace))
					r.False(subject.Delete(wrongNamespace))
				})
			})

			when("a LoginDiscoveryConfig with a different name changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(wrongName))
					r.False(subject.Update(wrongName, unrelated))
					r.False(subject.Update(unrelated, wrongName))
					r.False(subject.Delete(wrongName))
				})
			})

			when("a LoginDiscoveryConfig with a different name and a different namespace changes", func() {
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
		var placeholderInformerClient *placeholderfake.Clientset
		var kubeInformers kubeinformers.SharedInformerFactory
		var placeholderInformers placeholderinformers.SharedInformerFactory
		var placeholderAPIClient *placeholderfake.Clientset
		var timeoutContext context.Context
		var timeoutContextCancel context.CancelFunc
		var syncContext *controller.Context

		var expectedLoginDiscoveryConfig = func(expectedNamespace, expectedServerURL, expectedCAData string) (schema.GroupVersionResource, *crdsplaceholderv1alpha1.LoginDiscoveryConfig) {
			expectedLoginDiscoveryConfigGVR := schema.GroupVersionResource{
				Group:    crdsplaceholderv1alpha1.GroupName,
				Version:  "v1alpha1",
				Resource: "logindiscoveryconfigs",
			}
			expectedLoginDiscoveryConfig := &crdsplaceholderv1alpha1.LoginDiscoveryConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "placeholder-name-config",
					Namespace: expectedNamespace,
				},
				Spec: crdsplaceholderv1alpha1.LoginDiscoveryConfigSpec{
					Server:                   expectedServerURL,
					CertificateAuthorityData: expectedCAData,
				},
			}
			return expectedLoginDiscoveryConfigGVR, expectedLoginDiscoveryConfig
		}

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewPublisherController(
				installedInNamespace,
				serverOverride,
				placeholderAPIClient,
				kubeInformers.Core().V1().ConfigMaps(),
				placeholderInformers.Crds().V1alpha1().LoginDiscoveryConfigs(),
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
			placeholderInformers.Start(timeoutContext.Done())
			controller.TestRunSynchronously(t, subject)
		}

		it.Before(func() {
			r = require.New(t)

			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)

			kubeInformerClient = kubernetesfake.NewSimpleClientset()
			kubeInformers = kubeinformers.NewSharedInformerFactory(kubeInformerClient, 0)
			placeholderAPIClient = placeholderfake.NewSimpleClientset()
			placeholderInformerClient = placeholderfake.NewSimpleClientset()
			placeholderInformers = placeholderinformers.NewSharedInformerFactory(placeholderInformerClient, 0)
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

				when("the LoginDiscoveryConfig does not already exist", func() {
					it("creates a LoginDiscoveryConfig", func() {
						startInformersAndController()
						err := controller.TestSync(t, subject, *syncContext)
						r.NoError(err)

						expectedLoginDiscoveryConfigGVR, expectedLoginDiscoveryConfig := expectedLoginDiscoveryConfig(
							installedInNamespace,
							kubeServerURL,
							caData,
						)

						r.Equal(
							[]coretesting.Action{
								coretesting.NewCreateAction(
									expectedLoginDiscoveryConfigGVR,
									installedInNamespace,
									expectedLoginDiscoveryConfig,
								),
							},
							placeholderAPIClient.Actions(),
						)
					})

					when("creating the LoginDiscoveryConfig fails", func() {
						it.Before(func() {
							placeholderAPIClient.PrependReactor(
								"create",
								"logindiscoveryconfigs",
								func(_ coretesting.Action) (bool, runtime.Object, error) {
									return true, nil, errors.New("create failed")
								},
							)
						})

						it("returns the create error", func() {
							startInformersAndController()
							err := controller.TestSync(t, subject, *syncContext)
							r.EqualError(err, "could not create logindiscoveryconfig: create failed")
						})
					})

					when("a server override is passed to the controller", func() {
						it("uses the server override field", func() {
							serverOverride = new(string)
							*serverOverride = "https://some-server-override"

							startInformersAndController()
							err := controller.TestSync(t, subject, *syncContext)
							r.NoError(err)

							expectedLoginDiscoveryConfigGVR, expectedLoginDiscoveryConfig := expectedLoginDiscoveryConfig(
								installedInNamespace,
								kubeServerURL,
								caData,
							)
							expectedLoginDiscoveryConfig.Spec.Server = "https://some-server-override"

							r.Equal(
								[]coretesting.Action{
									coretesting.NewCreateAction(
										expectedLoginDiscoveryConfigGVR,
										installedInNamespace,
										expectedLoginDiscoveryConfig,
									),
								},
								placeholderAPIClient.Actions(),
							)
						})
					})
				})

				when("the LoginDiscoveryConfig already exists", func() {
					when("the LoginDiscoveryConfig is already up to date according to the data in the ConfigMap", func() {
						it.Before(func() {
							_, expectedLoginDiscoveryConfig := expectedLoginDiscoveryConfig(
								installedInNamespace,
								kubeServerURL,
								caData,
							)
							err := placeholderInformerClient.Tracker().Add(expectedLoginDiscoveryConfig)
							r.NoError(err)
						})

						it("does not update the LoginDiscoveryConfig to avoid unnecessary etcd writes/api calls", func() {
							startInformersAndController()
							err := controller.TestSync(t, subject, *syncContext)
							r.NoError(err)

							r.Empty(placeholderAPIClient.Actions())
						})
					})

					when("the LoginDiscoveryConfig is stale compared to the data in the ConfigMap", func() {
						it.Before(func() {
							_, expectedLoginDiscoveryConfig := expectedLoginDiscoveryConfig(
								installedInNamespace,
								kubeServerURL,
								caData,
							)
							expectedLoginDiscoveryConfig.Spec.Server = "https://some-other-server"
							r.NoError(placeholderInformerClient.Tracker().Add(expectedLoginDiscoveryConfig))
							r.NoError(placeholderAPIClient.Tracker().Add(expectedLoginDiscoveryConfig))
						})

						it("updates the existing LoginDiscoveryConfig", func() {
							startInformersAndController()
							err := controller.TestSync(t, subject, *syncContext)
							r.NoError(err)

							expectedLoginDiscoveryConfigGVR, expectedLoginDiscoveryConfig := expectedLoginDiscoveryConfig(
								installedInNamespace,
								kubeServerURL,
								caData,
							)
							expectedActions := []coretesting.Action{
								coretesting.NewUpdateAction(
									expectedLoginDiscoveryConfigGVR,
									installedInNamespace,
									expectedLoginDiscoveryConfig,
								),
							}
							r.Equal(expectedActions, placeholderAPIClient.Actions())
						})

						when("updating the LoginDiscoveryConfig fails", func() {
							it.Before(func() {
								placeholderAPIClient.PrependReactor(
									"update",
									"logindiscoveryconfigs",
									func(_ coretesting.Action) (bool, runtime.Object, error) {
										return true, nil, errors.New("update failed")
									},
								)
							})

							it("returns the update error", func() {
								startInformersAndController()
								err := controller.TestSync(t, subject, *syncContext)
								r.EqualError(err, "could not update logindiscoveryconfig: update failed")
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
					r.Empty(placeholderAPIClient.Actions())
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
				r.Empty(placeholderAPIClient.Actions())
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
