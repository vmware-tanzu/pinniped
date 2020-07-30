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
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"

	"github.com/suzerain-io/controller-go"
	placeholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder/v1alpha1"
	placeholderfake "github.com/suzerain-io/placeholder-name-client-go/pkg/generated/clientset/versioned/fake"
)

func TestRun(t *testing.T) {
	spec.Run(t, "publisher", func(t *testing.T, when spec.G, it spec.S) {
		const installedInNamespace = "some-namespace"

		var r *require.Assertions

		var subject controller.Controller
		var kubeClient *kubernetesfake.Clientset
		var placeholderClient *placeholderfake.Clientset
		var timeoutContext context.Context
		var timeoutContextCancel context.CancelFunc
		var controllerContext *controller.Context

		var expectedLoginDiscoveryConfig = func(expectedNamespace, expectedServerURL, expectedCAData string) (schema.GroupVersionResource, *placeholderv1alpha1.LoginDiscoveryConfig) {
			expectedLoginDiscoveryConfigGVR := schema.GroupVersionResource{
				Group:    placeholderv1alpha1.GroupName,
				Version:  "v1alpha1",
				Resource: "logindiscoveryconfigs",
			}
			expectedLoginDiscoveryConfig := &placeholderv1alpha1.LoginDiscoveryConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "placeholder-name-config",
					Namespace: expectedNamespace,
				},
				Spec: placeholderv1alpha1.LoginDiscoveryConfigSpec{
					Server:                   expectedServerURL,
					CertificateAuthorityData: expectedCAData,
				},
			}
			return expectedLoginDiscoveryConfigGVR, expectedLoginDiscoveryConfig
		}

		it.Before(func() {
			r = require.New(t)
			kubeClient = kubernetesfake.NewSimpleClientset()
			placeholderClient = placeholderfake.NewSimpleClientset()
			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)
			subject = NewPublisherController(installedInNamespace, kubeClient, placeholderClient)
			controllerContext = &controller.Context{
				Context: timeoutContext,
				Name:    subject.Name(),
				Key: controller.Key{
					Namespace: "kube-public",
					Name:      "cluster-info",
				},
			}
		})

		when("there is a cluster-info ConfigMap in the kube-public namespace", func() {
			const caData = "c29tZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YQo=" // "some-certificate-authority-data" base64 encoded
			const kubeServerURL = "https://some-server"
			var clusterInfoConfigMap *corev1.ConfigMap

			when("the ConfigMap has the expected `kubeconfig` top-level data key", func() {
				it.Before(func() {
					clusterInfoConfigMap = &corev1.ConfigMap{
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
					err := kubeClient.Tracker().Add(clusterInfoConfigMap)
					r.NoError(err)
				})

				when("the LoginDiscoveryConfig does not already exist", func() {
					it("creates a LoginDiscoveryConfig", func() {
						defer timeoutContextCancel()

						err := controller.TestSync(t, subject, *controllerContext)
						r.NoError(err)

						expectedLoginDiscoveryConfigGVR, expectedLoginDiscoveryConfig := expectedLoginDiscoveryConfig(
							installedInNamespace,
							kubeServerURL,
							caData,
						)
						expectedActions := []coretesting.Action{
							coretesting.NewGetAction(
								expectedLoginDiscoveryConfigGVR,
								installedInNamespace,
								expectedLoginDiscoveryConfig.Name,
							),
							coretesting.NewCreateAction(
								expectedLoginDiscoveryConfigGVR,
								installedInNamespace,
								expectedLoginDiscoveryConfig,
							),
						}
						r.Equal(expectedActions, placeholderClient.Actions())
					})

					when("creating the LoginDiscoveryConfig fails", func() {
						it.Before(func() {
							placeholderClient.PrependReactor(
								"create",
								"logindiscoveryconfigs",
								func(_ coretesting.Action) (bool, runtime.Object, error) {
									return true, nil, errors.New("create failed")
								},
							)
						})

						it("returns the create error", func() {
							err := controller.TestSync(t, subject, *controllerContext)
							r.EqualError(err, "could not create logindiscoveryconfig: create failed")
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
							err := placeholderClient.Tracker().Add(expectedLoginDiscoveryConfig)
							r.NoError(err)
						})

						it("does not update the LoginDiscoveryConfig to avoid unnecessary etcd writes/api calls", func() {
							err := controller.TestSync(t, subject, *controllerContext)
							r.NoError(err)

							expectedLoginDiscoveryConfigGVR, expectedLoginDiscoveryConfig := expectedLoginDiscoveryConfig(
								installedInNamespace,
								kubeServerURL,
								caData,
							)
							expectedActions := []coretesting.Action{
								coretesting.NewGetAction(
									expectedLoginDiscoveryConfigGVR,
									installedInNamespace,
									expectedLoginDiscoveryConfig.Name,
								),
							}
							r.Equal(expectedActions, placeholderClient.Actions())
						})

						when("getting the LoginDiscoveryConfig fails", func() {
							it.Before(func() {
								placeholderClient.PrependReactor(
									"get",
									"logindiscoveryconfigs",
									func(_ coretesting.Action) (bool, runtime.Object, error) {
										return true, nil, errors.New("get failed")
									},
								)
							})

							it("returns the get error", func() {
								err := controller.TestSync(t, subject, *controllerContext)
								r.EqualError(err, "could not get logindiscoveryconfig: get failed")
							})
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
							err := placeholderClient.Tracker().Add(expectedLoginDiscoveryConfig)
							r.NoError(err)
						})

						it("updates the existing LoginDiscoveryConfig", func() {
							err := controller.TestSync(t, subject, *controllerContext)
							r.NoError(err)

							expectedLoginDiscoveryConfigGVR, expectedLoginDiscoveryConfig := expectedLoginDiscoveryConfig(
								installedInNamespace,
								kubeServerURL,
								caData,
							)
							expectedActions := []coretesting.Action{
								coretesting.NewGetAction(
									expectedLoginDiscoveryConfigGVR,
									installedInNamespace,
									expectedLoginDiscoveryConfig.Name,
								),
								coretesting.NewUpdateAction(
									expectedLoginDiscoveryConfigGVR,
									installedInNamespace,
									expectedLoginDiscoveryConfig,
								),
							}
							r.Equal(expectedActions, placeholderClient.Actions())
						})

						when("updating the LoginDiscoveryConfig fails", func() {
							it.Before(func() {
								placeholderClient.PrependReactor(
									"update",
									"logindiscoveryconfigs",
									func(_ coretesting.Action) (bool, runtime.Object, error) {
										return true, nil, errors.New("update failed")
									},
								)
							})

							it("returns the update error", func() {
								err := controller.TestSync(t, subject, *controllerContext)
								r.EqualError(err, "could not update logindiscoveryconfig: update failed")
							})
						})
					})
				})
			})

			when("the ConfigMap is missing the expected `kubeconfig` top-level data key", func() {
				it.Before(func() {
					clusterInfoConfigMap = &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Name: "cluster-info", Namespace: "kube-public"},
						Data: map[string]string{
							"these are not the droids you're looking for": "uninteresting-value",
						},
					}
					err := kubeClient.Tracker().Add(clusterInfoConfigMap)
					r.NoError(err)
				})

				it("keeps waiting for it to exist", func() {
					err := controller.TestSync(t, subject, *controllerContext)
					r.NoError(err)
					r.Empty(placeholderClient.Actions())
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
				err := kubeClient.Tracker().Add(unrelatedConfigMap)
				r.NoError(err)
			})

			it("keeps waiting for one", func() {
				err := controller.TestSync(t, subject, *controllerContext)
				r.NoError(err)
				r.Empty(placeholderClient.Actions())
			})
		})

		when("getting the cluster-info ConfigMap in the kube-public namespace fails", func() {
			it.Before(func() {
				kubeClient.PrependReactor(
					"get",
					"configmaps",
					func(_ coretesting.Action) (bool, runtime.Object, error) {
						return true, nil, errors.New("get failed")
					},
				)
			})

			it("returns an error", func() {
				err := controller.TestSync(t, subject, *controllerContext)
				r.EqualError(err, "failed to get cluster-info configmap: get failed")
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
