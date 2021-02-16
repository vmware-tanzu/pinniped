// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonatorconfig

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
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
	"k8s.io/client-go/tools/cache"

	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/testutil"
)

type tlsListenerWrapper struct {
	listener   net.Listener
	closeError error
}

func (t *tlsListenerWrapper) Accept() (net.Conn, error) {
	return t.listener.Accept()
}

func (t *tlsListenerWrapper) Close() error {
	if t.closeError != nil {
		// Really close the connection and then "pretend" that there was an error during close.
		_ = t.listener.Close()
		return t.closeError
	}
	return t.listener.Close()
}

func (t *tlsListenerWrapper) Addr() net.Addr {
	return t.listener.Addr()
}

func TestImpersonatorConfigControllerOptions(t *testing.T) {
	spec.Run(t, "options", func(t *testing.T, when spec.G, it spec.S) {
		const installedInNamespace = "some-namespace"
		const configMapResourceName = "some-configmap-resource-name"
		const generatedLoadBalancerServiceName = "some-service-resource-name"

		var r *require.Assertions
		var observableWithInformerOption *testutil.ObservableWithInformerOption
		var observableWithInitialEventOption *testutil.ObservableWithInitialEventOption
		var configMapsInformerFilter controllerlib.Filter

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = testutil.NewObservableWithInformerOption()
			observableWithInitialEventOption = testutil.NewObservableWithInitialEventOption()
			configMapsInformer := kubeinformers.NewSharedInformerFactory(nil, 0).Core().V1().ConfigMaps()
			_ = NewImpersonatorConfigController(
				installedInNamespace,
				configMapResourceName,
				nil,
				configMapsInformer,
				observableWithInformerOption.WithInformer,
				observableWithInitialEventOption.WithInitialEvent,
				generatedLoadBalancerServiceName,
				nil,
				nil,
				nil,
			)
			configMapsInformerFilter = observableWithInformerOption.GetFilterForInformer(configMapsInformer)
		})

		when("watching ConfigMap objects", func() {
			var subject controllerlib.Filter
			var target, wrongNamespace, wrongName, unrelated *corev1.ConfigMap

			it.Before(func() {
				subject = configMapsInformerFilter
				target = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: configMapResourceName, Namespace: installedInNamespace}}
				wrongNamespace = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: configMapResourceName, Namespace: "wrong-namespace"}}
				wrongName = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: installedInNamespace}}
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

		when("starting up", func() {
			it("asks for an initial event because the ConfigMap may not exist yet and it needs to run anyway", func() {
				r.Equal(&controllerlib.Key{
					Namespace: installedInNamespace,
					Name:      configMapResourceName,
				}, observableWithInitialEventOption.GetInitialEventKey())
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}

func TestImpersonatorConfigControllerSync(t *testing.T) {
	spec.Run(t, "Sync", func(t *testing.T, when spec.G, it spec.S) {
		const installedInNamespace = "some-namespace"
		const configMapResourceName = "some-configmap-resource-name"
		const generatedLoadBalancerServiceName = "some-service-resource-name"
		var labels = map[string]string{"app": "app-name", "other-key": "other-value"}

		var r *require.Assertions

		var subject controllerlib.Controller
		var kubeAPIClient *kubernetesfake.Clientset
		var kubeInformerClient *kubernetesfake.Clientset
		var kubeInformers kubeinformers.SharedInformerFactory
		var timeoutContext context.Context
		var timeoutContextCancel context.CancelFunc
		var syncContext *controllerlib.Context
		var startTLSListenerFuncWasCalled int
		var startTLSListenerFuncError error
		var startTLSListenerUponCloseError error
		var httpHanderFactoryFuncError error
		var startedTLSListener net.Listener

		var startTLSListenerFunc = func(network, listenAddress string, config *tls.Config) (net.Listener, error) {
			startTLSListenerFuncWasCalled++
			r.Equal("tcp", network)
			r.Equal(":8444", listenAddress)
			r.Equal(uint16(tls.VersionTLS12), config.MinVersion)
			if startTLSListenerFuncError != nil {
				return nil, startTLSListenerFuncError
			}
			var err error
			//nolint: gosec // Intentionally binding to all network interfaces.
			startedTLSListener, err = tls.Listen(network, ":0", config) // automatically choose the port for unit tests
			r.NoError(err)
			return &tlsListenerWrapper{listener: startedTLSListener, closeError: startTLSListenerUponCloseError}, nil
		}

		var closeTLSListener = func() {
			if startedTLSListener != nil {
				err := startedTLSListener.Close()
				// Ignore when the production code has already closed the server because there is nothing to
				// clean up in that case.
				if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
					r.NoError(err)
				}
			}
		}

		var requireTLSServerIsRunning = func() {
			r.Greater(startTLSListenerFuncWasCalled, 0)

			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // TODO once we're using certs, do not skip verify
			}
			client := &http.Client{Transport: tr}
			url := "https://" + startedTLSListener.Addr().String()
			req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
			r.NoError(err)
			resp, err := client.Do(req)
			r.NoError(err)

			r.Equal(http.StatusOK, resp.StatusCode)
			body, err := ioutil.ReadAll(resp.Body)
			r.NoError(resp.Body.Close())
			r.NoError(err)
			r.Equal("hello world", string(body))
		}

		var requireTLSServerIsNoLongerRunning = func() {
			r.Greater(startTLSListenerFuncWasCalled, 0)
			_, err := tls.Dial(
				startedTLSListener.Addr().Network(),
				startedTLSListener.Addr().String(),
				&tls.Config{InsecureSkipVerify: true}, //nolint:gosec // TODO once we're using certs, do not skip verify
			)
			r.Error(err)
			r.Regexp(`dial tcp \[::\]:[0-9]+: connect: connection refused`, err.Error())
		}

		var requireTLSServerWasNeverStarted = func() {
			r.Equal(0, startTLSListenerFuncWasCalled)
		}

		var waitForInformerCacheToSeeResourceVersion = func(informer cache.SharedIndexInformer, wantVersion string) {
			r.Eventually(func() bool {
				return informer.LastSyncResourceVersion() == wantVersion
			}, 10*time.Second, time.Millisecond)
		}

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewImpersonatorConfigController(
				installedInNamespace,
				configMapResourceName,
				kubeAPIClient,
				kubeInformers.Core().V1().ConfigMaps(),
				controllerlib.WithInformer,
				controllerlib.WithInitialEvent,
				generatedLoadBalancerServiceName,
				labels,
				startTLSListenerFunc,
				func() (http.Handler, error) {
					return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						_, err := fmt.Fprintf(w, "hello world")
						r.NoError(err)
					}), httpHanderFactoryFuncError
				},
			)

			// Set this at the last second to support calling subject.Name().
			syncContext = &controllerlib.Context{
				Context: timeoutContext,
				Name:    subject.Name(),
				Key: controllerlib.Key{
					Namespace: installedInNamespace,
					Name:      configMapResourceName,
				},
			}

			// Must start informers before calling TestRunSynchronously()
			kubeInformers.Start(timeoutContext.Done())
			controllerlib.TestRunSynchronously(t, subject)
		}

		var addImpersonatorConfigMapToTracker = func(resourceName, configYAML string) {
			impersonatorConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: installedInNamespace,
					// Note that this seems to be ignored by the informer during initial creation, so actually
					// the informer will see this as resource version "". Leaving it here to express the intent
					// that the initial version is version 0.
					ResourceVersion: "0",
				},
				Data: map[string]string{
					"config.yaml": configYAML,
				},
			}
			r.NoError(kubeInformerClient.Tracker().Add(impersonatorConfigMap))
		}

		var updateImpersonatorConfigMapInTracker = func(resourceName, configYAML, newResourceVersion string) {
			impersonatorConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: installedInNamespace,
					// Different resource version compared to the initial version when this resource was created
					// so we can tell when the informer cache has cached this newly updated version.
					ResourceVersion: newResourceVersion,
				},
				Data: map[string]string{
					"config.yaml": configYAML,
				},
			}
			r.NoError(kubeInformerClient.Tracker().Update(
				schema.GroupVersionResource{Version: "v1", Resource: "configmaps"},
				impersonatorConfigMap,
				installedInNamespace,
			))
		}

		var addNodeWithRoleToTracker = func(role string) {
			r.NoError(kubeAPIClient.Tracker().Add(
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node",
						Labels: map[string]string{"kubernetes.io/node-role": role},
					},
				},
			))
		}

		it.Before(func() {
			r = require.New(t)

			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)

			kubeInformerClient = kubernetesfake.NewSimpleClientset()
			kubeInformers = kubeinformers.NewSharedInformerFactoryWithOptions(kubeInformerClient, 0,
				kubeinformers.WithNamespace(installedInNamespace),
			)
			kubeAPIClient = kubernetesfake.NewSimpleClientset()
		})

		it.After(func() {
			timeoutContextCancel()
			closeTLSListener()
		})

		when("the ConfigMap does not yet exist in the installation namespace or it was deleted (defaults to auto mode)", func() {
			it.Before(func() {
				addImpersonatorConfigMapToTracker("some-other-ConfigMap", "foo: bar")
			})

			when("there are visible control plane nodes", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("control-plane")
				})

				it("does not start the impersonator", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					requireTLSServerWasNeverStarted()
				})
			})

			when("there are not visible control plane nodes", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker")
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				})

				it("automatically starts the impersonator", func() {
					requireTLSServerIsRunning()
				})

				it("starts the load balancer automatically", func() {
					// action 0: list nodes
					// action 1: create load balancer
					// that should be all
					createLoadBalancerAction := kubeAPIClient.Actions()[1].(coretesting.CreateAction)
					r.Equal("create", createLoadBalancerAction.GetVerb())
					createdLoadBalancerService := createLoadBalancerAction.GetObject().(*corev1.Service)
					r.Equal(generatedLoadBalancerServiceName, createdLoadBalancerService.Name)
					r.Equal(installedInNamespace, createdLoadBalancerService.Namespace)
					r.Equal(corev1.ServiceTypeLoadBalancer, createdLoadBalancerService.Spec.Type)
					r.Equal("app-name", createdLoadBalancerService.Spec.Selector["app"])
					r.Equal(labels, createdLoadBalancerService.Labels)
				})
			})
		})

		when("sync is called more than once", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("worker")
			})

			it("only starts the impersonator once and only lists the cluster's nodes once", func() {
				startInformersAndController()
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				r.Equal(2, len(kubeAPIClient.Actions()))
				r.Equal(
					coretesting.NewListAction(
						schema.GroupVersionResource{Version: "v1", Resource: "nodes"},
						schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Node"},
						"",
						metav1.ListOptions{}),
					kubeAPIClient.Actions()[0],
				)

				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				r.Equal(1, startTLSListenerFuncWasCalled) // wasn't started a second time
				requireTLSServerIsRunning()               // still running
				r.Equal(2, len(kubeAPIClient.Actions()))  // no new API calls
			})
		})

		when("getting the control plane nodes returns an error, e.g. when there are no nodes", func() {
			it("returns an error", func() {
				startInformersAndController()
				r.EqualError(controllerlib.TestSync(t, subject, *syncContext), "no nodes found")
				requireTLSServerWasNeverStarted()
			})
		})

		when("the http handler factory function returns an error", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("worker")
				httpHanderFactoryFuncError = errors.New("some factory error")
			})

			it("returns an error", func() {
				startInformersAndController()
				r.EqualError(controllerlib.TestSync(t, subject, *syncContext), "some factory error")
				requireTLSServerWasNeverStarted()
			})
		})

		when("the configmap is invalid", func() {
			it.Before(func() {
				addImpersonatorConfigMapToTracker(configMapResourceName, "not yaml")
			})

			it("returns an error", func() {
				startInformersAndController()
				r.EqualError(controllerlib.TestSync(t, subject, *syncContext), "invalid impersonator configuration: decode yaml: error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type impersonator.Config")
				requireTLSServerWasNeverStarted()
			})
		})

		when("the ConfigMap is already in the installation namespace", func() {
			when("the configuration is auto mode with an endpoint", func() {
				it.Before(func() {
					addImpersonatorConfigMapToTracker(configMapResourceName, here.Doc(`
						mode: auto
						endpoint: https://proxy.example.com:8443/
					  `),
					)
				})

				when("there are visible control plane nodes", func() {
					it.Before(func() {
						addNodeWithRoleToTracker("control-plane")
					})

					it("does not start the impersonator", func() {
						startInformersAndController()
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))
						requireTLSServerWasNeverStarted()
					})
				})

				when("there are not visible control plane nodes", func() {
					it.Before(func() {
						addNodeWithRoleToTracker("worker")
					})

					it("starts the impersonator according to the settings in the ConfigMap", func() {
						startInformersAndController()
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))
						requireTLSServerIsRunning()
						r.Equal(1, len(kubeAPIClient.Actions()))
					})
				})
			})

			when("the configuration is disabled mode", func() {
				it.Before(func() {
					addImpersonatorConfigMapToTracker(configMapResourceName, "mode: disabled")
					addNodeWithRoleToTracker("worker")
				})

				it("does not start the impersonator", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					requireTLSServerWasNeverStarted()
				})
			})

			when("the configuration is enabled mode", func() {
				it.Before(func() {
					addImpersonatorConfigMapToTracker(configMapResourceName, "mode: enabled")
					addNodeWithRoleToTracker("control-plane")
				})

				it("starts the impersonator regardless of the visibility of control plane nodes", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					requireTLSServerIsRunning()
				})

				it("returns an error when the tls listener fails to start", func() {
					startTLSListenerFuncError = errors.New("tls error")
					startInformersAndController()
					r.EqualError(controllerlib.TestSync(t, subject, *syncContext), "tls error")
				})

				it("does not start the load balancer if there are control plane nodes", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					// action 0: list nodes
					// that should be all
					r.Equal(1, len(kubeAPIClient.Actions()))
				})
			})

			when("the configuration switches from enabled to disabled mode", func() {
				it.Before(func() {
					addImpersonatorConfigMapToTracker(configMapResourceName, "mode: enabled")
					addNodeWithRoleToTracker("worker")
				})

				it("starts the impersonator and loadbalancer, then shuts it down, then starts it again", func() {
					startInformersAndController()

					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					requireTLSServerIsRunning()
					// TODO extract this
					// action 0: list nodes
					// action 1: create load balancer
					// that should be all
					createLoadBalancerAction := kubeAPIClient.Actions()[1].(coretesting.CreateAction)
					r.Equal("create", createLoadBalancerAction.GetVerb())
					createdLoadBalancerService := createLoadBalancerAction.GetObject().(*corev1.Service)
					r.Equal(generatedLoadBalancerServiceName, createdLoadBalancerService.Name)
					r.Equal(installedInNamespace, createdLoadBalancerService.Namespace)
					r.Equal(corev1.ServiceTypeLoadBalancer, createdLoadBalancerService.Spec.Type)
					r.Equal("app-name", createdLoadBalancerService.Spec.Selector["app"])
					r.Equal(labels, createdLoadBalancerService.Labels)

					updateImpersonatorConfigMapInTracker(configMapResourceName, "mode: disabled", "1")
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().ConfigMaps().Informer(), "1")

					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					requireTLSServerIsNoLongerRunning()
					deleteLoadBalancerAction := kubeAPIClient.Actions()[2].(coretesting.DeleteAction)
					r.Equal("delete", deleteLoadBalancerAction.GetVerb())
					r.Equal(generatedLoadBalancerServiceName, deleteLoadBalancerAction.GetName())

					updateImpersonatorConfigMapInTracker(configMapResourceName, "mode: enabled", "2")
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().ConfigMaps().Informer(), "2")

					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					requireTLSServerIsRunning()
				})

				when("there is an error while shutting down the server", func() {
					it.Before(func() {
						startTLSListenerUponCloseError = errors.New("fake server close error")
					})

					it("returns the error from the sync function", func() {
						startInformersAndController()
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))
						requireTLSServerIsRunning()

						updateImpersonatorConfigMapInTracker(configMapResourceName, "mode: disabled", "1")
						waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().ConfigMaps().Informer(), "1")

						r.EqualError(controllerlib.TestSync(t, subject, *syncContext), "fake server close error")
						requireTLSServerIsNoLongerRunning()
					})
				})
			})

			when("the endpoint switches from not specified, to specified, to not specified", func() {
				it.Before(func() {
					addImpersonatorConfigMapToTracker(configMapResourceName, here.Doc(`
						mode: enabled
						endpoint: https://proxy.example.com:8443/
					  `))
					addNodeWithRoleToTracker("worker")
				})

				it("starts, stops, restarts the loadbalancer", func() {
					startInformersAndController()

					r.NoError(controllerlib.TestSync(t, subject, *syncContext))

					loadBalancer, err := kubeAPIClient.CoreV1().Services(installedInNamespace).Get(context.Background(), generatedLoadBalancerServiceName, metav1.GetOptions{})
					r.Nil(loadBalancer)
					r.EqualError(err, "services \"some-service-resource-name\" not found")

					updateImpersonatorConfigMapInTracker(configMapResourceName, "mode: enabled", "1")
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().ConfigMaps().Informer(), "1")

					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					loadBalancer, err = kubeAPIClient.CoreV1().Services(installedInNamespace).Get(context.Background(), generatedLoadBalancerServiceName, metav1.GetOptions{})
					r.NotNil(loadBalancer)
					r.NoError(err, "services \"some-service-resource-name\" not found")

					updateImpersonatorConfigMapInTracker(configMapResourceName, here.Doc(`
						mode: enabled
						endpoint: https://proxy.example.com:8443/
					  `), "2")
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().ConfigMaps().Informer(), "2")

					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					loadBalancer, err = kubeAPIClient.CoreV1().Services(installedInNamespace).Get(context.Background(), generatedLoadBalancerServiceName, metav1.GetOptions{})
					r.Nil(loadBalancer)
					r.EqualError(err, "services \"some-service-resource-name\" not found")
				})
			})
		})

		when("there is an error creating the load balancer", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("worker")
				startInformersAndController()
				kubeAPIClient.PrependReactor("create", "services", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("error on create")
				})
			})

			it("exits with an error", func() {
				r.EqualError(controllerlib.TestSync(t, subject, *syncContext), "could not create load balancer: error on create")
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
