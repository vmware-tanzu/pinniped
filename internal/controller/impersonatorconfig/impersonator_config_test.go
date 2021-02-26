// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonatorconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeinformers "k8s.io/client-go/informers"
	corev1informers "k8s.io/client-go/informers/core/v1"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/controllerlib"
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
		const tlsSecretName = "some-secret-name"

		var r *require.Assertions
		var observableWithInformerOption *testutil.ObservableWithInformerOption
		var observableWithInitialEventOption *testutil.ObservableWithInitialEventOption
		var configMapsInformerFilter controllerlib.Filter
		var servicesInformerFilter controllerlib.Filter
		var secretsInformerFilter controllerlib.Filter

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = testutil.NewObservableWithInformerOption()
			observableWithInitialEventOption = testutil.NewObservableWithInitialEventOption()
			sharedInformerFactory := kubeinformers.NewSharedInformerFactory(nil, 0)
			configMapsInformer := sharedInformerFactory.Core().V1().ConfigMaps()
			servicesInformer := sharedInformerFactory.Core().V1().Services()
			secretsInformer := sharedInformerFactory.Core().V1().Secrets()

			_ = NewImpersonatorConfigController(
				installedInNamespace,
				configMapResourceName,
				nil,
				configMapsInformer,
				servicesInformer,
				secretsInformer,
				observableWithInformerOption.WithInformer,
				observableWithInitialEventOption.WithInitialEvent,
				generatedLoadBalancerServiceName,
				tlsSecretName,
				nil,
				nil,
				nil,
			)
			configMapsInformerFilter = observableWithInformerOption.GetFilterForInformer(configMapsInformer)
			servicesInformerFilter = observableWithInformerOption.GetFilterForInformer(servicesInformer)
			secretsInformerFilter = observableWithInformerOption.GetFilterForInformer(secretsInformer)
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

		when("watching Service objects", func() {
			var subject controllerlib.Filter
			var target, wrongNamespace, wrongName, unrelated *corev1.Service

			it.Before(func() {
				subject = servicesInformerFilter
				target = &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: generatedLoadBalancerServiceName, Namespace: installedInNamespace}}
				wrongNamespace = &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: generatedLoadBalancerServiceName, Namespace: "wrong-namespace"}}
				wrongName = &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: installedInNamespace}}
				unrelated = &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: "wrong-namespace"}}
			})

			when("the target Service changes", func() {
				it("returns true to trigger the sync method", func() {
					r.True(subject.Add(target))
					r.True(subject.Update(target, unrelated))
					r.True(subject.Update(unrelated, target))
					r.True(subject.Delete(target))
				})
			})

			when("a Service from another namespace changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(wrongNamespace))
					r.False(subject.Update(wrongNamespace, unrelated))
					r.False(subject.Update(unrelated, wrongNamespace))
					r.False(subject.Delete(wrongNamespace))
				})
			})

			when("a Service with a different name changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(wrongName))
					r.False(subject.Update(wrongName, unrelated))
					r.False(subject.Update(unrelated, wrongName))
					r.False(subject.Delete(wrongName))
				})
			})

			when("a Service with a different name and a different namespace changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(unrelated))
					r.False(subject.Update(unrelated, unrelated))
					r.False(subject.Delete(unrelated))
				})
			})
		})

		when("watching Secret objects", func() {
			var subject controllerlib.Filter
			var target, wrongNamespace, wrongName, unrelated *corev1.Secret

			it.Before(func() {
				subject = secretsInformerFilter
				target = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: tlsSecretName, Namespace: installedInNamespace}}
				wrongNamespace = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: tlsSecretName, Namespace: "wrong-namespace"}}
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
		const tlsSecretName = "some-secret-name"
		const localhostIP = "127.0.0.1"
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
			startedTLSListener, err = tls.Listen(network, "127.0.0.1:0", config) // automatically choose the port for unit tests
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

		var requireTLSServerIsRunning = func(caCrt []byte, addr string, dnsOverrides map[string]string) {
			r.Greater(startTLSListenerFuncWasCalled, 0)

			realDialer := &net.Dialer{}
			overrideDialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
				replacementAddr, hasKey := dnsOverrides[addr]
				if hasKey {
					t.Logf("DialContext replacing addr %s with %s", addr, replacementAddr)
					addr = replacementAddr
				} else if dnsOverrides != nil {
					t.Fatal("dnsOverrides was provided but not used, which was probably a mistake")
				}
				return realDialer.DialContext(ctx, network, addr)
			}

			var tr *http.Transport
			if caCrt == nil {
				tr = &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
					DialContext:     overrideDialContext,
				}
			} else {
				rootCAs := x509.NewCertPool()
				rootCAs.AppendCertsFromPEM(caCrt)

				tr = &http.Transport{
					TLSClientConfig: &tls.Config{RootCAs: rootCAs},
					DialContext:     overrideDialContext,
				}
			}
			client := &http.Client{Transport: tr}
			url := "https://" + addr
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

		var requireTLSServerIsRunningWithoutCerts = func() {
			r.Greater(startTLSListenerFuncWasCalled, 0)

			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			}

			client := &http.Client{Transport: tr}
			url := "https://" + startedTLSListener.Addr().String()
			req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
			r.NoError(err)
			_, err = client.Do(req) //nolint:bodyclose
			r.Error(err)
			r.Regexp("Get .*: remote error: tls: unrecognized name", err.Error())
		}

		var requireTLSServerIsNoLongerRunning = func() {
			r.Greater(startTLSListenerFuncWasCalled, 0)
			_, err := tls.Dial(
				startedTLSListener.Addr().Network(),
				startedTLSListener.Addr().String(),
				&tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			)
			r.Error(err)
			r.Regexp(`dial tcp .*: connect: connection refused`, err.Error())
		}

		var requireTLSServerWasNeverStarted = func() {
			r.Equal(0, startTLSListenerFuncWasCalled)
		}

		var waitForInformerCacheToSeeResourceVersion = func(informer cache.SharedIndexInformer, wantVersion string) {
			r.Eventually(func() bool {
				return informer.LastSyncResourceVersion() == wantVersion
			}, 10*time.Second, time.Millisecond)
		}

		var waitForLoadBalancerToBeDeleted = func(informer corev1informers.ServiceInformer, name string) {
			r.Eventually(func() bool {
				_, err := informer.Lister().Services(installedInNamespace).Get(name)
				return k8serrors.IsNotFound(err)
			}, 10*time.Second, time.Millisecond)
		}

		var waitForTLSCertSecretToBeDeleted = func(informer corev1informers.SecretInformer, name string) {
			r.Eventually(func() bool {
				_, err := informer.Lister().Secrets(installedInNamespace).Get(name)
				return k8serrors.IsNotFound(err)
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
				kubeInformers.Core().V1().Services(),
				kubeInformers.Core().V1().Secrets(),
				controllerlib.WithInformer,
				controllerlib.WithInitialEvent,
				generatedLoadBalancerServiceName,
				tlsSecretName,
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

		var addImpersonatorConfigMapToTracker = func(resourceName, configYAML string, client *kubernetesfake.Clientset) {
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
			r.NoError(client.Tracker().Add(impersonatorConfigMap))
		}

		var updateImpersonatorConfigMapInTracker = func(resourceName, configYAML string, client *kubernetesfake.Clientset, newResourceVersion string) {
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
			r.NoError(client.Tracker().Update(
				schema.GroupVersionResource{Version: "v1", Resource: "configmaps"},
				impersonatorConfigMap,
				installedInNamespace,
			))
		}

		var secretWithData = func(resourceName string, data map[string][]byte) *corev1.Secret {
			return &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: installedInNamespace,
					// Note that this seems to be ignored by the informer during initial creation, so actually
					// the informer will see this as resource version "". Leaving it here to express the intent
					// that the initial version is version 0.
					ResourceVersion: "0",
				},
				Data: data,
			}
		}

		var createStubTLSSecret = func(resourceName string) *corev1.Secret {
			return secretWithData(resourceName, map[string][]byte{})
		}

		var createActualTLSSecret = func(resourceName string, ip string) *corev1.Secret {
			impersonationCA, err := certauthority.New(pkix.Name{CommonName: "test CA"}, 24*time.Hour)
			r.NoError(err)
			impersonationCert, err := impersonationCA.Issue(pkix.Name{}, nil, []net.IP{net.ParseIP(ip)}, 24*time.Hour)
			r.NoError(err)
			certPEM, keyPEM, err := certauthority.ToPEM(impersonationCert)
			r.NoError(err)
			return secretWithData(resourceName, map[string][]byte{
				"ca.crt":                impersonationCA.Bundle(),
				corev1.TLSPrivateKeyKey: keyPEM,
				corev1.TLSCertKey:       certPEM,
			})
		}

		var createTLSSecretWithMultipleHostnames = func(resourceName string, ip string) *corev1.Secret {
			impersonationCA, err := certauthority.New(pkix.Name{CommonName: "test CA"}, 24*time.Hour)
			r.NoError(err)
			impersonationCert, err := impersonationCA.Issue(pkix.Name{}, []string{"foo", "bar"}, []net.IP{net.ParseIP(ip)}, 24*time.Hour)
			r.NoError(err)
			certPEM, keyPEM, err := certauthority.ToPEM(impersonationCert)
			r.NoError(err)
			return secretWithData(resourceName, map[string][]byte{
				"ca.crt":                impersonationCA.Bundle(),
				corev1.TLSPrivateKeyKey: keyPEM,
				corev1.TLSCertKey:       certPEM,
			})
		}

		var addLoadBalancerServiceToTracker = func(resourceName string, client *kubernetesfake.Clientset) {
			loadBalancerService := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: installedInNamespace,
					// Note that this seems to be ignored by the informer during initial creation, so actually
					// the informer will see this as resource version "". Leaving it here to express the intent
					// that the initial version is version 0.
					ResourceVersion: "0",
				},
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeLoadBalancer,
				},
			}
			r.NoError(client.Tracker().Add(loadBalancerService))
		}

		var updateLoadBalancerServiceInTracker = func(resourceName, lbIngressIP string, client *kubernetesfake.Clientset, newResourceVersion string) {
			loadBalancerService := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:            resourceName,
					Namespace:       installedInNamespace,
					ResourceVersion: newResourceVersion,
				},
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeLoadBalancer,
				},
				Status: corev1.ServiceStatus{
					LoadBalancer: corev1.LoadBalancerStatus{
						Ingress: []corev1.LoadBalancerIngress{
							{IP: lbIngressIP},
						},
					},
				},
			}
			r.NoError(client.Tracker().Update(
				schema.GroupVersionResource{Version: "v1", Resource: "services"},
				loadBalancerService,
				installedInNamespace,
			))
		}

		var addLoadBalancerServiceWithIngressToTracker = func(resourceName string, ingress []corev1.LoadBalancerIngress, client *kubernetesfake.Clientset) {
			loadBalancerService := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: installedInNamespace,
					// Note that this seems to be ignored by the informer during initial creation, so actually
					// the informer will see this as resource version "". Leaving it here to express the intent
					// that the initial version is version 0.
					ResourceVersion: "0",
				},
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeLoadBalancer,
				},
				Status: corev1.ServiceStatus{
					LoadBalancer: corev1.LoadBalancerStatus{
						Ingress: ingress,
					},
				},
			}
			r.NoError(client.Tracker().Add(loadBalancerService))
		}

		var deleteLoadBalancerServiceFromTracker = func(resourceName string, client *kubernetesfake.Clientset) {
			r.NoError(client.Tracker().Delete(
				schema.GroupVersionResource{Version: "v1", Resource: "services"},
				installedInNamespace,
				resourceName,
			))
		}

		var deleteTLSCertSecretFromTracker = func(resourceName string, client *kubernetesfake.Clientset) {
			r.NoError(client.Tracker().Delete(
				schema.GroupVersionResource{Version: "v1", Resource: "secrets"},
				installedInNamespace,
				resourceName,
			))
		}

		var addSecretFromCreateActionToTracker = func(action coretesting.Action, client *kubernetesfake.Clientset, resourceVersion string) {
			createdSecret := action.(coretesting.CreateAction).GetObject().(*corev1.Secret)
			createdSecret.ResourceVersion = resourceVersion
			r.NoError(client.Tracker().Add(createdSecret))
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

		var requireNodesListed = func(action coretesting.Action) {
			r.Equal(
				coretesting.NewListAction(
					schema.GroupVersionResource{Version: "v1", Resource: "nodes"},
					schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Node"},
					"",
					metav1.ListOptions{}),
				action,
			)
		}

		var requireLoadBalancerWasCreated = func(action coretesting.Action) {
			createAction := action.(coretesting.CreateAction)
			r.Equal("create", createAction.GetVerb())
			createdLoadBalancerService := createAction.GetObject().(*corev1.Service)
			r.Equal(generatedLoadBalancerServiceName, createdLoadBalancerService.Name)
			r.Equal(installedInNamespace, createdLoadBalancerService.Namespace)
			r.Equal(corev1.ServiceTypeLoadBalancer, createdLoadBalancerService.Spec.Type)
			r.Equal("app-name", createdLoadBalancerService.Spec.Selector["app"])
			r.Equal(labels, createdLoadBalancerService.Labels)
		}

		var requireLoadBalancerDeleted = func(action coretesting.Action) {
			deleteAction := action.(coretesting.DeleteAction)
			r.Equal("delete", deleteAction.GetVerb())
			r.Equal(generatedLoadBalancerServiceName, deleteAction.GetName())
			r.Equal("services", deleteAction.GetResource().Resource)
		}

		var requireTLSSecretDeleted = func(action coretesting.Action) {
			deleteAction := action.(coretesting.DeleteAction)
			r.Equal("delete", deleteAction.GetVerb())
			r.Equal(tlsSecretName, deleteAction.GetName())
			r.Equal("secrets", deleteAction.GetResource().Resource)
		}

		var requireTLSSecretWasCreated = func(action coretesting.Action) []byte {
			createAction := action.(coretesting.CreateAction)
			r.Equal("create", createAction.GetVerb())
			createdSecret := createAction.GetObject().(*corev1.Secret)
			r.Equal(tlsSecretName, createdSecret.Name)
			r.Equal(installedInNamespace, createdSecret.Namespace)
			r.Equal(corev1.SecretTypeTLS, createdSecret.Type)
			r.Equal(labels, createdSecret.Labels)
			r.Len(createdSecret.Data, 3)
			r.NotNil(createdSecret.Data["ca.crt"])
			r.NotNil(createdSecret.Data[corev1.TLSPrivateKeyKey])
			r.NotNil(createdSecret.Data[corev1.TLSCertKey])
			return createdSecret.Data["ca.crt"]
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
				addImpersonatorConfigMapToTracker("some-other-ConfigMap", "foo: bar", kubeInformerClient)
			})

			when("there are visible control plane nodes", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("control-plane")
				})

				it("does not start the impersonator or load balancer", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					requireTLSServerWasNeverStarted()
					r.Len(kubeAPIClient.Actions(), 1)
					requireNodesListed(kubeAPIClient.Actions()[0])
				})
			})

			when("there are visible control plane nodes and a loadbalancer and a tls Secret", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("control-plane")
					addLoadBalancerServiceToTracker(generatedLoadBalancerServiceName, kubeInformerClient)
					addLoadBalancerServiceToTracker(generatedLoadBalancerServiceName, kubeAPIClient)
					tlsSecret := createStubTLSSecret(tlsSecretName)
					r.NoError(kubeAPIClient.Tracker().Add(tlsSecret))
					r.NoError(kubeInformerClient.Tracker().Add(tlsSecret))
				})

				it("does not start the impersonator, deletes the loadbalancer, deletes the Secret", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					requireTLSServerWasNeverStarted()
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireLoadBalancerDeleted(kubeAPIClient.Actions()[1])
					requireTLSSecretDeleted(kubeAPIClient.Actions()[2])
				})
			})

			when("there are not visible control plane nodes", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker")
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				})

				it("starts the impersonator without tls certs", func() {
					requireTLSServerIsRunningWithoutCerts()
				})

				it("starts the load balancer automatically", func() {
					r.Len(kubeAPIClient.Actions(), 2)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
				})
			})

			when("there are not visible control plane nodes and a load balancer already exists without an IP", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker")
					addLoadBalancerServiceToTracker(generatedLoadBalancerServiceName, kubeInformerClient)
					addLoadBalancerServiceToTracker(generatedLoadBalancerServiceName, kubeAPIClient)
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				})

				it("starts the impersonator without tls certs", func() {
					requireTLSServerIsRunningWithoutCerts()
				})

				it("does not start the load balancer automatically", func() {
					r.Len(kubeAPIClient.Actions(), 1)
					requireNodesListed(kubeAPIClient.Actions()[0])
				})
			})

			when("there are not visible control plane nodes and a load balancer already exists with empty ingress", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker")
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "", Hostname: ""}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "", Hostname: ""}}, kubeAPIClient)
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				})

				it("starts the impersonator without tls certs", func() {
					requireTLSServerIsRunningWithoutCerts()
				})

				it("does not start the load balancer automatically", func() {
					r.Len(kubeAPIClient.Actions(), 1)
					requireNodesListed(kubeAPIClient.Actions()[0])
				})
			})

			when("there are not visible control plane nodes and a load balancer already exists with invalid ip", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker")
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "not-an-ip"}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "not-an-ip"}}, kubeAPIClient)
					startInformersAndController()
					r.EqualError(controllerlib.TestSync(t, subject, *syncContext), "could not find valid IP addresses or hostnames from load balancer some-namespace/some-service-resource-name")
				})

				it("starts the impersonator without tls certs", func() {
					requireTLSServerIsRunningWithoutCerts()
				})

				it("does not start the load balancer automatically", func() {
					r.Len(kubeAPIClient.Actions(), 1)
					requireNodesListed(kubeAPIClient.Actions()[0])
				})
			})

			when("there are not visible control plane nodes and a load balancer already exists with multiple ips", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker")
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "127.0.0.123"}, {IP: "127.0.0.456"}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "127.0.0.123"}, {IP: "127.0.0.456"}}, kubeAPIClient)
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				})

				it("starts the impersonator with certs that match the first IP address", func() {
					r.Len(kubeAPIClient.Actions(), 2)
					requireNodesListed(kubeAPIClient.Actions()[0])
					ca := requireTLSSecretWasCreated(kubeAPIClient.Actions()[1])
					requireTLSServerIsRunning(ca, "127.0.0.123", map[string]string{"127.0.0.123:443": startedTLSListener.Addr().String()})
				})

				it("keeps the secret around after resync", func() {
					addSecretFromCreateActionToTracker(kubeAPIClient.Actions()[1], kubeInformerClient, "0")
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Secrets().Informer(), "0")
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					r.Len(kubeAPIClient.Actions(), 2) // nothing changed
				})
			})

			when("there are not visible control plane nodes and a load balancer already exists with multiple hostnames", func() {
				firstHostname := "fake-1.example.com"
				it.Before(func() {
					addNodeWithRoleToTracker("worker")
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{Hostname: firstHostname}, {Hostname: "fake-2.example.com"}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{Hostname: firstHostname}, {Hostname: "fake-2.example.com"}}, kubeAPIClient)
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				})

				it("starts the impersonator with certs that match the first hostname", func() {
					r.Len(kubeAPIClient.Actions(), 2)
					requireNodesListed(kubeAPIClient.Actions()[0])
					ca := requireTLSSecretWasCreated(kubeAPIClient.Actions()[1])
					requireTLSServerIsRunning(ca, firstHostname, map[string]string{firstHostname + ":443": startedTLSListener.Addr().String()})
				})

				it("keeps the secret around after resync", func() {
					addSecretFromCreateActionToTracker(kubeAPIClient.Actions()[1], kubeInformerClient, "0")
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Secrets().Informer(), "0")
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					r.Len(kubeAPIClient.Actions(), 2) // nothing changed
				})
			})

			when("there are not visible control plane nodes and a load balancer already exists with hostnames and ips", func() {
				firstHostname := "fake-1.example.com"
				it.Before(func() {
					addNodeWithRoleToTracker("worker")
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "127.0.0.254"}, {Hostname: firstHostname}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "127.0.0.254"}, {Hostname: firstHostname}}, kubeAPIClient)
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				})

				it("starts the impersonator with certs that match the first hostname", func() {
					r.Len(kubeAPIClient.Actions(), 2)
					requireNodesListed(kubeAPIClient.Actions()[0])
					ca := requireTLSSecretWasCreated(kubeAPIClient.Actions()[1])
					requireTLSServerIsRunning(ca, firstHostname, map[string]string{firstHostname + ":443": startedTLSListener.Addr().String()})
				})

				it("keeps the secret around after resync", func() {
					addSecretFromCreateActionToTracker(kubeAPIClient.Actions()[1], kubeInformerClient, "0")
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Secrets().Informer(), "0")
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					r.Len(kubeAPIClient.Actions(), 2) // nothing changed
				})
			})

			when("there are not visible control plane nodes, a secret exists with multiple hostnames and an IP", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker")
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeAPIClient)
					tlsSecret := createTLSSecretWithMultipleHostnames(tlsSecretName, localhostIP)
					r.NoError(kubeAPIClient.Tracker().Add(tlsSecret))
					r.NoError(kubeInformerClient.Tracker().Add(tlsSecret))
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				})

				it("deletes and recreates the secret to match the IP in the load balancer without the extra hostnames", func() {
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireTLSSecretDeleted(kubeAPIClient.Actions()[1])
					ca := requireTLSSecretWasCreated(kubeAPIClient.Actions()[2])
					requireTLSServerIsRunning(ca, startedTLSListener.Addr().String(), nil)
				})
			})

			when("the cert's name needs to change but there is an error while deleting the tls Secret", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker")
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "127.0.0.42"}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "127.0.0.42"}}, kubeAPIClient)
					tlsSecret := createActualTLSSecret(tlsSecretName, localhostIP)
					r.NoError(kubeAPIClient.Tracker().Add(tlsSecret))
					r.NoError(kubeInformerClient.Tracker().Add(tlsSecret))
					kubeAPIClient.PrependReactor("delete", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("error on delete")
					})
				})

				it("returns an error and runs the proxy without certs", func() {
					startInformersAndController()
					r.Error(controllerlib.TestSync(t, subject, *syncContext), "error on delete")
					r.Len(kubeAPIClient.Actions(), 2)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireTLSSecretDeleted(kubeAPIClient.Actions()[1])
					requireTLSServerIsRunningWithoutCerts()
				})
			})

			when("the cert's name might need to change but there is an error while determining the new name", func() {
				var ca []byte
				it.Before(func() {
					addNodeWithRoleToTracker("worker")
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeAPIClient)
					tlsSecret := createActualTLSSecret(tlsSecretName, localhostIP)
					ca = tlsSecret.Data["ca.crt"]
					r.NoError(kubeAPIClient.Tracker().Add(tlsSecret))
					r.NoError(kubeInformerClient.Tracker().Add(tlsSecret))
				})

				it("returns an error and keeps running the proxy with the old cert", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					r.Len(kubeAPIClient.Actions(), 1)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireTLSServerIsRunning(ca, startedTLSListener.Addr().String(), nil)

					updateLoadBalancerServiceInTracker(generatedLoadBalancerServiceName, "not-an-ip", kubeInformerClient, "1")
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Services().Informer(), "1")

					r.EqualError(controllerlib.TestSync(t, subject, *syncContext),
						"could not find valid IP addresses or hostnames from load balancer some-namespace/some-service-resource-name")
					r.Len(kubeAPIClient.Actions(), 1) // no new actions
					requireTLSServerIsRunning(ca, startedTLSListener.Addr().String(), nil)
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
				r.Len(kubeAPIClient.Actions(), 2)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
				requireTLSServerIsRunningWithoutCerts()

				// update manually because the kubeAPIClient isn't connected to the informer in the tests
				addLoadBalancerServiceToTracker(generatedLoadBalancerServiceName, kubeInformerClient)
				waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Services().Informer(), "0")

				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				r.Equal(1, startTLSListenerFuncWasCalled) // wasn't started a second time
				requireTLSServerIsRunningWithoutCerts()   // still running
				r.Len(kubeAPIClient.Actions(), 2)         // no new API calls
			})

			it("creates certs from the ip address listed on the load balancer", func() {
				startInformersAndController()
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				r.Len(kubeAPIClient.Actions(), 2)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
				requireTLSServerIsRunningWithoutCerts()

				// update manually because the kubeAPIClient isn't connected to the informer in the tests
				addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformerClient)
				waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Services().Informer(), "0")

				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				r.Equal(1, startTLSListenerFuncWasCalled) // wasn't started a second time
				r.Len(kubeAPIClient.Actions(), 3)
				ca := requireTLSSecretWasCreated(kubeAPIClient.Actions()[2])
				requireTLSServerIsRunning(ca, startedTLSListener.Addr().String(), nil) // running with certs now

				// update manually because the kubeAPIClient isn't connected to the informer in the tests
				addSecretFromCreateActionToTracker(kubeAPIClient.Actions()[2], kubeInformerClient, "1")
				waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Secrets().Informer(), "1")

				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				r.Equal(1, startTLSListenerFuncWasCalled)                              // wasn't started a third time
				r.Len(kubeAPIClient.Actions(), 3)                                      // no more actions
				requireTLSServerIsRunning(ca, startedTLSListener.Addr().String(), nil) // still running
			})

			it("creates certs from the hostname listed on the load balancer", func() {
				hostname := "fake.example.com"
				startInformersAndController()
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				r.Len(kubeAPIClient.Actions(), 2)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
				requireTLSServerIsRunningWithoutCerts()

				// update manually because the kubeAPIClient isn't connected to the informer in the tests
				addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP, Hostname: hostname}}, kubeInformerClient)
				waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Services().Informer(), "0")

				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				r.Equal(1, startTLSListenerFuncWasCalled) // wasn't started a second time
				r.Len(kubeAPIClient.Actions(), 3)
				ca := requireTLSSecretWasCreated(kubeAPIClient.Actions()[2])
				requireTLSServerIsRunning(ca, hostname, map[string]string{hostname + ":443": startedTLSListener.Addr().String()}) // running with certs now

				// update manually because the kubeAPIClient isn't connected to the informer in the tests
				addSecretFromCreateActionToTracker(kubeAPIClient.Actions()[2], kubeInformerClient, "1")
				waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Secrets().Informer(), "1")

				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				r.Equal(1, startTLSListenerFuncWasCalled)                                                                         // wasn't started a third time
				r.Len(kubeAPIClient.Actions(), 3)                                                                                 // no more actions
				requireTLSServerIsRunning(ca, hostname, map[string]string{hostname + ":443": startedTLSListener.Addr().String()}) // still running
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
				addImpersonatorConfigMapToTracker(configMapResourceName, "not yaml", kubeInformerClient)
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
					addImpersonatorConfigMapToTracker(configMapResourceName, "{mode: auto, endpoint: 127.0.0.1}", kubeInformerClient)
				})

				when("there are visible control plane nodes", func() {
					it.Before(func() {
						addNodeWithRoleToTracker("control-plane")
					})

					it("does not start the impersonator", func() {
						startInformersAndController()
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))
						requireTLSServerWasNeverStarted()
						requireNodesListed(kubeAPIClient.Actions()[0])
						r.Len(kubeAPIClient.Actions(), 1)
					})
				})

				when("there are not visible control plane nodes", func() {
					it.Before(func() {
						addNodeWithRoleToTracker("worker")
					})

					it("starts the impersonator according to the settings in the ConfigMap", func() {
						startInformersAndController()
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))
						r.Len(kubeAPIClient.Actions(), 2)
						requireNodesListed(kubeAPIClient.Actions()[0])
						ca := requireTLSSecretWasCreated(kubeAPIClient.Actions()[1])
						requireTLSServerIsRunning(ca, startedTLSListener.Addr().String(), nil)
					})
				})
			})

			when("the configuration is disabled mode", func() {
				it.Before(func() {
					addImpersonatorConfigMapToTracker(configMapResourceName, "mode: disabled", kubeInformerClient)
					addNodeWithRoleToTracker("worker")
				})

				it("does not start the impersonator", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					requireTLSServerWasNeverStarted()
					requireNodesListed(kubeAPIClient.Actions()[0])
					r.Len(kubeAPIClient.Actions(), 1)
				})
			})

			when("the configuration is enabled mode", func() {
				when("no load balancer", func() {
					it.Before(func() {
						addImpersonatorConfigMapToTracker(configMapResourceName, "mode: enabled", kubeInformerClient)
						addNodeWithRoleToTracker("control-plane")
					})

					it("starts the impersonator", func() {
						startInformersAndController()
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))
						requireTLSServerIsRunningWithoutCerts()
					})

					it("returns an error when the tls listener fails to start", func() {
						startTLSListenerFuncError = errors.New("tls error")
						startInformersAndController()
						r.EqualError(controllerlib.TestSync(t, subject, *syncContext), "tls error")
					})

					it("starts the load balancer", func() {
						startInformersAndController()
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))
						r.Len(kubeAPIClient.Actions(), 2)
						requireNodesListed(kubeAPIClient.Actions()[0])
						requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
					})
				})

				when("a loadbalancer already exists", func() {
					it.Before(func() {
						addImpersonatorConfigMapToTracker(configMapResourceName, "mode: enabled", kubeInformerClient)
						addNodeWithRoleToTracker("worker")
						addLoadBalancerServiceToTracker(generatedLoadBalancerServiceName, kubeInformerClient)
						addLoadBalancerServiceToTracker(generatedLoadBalancerServiceName, kubeAPIClient)
					})

					it("starts the impersonator", func() {
						startInformersAndController()
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))
						requireTLSServerIsRunningWithoutCerts()
					})

					it("returns an error when the tls listener fails to start", func() {
						startTLSListenerFuncError = errors.New("tls error")
						startInformersAndController()
						r.EqualError(controllerlib.TestSync(t, subject, *syncContext), "tls error")
					})

					it("does not start the load balancer", func() {
						startInformersAndController()
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))
						r.Len(kubeAPIClient.Actions(), 1)
						requireNodesListed(kubeAPIClient.Actions()[0])
					})
				})

				when("a load balancer and a secret already exists", func() {
					var ca []byte
					it.Before(func() {
						addImpersonatorConfigMapToTracker(configMapResourceName, "mode: enabled", kubeInformerClient)
						addNodeWithRoleToTracker("worker")
						tlsSecret := createActualTLSSecret(tlsSecretName, localhostIP)
						ca = tlsSecret.Data["ca.crt"]
						r.NoError(kubeAPIClient.Tracker().Add(tlsSecret))
						r.NoError(kubeInformerClient.Tracker().Add(tlsSecret))
						addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformerClient)
						addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeAPIClient)
					})

					it("starts the impersonator with the existing tls certs, does not start loadbalancer or make tls secret", func() {
						startInformersAndController()
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))
						r.Len(kubeAPIClient.Actions(), 1)
						requireNodesListed(kubeAPIClient.Actions()[0])
						requireTLSServerIsRunning(ca, startedTLSListener.Addr().String(), nil)
					})
				})

				when("we have a hostname specified for the endpoint", func() {
					const fakeHostname = "fake.example.com"
					it.Before(func() {
						configMapYAML := fmt.Sprintf("{mode: enabled, endpoint: %s}", fakeHostname)
						addImpersonatorConfigMapToTracker(configMapResourceName, configMapYAML, kubeInformerClient)
						addNodeWithRoleToTracker("worker")
					})

					it("starts the impersonator, generates a valid cert for the hostname", func() {
						startInformersAndController()
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))
						r.Len(kubeAPIClient.Actions(), 2)
						requireNodesListed(kubeAPIClient.Actions()[0])
						ca := requireTLSSecretWasCreated(kubeAPIClient.Actions()[1])
						// Check that the server is running and that TLS certs that are being served are are for fakeHostname.
						requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + ":443": startedTLSListener.Addr().String()})
					})
				})

				when("switching from ip address endpoint to hostname endpoint and back to ip address", func() {
					const fakeHostname = "fake.example.com"
					const fakeIP = "127.0.0.42"
					var hostnameYAML = fmt.Sprintf("{mode: enabled, endpoint: %s}", fakeHostname)
					var ipAddressYAML = fmt.Sprintf("{mode: enabled, endpoint: %s}", fakeIP)
					it.Before(func() {
						addImpersonatorConfigMapToTracker(configMapResourceName, ipAddressYAML, kubeInformerClient)
						addNodeWithRoleToTracker("worker")
					})

					it("regenerates the cert for the hostname, then regenerates it for the IP again", func() {
						startInformersAndController()
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))
						r.Len(kubeAPIClient.Actions(), 2)
						requireNodesListed(kubeAPIClient.Actions()[0])
						ca := requireTLSSecretWasCreated(kubeAPIClient.Actions()[1])
						// Check that the server is running and that TLS certs that are being served are are for fakeIP.
						requireTLSServerIsRunning(ca, fakeIP, map[string]string{fakeIP + ":443": startedTLSListener.Addr().String()})

						// update manually because the kubeAPIClient isn't connected to the informer in the tests
						addSecretFromCreateActionToTracker(kubeAPIClient.Actions()[1], kubeInformerClient, "1")
						waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Secrets().Informer(), "1")

						// Switch the endpoint config to a hostname.
						updateImpersonatorConfigMapInTracker(configMapResourceName, hostnameYAML, kubeInformerClient, "1")
						waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().ConfigMaps().Informer(), "1")

						r.NoError(controllerlib.TestSync(t, subject, *syncContext))
						r.Len(kubeAPIClient.Actions(), 4)
						requireTLSSecretDeleted(kubeAPIClient.Actions()[2])
						ca = requireTLSSecretWasCreated(kubeAPIClient.Actions()[3])
						// Check that the server is running and that TLS certs that are being served are are for fakeHostname.
						requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + ":443": startedTLSListener.Addr().String()})

						// update manually because the kubeAPIClient isn't connected to the informer in the tests
						deleteTLSCertSecretFromTracker(tlsSecretName, kubeInformerClient)
						addSecretFromCreateActionToTracker(kubeAPIClient.Actions()[3], kubeInformerClient, "2")
						waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Secrets().Informer(), "2")

						// Switch the endpoint config back to an IP.
						updateImpersonatorConfigMapInTracker(configMapResourceName, ipAddressYAML, kubeInformerClient, "2")
						waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().ConfigMaps().Informer(), "2")

						r.NoError(controllerlib.TestSync(t, subject, *syncContext))
						r.Len(kubeAPIClient.Actions(), 6)
						requireTLSSecretDeleted(kubeAPIClient.Actions()[4])
						ca = requireTLSSecretWasCreated(kubeAPIClient.Actions()[5])
						// Check that the server is running and that TLS certs that are being served are are for fakeIP.
						requireTLSServerIsRunning(ca, fakeIP, map[string]string{fakeIP + ":443": startedTLSListener.Addr().String()})
					})
				})
			})

			when("the configuration switches from enabled to disabled mode", func() {
				it.Before(func() {
					addImpersonatorConfigMapToTracker(configMapResourceName, "mode: enabled", kubeInformerClient)
					addNodeWithRoleToTracker("worker")
				})

				it("starts the impersonator and loadbalancer, then shuts it down, then starts it again", func() {
					startInformersAndController()

					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 2)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])

					// update manually because the kubeAPIClient isn't connected to the informer in the tests
					addLoadBalancerServiceToTracker(generatedLoadBalancerServiceName, kubeInformerClient)
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Services().Informer(), "0")

					updateImpersonatorConfigMapInTracker(configMapResourceName, "mode: disabled", kubeInformerClient, "1")
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().ConfigMaps().Informer(), "1")

					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					requireTLSServerIsNoLongerRunning()
					r.Len(kubeAPIClient.Actions(), 3)
					requireLoadBalancerDeleted(kubeAPIClient.Actions()[2])

					deleteLoadBalancerServiceFromTracker(generatedLoadBalancerServiceName, kubeInformerClient)
					waitForLoadBalancerToBeDeleted(kubeInformers.Core().V1().Services(), generatedLoadBalancerServiceName)

					updateImpersonatorConfigMapInTracker(configMapResourceName, "mode: enabled", kubeInformerClient, "2")
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().ConfigMaps().Informer(), "2")

					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 4)
					requireLoadBalancerWasCreated(kubeAPIClient.Actions()[3])
				})

				when("there is an error while shutting down the server", func() {
					it.Before(func() {
						startTLSListenerUponCloseError = errors.New("fake server close error")
					})

					it("returns the error from the sync function", func() {
						startInformersAndController()
						r.NoError(controllerlib.TestSync(t, subject, *syncContext))
						requireTLSServerIsRunningWithoutCerts()

						updateImpersonatorConfigMapInTracker(configMapResourceName, "mode: disabled", kubeInformerClient, "1")
						waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().ConfigMaps().Informer(), "1")

						r.EqualError(controllerlib.TestSync(t, subject, *syncContext), "fake server close error")
						requireTLSServerIsNoLongerRunning()
					})
				})
			})

			when("the endpoint switches from specified, to not specified, to specified again", func() {
				it.Before(func() {
					addImpersonatorConfigMapToTracker(configMapResourceName, "{mode: enabled, endpoint: 127.0.0.1}", kubeInformerClient)
					addNodeWithRoleToTracker("worker")
				})

				it("doesn't create, then creates, then deletes the load balancer", func() {
					startInformersAndController()

					// Should have started in "enabled" mode with an "endpoint", so no load balancer is needed.
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					r.Len(kubeAPIClient.Actions(), 2)
					requireNodesListed(kubeAPIClient.Actions()[0])
					ca := requireTLSSecretWasCreated(kubeAPIClient.Actions()[1]) // created immediately because "endpoint" was specified
					requireTLSServerIsRunning(ca, startedTLSListener.Addr().String(), nil)

					// update manually because the kubeAPIClient isn't connected to the informer in the tests
					addSecretFromCreateActionToTracker(kubeAPIClient.Actions()[1], kubeInformerClient, "1")
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Secrets().Informer(), "1")

					// Switch to "enabled" mode without an "endpoint", so a load balancer is needed now.
					updateImpersonatorConfigMapInTracker(configMapResourceName, "mode: enabled", kubeInformerClient, "1")
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().ConfigMaps().Informer(), "1")

					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					r.Len(kubeAPIClient.Actions(), 4)
					requireLoadBalancerWasCreated(kubeAPIClient.Actions()[2])
					requireTLSSecretDeleted(kubeAPIClient.Actions()[3]) // the Secret was deleted because it contained a cert with the wrong IP
					requireTLSServerIsRunningWithoutCerts()

					// update manually because the kubeAPIClient isn't connected to the informer in the tests
					addLoadBalancerServiceToTracker(generatedLoadBalancerServiceName, kubeInformerClient)
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Services().Informer(), "0")
					deleteTLSCertSecretFromTracker(tlsSecretName, kubeInformerClient)
					waitForTLSCertSecretToBeDeleted(kubeInformers.Core().V1().Secrets(), tlsSecretName)

					// The controller should be waiting for the load balancer's ingress to become available.
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					r.Len(kubeAPIClient.Actions(), 4) // no new actions while it is waiting for the load balancer's ingress
					requireTLSServerIsRunningWithoutCerts()

					// Update the ingress of the LB in the informer's client and run Sync again.
					fakeIP := "127.0.0.123"
					updateLoadBalancerServiceInTracker(generatedLoadBalancerServiceName, fakeIP, kubeInformerClient, "1")
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Services().Informer(), "1")
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					r.Len(kubeAPIClient.Actions(), 5)
					ca = requireTLSSecretWasCreated(kubeAPIClient.Actions()[4]) // created because the LB ingress became available
					// Check that the server is running and that TLS certs that are being served are are for fakeIP.
					requireTLSServerIsRunning(ca, fakeIP, map[string]string{fakeIP + ":443": startedTLSListener.Addr().String()})

					// update manually because the kubeAPIClient isn't connected to the informer in the tests
					addSecretFromCreateActionToTracker(kubeAPIClient.Actions()[4], kubeInformerClient, "2")
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().Secrets().Informer(), "2")

					// Now switch back to having the "endpoint" specified, so the load balancer is not needed anymore.
					updateImpersonatorConfigMapInTracker(configMapResourceName, "{mode: enabled, endpoint: 127.0.0.1}", kubeInformerClient, "2")
					waitForInformerCacheToSeeResourceVersion(kubeInformers.Core().V1().ConfigMaps().Informer(), "2")

					r.NoError(controllerlib.TestSync(t, subject, *syncContext))
					r.Len(kubeAPIClient.Actions(), 8)
					requireLoadBalancerDeleted(kubeAPIClient.Actions()[5])
					requireTLSSecretDeleted(kubeAPIClient.Actions()[6])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[7]) // recreated because the endpoint was updated
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

		when("there is an error creating the tls secret", func() {
			it.Before(func() {
				addImpersonatorConfigMapToTracker(configMapResourceName, "{mode: enabled, endpoint: example.com}", kubeInformerClient)
				addNodeWithRoleToTracker("control-plane")
				kubeAPIClient.PrependReactor("create", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("error on create")
				})
			})

			it("starts the impersonator without certs and returns an error", func() {
				startInformersAndController()
				r.EqualError(controllerlib.TestSync(t, subject, *syncContext), "error on create")
				requireTLSServerIsRunningWithoutCerts()
				r.Len(kubeAPIClient.Actions(), 2)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[1])
			})
		})

		when("there is an error deleting the tls secret", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("control-plane")
				addLoadBalancerServiceToTracker(generatedLoadBalancerServiceName, kubeInformerClient)
				addLoadBalancerServiceToTracker(generatedLoadBalancerServiceName, kubeAPIClient)
				tlsSecret := createStubTLSSecret(tlsSecretName)
				r.NoError(kubeAPIClient.Tracker().Add(tlsSecret))
				r.NoError(kubeInformerClient.Tracker().Add(tlsSecret))
				startInformersAndController()
				kubeAPIClient.PrependReactor("delete", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("error on delete")
				})
			})

			it("does not start the impersonator, deletes the loadbalancer, returns an error", func() {
				r.EqualError(controllerlib.TestSync(t, subject, *syncContext), "error on delete")
				requireTLSServerWasNeverStarted()
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireLoadBalancerDeleted(kubeAPIClient.Actions()[1])
				requireTLSSecretDeleted(kubeAPIClient.Actions()[2])
			})
		})

		when("the PEM formatted data in the Secret is not a valid cert", func() {
			it.Before(func() {
				addImpersonatorConfigMapToTracker(configMapResourceName, "{mode: enabled, endpoint: 127.0.0.1}", kubeInformerClient)
				addNodeWithRoleToTracker("worker")
				tlsSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      tlsSecretName,
						Namespace: installedInNamespace,
					},
					Data: map[string][]byte{
						// "aGVsbG8gd29ybGQK" is "hello world" base64 encoded
						corev1.TLSCertKey: []byte("-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQK\n-----END CERTIFICATE-----\n"),
					},
				}
				r.NoError(kubeAPIClient.Tracker().Add(tlsSecret))
				r.NoError(kubeInformerClient.Tracker().Add(tlsSecret))
			})

			it("deletes the invalid certs, creates new certs, and starts the impersonator", func() {
				startInformersAndController()
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireTLSSecretDeleted(kubeAPIClient.Actions()[1]) // deleted the bad cert
				ca := requireTLSSecretWasCreated(kubeAPIClient.Actions()[2])
				requireTLSServerIsRunning(ca, startedTLSListener.Addr().String(), nil)
			})

			when("there is an error while the invalid cert is being deleted", func() {
				it.Before(func() {
					kubeAPIClient.PrependReactor("delete", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("error on delete")
					})
				})

				it("tries to delete the invalid cert, starts the impersonator without certs, and returns an error", func() {
					startInformersAndController()
					r.EqualError(controllerlib.TestSync(t, subject, *syncContext), "PEM data represented an invalid cert, but got error while deleting it: error on delete")
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 2)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireTLSSecretDeleted(kubeAPIClient.Actions()[1]) // tried deleted the bad cert, which failed
					requireTLSServerIsRunningWithoutCerts()
				})
			})
		})

		when("a tls secret already exists but it is not valid", func() {
			it.Before(func() {
				addImpersonatorConfigMapToTracker(configMapResourceName, "mode: enabled", kubeInformerClient)
				addNodeWithRoleToTracker("worker")
				tlsSecret := createStubTLSSecret(tlsSecretName) // secret exists but lacks certs
				r.NoError(kubeAPIClient.Tracker().Add(tlsSecret))
				r.NoError(kubeInformerClient.Tracker().Add(tlsSecret))
				addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformerClient)
				addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeAPIClient)
			})

			it("deletes the invalid certs, creates new certs, and starts the impersonator", func() {
				startInformersAndController()
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireTLSSecretDeleted(kubeAPIClient.Actions()[1]) // deleted the bad cert
				ca := requireTLSSecretWasCreated(kubeAPIClient.Actions()[2])
				requireTLSServerIsRunning(ca, startedTLSListener.Addr().String(), nil)
			})

			when("there is an error while the invalid cert is being deleted", func() {
				it.Before(func() {
					kubeAPIClient.PrependReactor("delete", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("error on delete")
					})
				})

				it("tries to delete the invalid cert, starts the impersonator without certs, and returns an error", func() {
					startInformersAndController()
					r.EqualError(controllerlib.TestSync(t, subject, *syncContext), "found missing or not PEM-encoded data in TLS Secret, but got error while deleting it: error on delete")
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 2)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireTLSSecretDeleted(kubeAPIClient.Actions()[1]) // tried deleted the bad cert, which failed
					requireTLSServerIsRunningWithoutCerts()
				})
			})
		})

		when("a tls secret already exists but the private key is not valid", func() {
			it.Before(func() {
				addImpersonatorConfigMapToTracker(configMapResourceName, "mode: enabled", kubeInformerClient)
				addNodeWithRoleToTracker("worker")
				tlsSecret := createActualTLSSecret(tlsSecretName, localhostIP)
				tlsSecret.Data["tls.key"] = nil
				r.NoError(kubeAPIClient.Tracker().Add(tlsSecret))
				r.NoError(kubeInformerClient.Tracker().Add(tlsSecret))
				addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformerClient)
				addLoadBalancerServiceWithIngressToTracker(generatedLoadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeAPIClient)
			})

			it("deletes the invalid certs, creates new certs, and starts the impersonator", func() {
				startInformersAndController()
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireTLSSecretDeleted(kubeAPIClient.Actions()[1]) // deleted the bad cert
				ca := requireTLSSecretWasCreated(kubeAPIClient.Actions()[2])
				requireTLSServerIsRunning(ca, startedTLSListener.Addr().String(), nil)
			})

			when("there is an error while the invalid cert is being deleted", func() {
				it.Before(func() {
					kubeAPIClient.PrependReactor("delete", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("error on delete")
					})
				})

				it("tries to delete the invalid cert, starts the impersonator without certs, and returns an error", func() {
					startInformersAndController()
					r.EqualError(controllerlib.TestSync(t, subject, *syncContext), "cert had an invalid private key, but got error while deleting it: error on delete")
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 2)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireTLSSecretDeleted(kubeAPIClient.Actions()[1]) // tried deleted the bad cert, which failed
					requireTLSServerIsRunningWithoutCerts()
				})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
