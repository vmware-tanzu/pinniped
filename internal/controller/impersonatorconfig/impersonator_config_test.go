// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonatorconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/clock"
	kubeinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"

	"go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/kubeclient"
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
		const tlsSecretName = "some-tls-secret-name" //nolint:gosec // this is not a credential
		const caSecretName = "some-ca-secret-name"

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
				"",
				nil,
				nil,
				configMapsInformer,
				servicesInformer,
				secretsInformer,
				observableWithInformerOption.WithInformer,
				observableWithInitialEventOption.WithInitialEvent,
				generatedLoadBalancerServiceName,
				tlsSecretName,
				caSecretName,
				nil,
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
			var target1, target2, wrongNamespace1, wrongNamespace2, wrongName, unrelated *corev1.Secret

			it.Before(func() {
				subject = secretsInformerFilter
				target1 = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: tlsSecretName, Namespace: installedInNamespace}}
				target2 = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: caSecretName, Namespace: installedInNamespace}}
				wrongNamespace1 = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: tlsSecretName, Namespace: "wrong-namespace"}}
				wrongNamespace2 = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: caSecretName, Namespace: "wrong-namespace"}}
				wrongName = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: installedInNamespace}}
				unrelated = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: "wrong-namespace"}}
			})

			when("one of the target Secrets changes", func() {
				it("returns true to trigger the sync method", func() {
					r.True(subject.Add(target1))
					r.True(subject.Update(target1, unrelated))
					r.True(subject.Update(unrelated, target1))
					r.True(subject.Delete(target1))
					r.True(subject.Add(target2))
					r.True(subject.Update(target2, unrelated))
					r.True(subject.Update(unrelated, target2))
					r.True(subject.Delete(target2))
				})
			})

			when("a Secret from another namespace changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(wrongNamespace1))
					r.False(subject.Update(wrongNamespace1, unrelated))
					r.False(subject.Update(unrelated, wrongNamespace1))
					r.False(subject.Delete(wrongNamespace1))
					r.False(subject.Add(wrongNamespace2))
					r.False(subject.Update(wrongNamespace2, unrelated))
					r.False(subject.Update(unrelated, wrongNamespace2))
					r.False(subject.Delete(wrongNamespace2))
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
		const credentialIssuerResourceName = "some-credential-issuer-resource-name"
		const loadBalancerServiceName = "some-service-resource-name"
		const tlsSecretName = "some-tls-secret-name" //nolint:gosec // this is not a credential
		const caSecretName = "some-ca-secret-name"
		const localhostIP = "127.0.0.1"
		const httpsPort = ":443"
		const fakeServerResponseBody = "hello, world!"
		var labels = map[string]string{"app": "app-name", "other-key": "other-value"}

		var r *require.Assertions

		var subject controllerlib.Controller
		var kubeAPIClient *kubernetesfake.Clientset
		var pinnipedAPIClient *pinnipedfake.Clientset
		var kubeInformerClient *kubernetesfake.Clientset
		var kubeInformers kubeinformers.SharedInformerFactory
		var cancelContext context.Context
		var cancelContextCancelFunc context.CancelFunc
		var syncContext *controllerlib.Context
		var startTLSListenerFuncWasCalled int
		var startTLSListenerFuncError error
		var startTLSListenerUponCloseError error
		var httpHandlerFactoryFuncError error
		var startedTLSListener net.Listener
		var frozenNow time.Time

		var startTLSListenerFunc = func(network, listenAddress string, config *tls.Config) (net.Listener, error) {
			startTLSListenerFuncWasCalled++
			r.Equal("tcp", network)
			r.Equal(":8444", listenAddress)
			r.Equal(uint16(tls.VersionTLS12), config.MinVersion)
			if startTLSListenerFuncError != nil {
				return nil, startTLSListenerFuncError
			}
			var err error
			startedTLSListener, err = tls.Listen(network, localhostIP+":0", config) // automatically choose the port for unit tests
			r.NoError(err)
			return &tlsListenerWrapper{listener: startedTLSListener, closeError: startTLSListenerUponCloseError}, nil
		}

		var testServerAddr = func() string {
			return startedTLSListener.Addr().String()
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

			var resp *http.Response
			assert.Eventually(t, func() bool {
				resp, err = client.Do(req.Clone(context.Background())) //nolint:bodyclose
				return err == nil
			}, 20*time.Second, 50*time.Millisecond)
			r.NoError(err)

			r.Equal(http.StatusOK, resp.StatusCode)
			body, err := ioutil.ReadAll(resp.Body)
			r.NoError(resp.Body.Close())
			r.NoError(err)
			r.Equal(fakeServerResponseBody, string(body))
		}

		var requireTLSServerIsRunningWithoutCerts = func() {
			r.Greater(startTLSListenerFuncWasCalled, 0)
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			}
			client := &http.Client{Transport: tr}
			url := "https://" + testServerAddr()
			req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
			r.NoError(err)

			expectedErrorRegex := "Get .*: remote error: tls: unrecognized name"
			expectedErrorRegexCompiled, err := regexp.Compile(expectedErrorRegex)
			r.NoError(err)
			assert.Eventually(t, func() bool {
				_, err = client.Do(req.Clone(context.Background())) //nolint:bodyclose
				return err != nil && expectedErrorRegexCompiled.MatchString(err.Error())
			}, 20*time.Second, 50*time.Millisecond)
			r.Error(err)
			r.Regexp(expectedErrorRegex, err.Error())
		}

		var requireTLSServerIsNoLongerRunning = func() {
			r.Greater(startTLSListenerFuncWasCalled, 0)
			var err error
			expectedErrorRegex := "dial tcp .*: connect: connection refused"
			expectedErrorRegexCompiled, err := regexp.Compile(expectedErrorRegex)
			r.NoError(err)
			assert.Eventually(t, func() bool {
				_, err = tls.Dial(
					startedTLSListener.Addr().Network(),
					testServerAddr(),
					&tls.Config{InsecureSkipVerify: true}, //nolint:gosec
				)
				return err != nil && expectedErrorRegexCompiled.MatchString(err.Error())
			}, 20*time.Second, 50*time.Millisecond)
			r.Error(err)
			r.Regexp(expectedErrorRegex, err.Error())
		}

		var requireTLSServerWasNeverStarted = func() {
			r.Equal(0, startTLSListenerFuncWasCalled)
		}

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewImpersonatorConfigController(
				installedInNamespace,
				configMapResourceName,
				credentialIssuerResourceName,
				kubeAPIClient,
				pinnipedAPIClient,
				kubeInformers.Core().V1().ConfigMaps(),
				kubeInformers.Core().V1().Services(),
				kubeInformers.Core().V1().Secrets(),
				controllerlib.WithInformer,
				controllerlib.WithInitialEvent,
				loadBalancerServiceName,
				tlsSecretName,
				caSecretName,
				labels,
				clock.NewFakeClock(frozenNow),
				startTLSListenerFunc,
				func() (http.Handler, error) {
					return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						_, err := fmt.Fprint(w, fakeServerResponseBody)
						r.NoError(err)
					}), httpHandlerFactoryFuncError
				},
			)

			// Set this at the last second to support calling subject.Name().
			syncContext = &controllerlib.Context{
				Context: cancelContext,
				Name:    subject.Name(),
				Key: controllerlib.Key{
					Namespace: installedInNamespace,
					Name:      configMapResourceName,
				},
			}

			// Must start informers before calling TestRunSynchronously()
			kubeInformers.Start(cancelContext.Done())
			controllerlib.TestRunSynchronously(t, subject)
		}

		var addImpersonatorConfigMapToTracker = func(resourceName, configYAML string, client *kubernetesfake.Clientset) {
			impersonatorConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: installedInNamespace,
				},
				Data: map[string]string{
					"config.yaml": configYAML,
				},
			}
			r.NoError(client.Tracker().Add(impersonatorConfigMap))
		}

		var newSecretWithData = func(resourceName string, data map[string][]byte) *corev1.Secret {
			return &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: installedInNamespace,
				},
				Data: data,
			}
		}

		var newEmptySecret = func(resourceName string) *corev1.Secret {
			return newSecretWithData(resourceName, map[string][]byte{})
		}

		var newCA = func() *certauthority.CA {
			ca, err := certauthority.New(pkix.Name{CommonName: "test CA"}, 24*time.Hour)
			r.NoError(err)
			return ca
		}

		var newCACertSecretData = func(ca *certauthority.CA) map[string][]byte {
			keyPEM, err := ca.PrivateKeyToPEM()
			r.NoError(err)
			return map[string][]byte{
				"ca.crt": ca.Bundle(),
				"ca.key": keyPEM,
			}
		}

		var newTLSCertSecretData = func(ca *certauthority.CA, dnsNames []string, ip string) map[string][]byte {
			impersonationCert, err := ca.Issue(pkix.Name{}, dnsNames, []net.IP{net.ParseIP(ip)}, 24*time.Hour)
			r.NoError(err)
			certPEM, keyPEM, err := certauthority.ToPEM(impersonationCert)
			r.NoError(err)
			return map[string][]byte{
				corev1.TLSPrivateKeyKey: keyPEM,
				corev1.TLSCertKey:       certPEM,
			}
		}

		var newActualCASecret = func(ca *certauthority.CA, resourceName string) *corev1.Secret {
			return newSecretWithData(resourceName, newCACertSecretData(ca))
		}

		var newActualTLSSecret = func(ca *certauthority.CA, resourceName string, ip string) *corev1.Secret {
			return newSecretWithData(resourceName, newTLSCertSecretData(ca, nil, ip))
		}

		var newActualTLSSecretWithMultipleHostnames = func(ca *certauthority.CA, resourceName string, ip string) *corev1.Secret {
			return newSecretWithData(resourceName, newTLSCertSecretData(ca, []string{"foo", "bar"}, ip))
		}

		var newLoadBalancerService = func(resourceName string, status corev1.ServiceStatus) *corev1.Service {
			return &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: installedInNamespace,
				},
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeLoadBalancer,
				},
				Status: status,
			}
		}

		// Anytime an object is added/updated/deleted in the informer's client *after* the informer is started, then we
		// need to wait for the informer's cache to asynchronously pick up that change from its "watch".
		// If an object is added to the informer's client *before* the informer is started, then waiting is
		// not needed because the informer's initial "list" will pick up the object.
		var waitForObjectToAppearInInformer = func(obj kubeclient.Object, informer controllerlib.InformerGetter) {
			var objFromInformer interface{}
			var exists bool
			var err error
			assert.Eventually(t, func() bool {
				objFromInformer, exists, err = informer.Informer().GetIndexer().GetByKey(installedInNamespace + "/" + obj.GetName())
				return err == nil && exists && reflect.DeepEqual(objFromInformer.(kubeclient.Object), obj)
			}, 30*time.Second, 10*time.Millisecond)
			r.NoError(err)
			r.True(exists, "this object should have existed in informer but didn't: %+v", obj)
			r.Equal(obj, objFromInformer, "was waiting for expected to be found in informer, but found actual")
		}

		// See comment for waitForObjectToAppearInInformer above.
		var waitForObjectToBeDeletedFromInformer = func(resourceName string, informer controllerlib.InformerGetter) {
			var objFromInformer interface{}
			var exists bool
			var err error
			assert.Eventually(t, func() bool {
				objFromInformer, exists, err = informer.Informer().GetIndexer().GetByKey(installedInNamespace + "/" + resourceName)
				return err == nil && !exists
			}, 30*time.Second, 10*time.Millisecond)
			r.NoError(err)
			r.False(exists, "this object should have been deleted from informer but wasn't: %s", objFromInformer)
		}

		var addObjectToInformerAndWait = func(obj kubeclient.Object, informer controllerlib.InformerGetter) {
			r.NoError(kubeInformerClient.Tracker().Add(obj))
			waitForObjectToAppearInInformer(obj, informer)
		}

		var addObjectFromCreateActionToInformerAndWait = func(action coretesting.Action, informer controllerlib.InformerGetter) {
			createdObject, ok := action.(coretesting.CreateAction).GetObject().(kubeclient.Object)
			r.True(ok, "should have been able to cast this action's object to kubeclient.Object: %v", action)
			addObjectToInformerAndWait(createdObject, informer)
		}

		var updateImpersonatorConfigMapInInformerAndWait = func(resourceName, configYAML string, informer controllerlib.InformerGetter) {
			configMapObj, err := kubeInformerClient.Tracker().Get(
				schema.GroupVersionResource{Version: "v1", Resource: "configmaps"},
				installedInNamespace,
				resourceName,
			)
			r.NoError(err)
			configMap := configMapObj.(*corev1.ConfigMap)
			configMap = configMap.DeepCopy() // don't edit the original from the tracker
			configMap.Data = map[string]string{
				"config.yaml": configYAML,
			}
			r.NoError(kubeInformerClient.Tracker().Update(
				schema.GroupVersionResource{Version: "v1", Resource: "configmaps"},
				configMap,
				installedInNamespace,
			))
			waitForObjectToAppearInInformer(configMap, informer)
		}

		var updateLoadBalancerServiceInInformerAndWait = func(resourceName string, ingresses []corev1.LoadBalancerIngress, informer controllerlib.InformerGetter) {
			serviceObj, err := kubeInformerClient.Tracker().Get(
				schema.GroupVersionResource{Version: "v1", Resource: "services"},
				installedInNamespace,
				resourceName,
			)
			r.NoError(err)
			service := serviceObj.(*corev1.Service)
			service = service.DeepCopy() // don't edit the original from the tracker
			service.Status = corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: ingresses}}
			r.NoError(kubeInformerClient.Tracker().Update(
				schema.GroupVersionResource{Version: "v1", Resource: "services"},
				service,
				installedInNamespace,
			))
			waitForObjectToAppearInInformer(service, informer)
		}

		var addLoadBalancerServiceToTracker = func(resourceName string, client *kubernetesfake.Clientset) {
			loadBalancerService := newLoadBalancerService(resourceName, corev1.ServiceStatus{})
			r.NoError(client.Tracker().Add(loadBalancerService))
		}

		var addLoadBalancerServiceWithIngressToTracker = func(resourceName string, ingress []corev1.LoadBalancerIngress, client *kubernetesfake.Clientset) {
			loadBalancerService := newLoadBalancerService(resourceName, corev1.ServiceStatus{
				LoadBalancer: corev1.LoadBalancerStatus{Ingress: ingress},
			})
			r.NoError(client.Tracker().Add(loadBalancerService))
		}

		var addSecretToTrackers = func(secret *corev1.Secret, clients ...*kubernetesfake.Clientset) {
			for _, client := range clients {
				secretCopy := secret.DeepCopy()
				r.NoError(client.Tracker().Add(secretCopy))
			}
		}

		var deleteServiceFromTracker = func(resourceName string, client *kubernetesfake.Clientset) {
			r.NoError(client.Tracker().Delete(
				schema.GroupVersionResource{Version: "v1", Resource: "services"},
				installedInNamespace,
				resourceName,
			))
		}

		var deleteSecretFromTracker = func(resourceName string, client *kubernetesfake.Clientset) {
			r.NoError(client.Tracker().Delete(
				schema.GroupVersionResource{Version: "v1", Resource: "secrets"},
				installedInNamespace,
				resourceName,
			))
		}

		var addNodeWithRoleToTracker = func(role string, client *kubernetesfake.Clientset) {
			r.NoError(client.Tracker().Add(
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

		var newSuccessStrategy = func(endpoint string, ca []byte) v1alpha1.CredentialIssuerStrategy {
			return v1alpha1.CredentialIssuerStrategy{
				Type:           v1alpha1.ImpersonationProxyStrategyType,
				Status:         v1alpha1.SuccessStrategyStatus,
				Reason:         v1alpha1.ListeningStrategyReason,
				Message:        "impersonation proxy is ready to accept client connections",
				LastUpdateTime: metav1.NewTime(frozenNow),
				Frontend: &v1alpha1.CredentialIssuerFrontend{
					Type: v1alpha1.ImpersonationProxyFrontendType,
					ImpersonationProxyInfo: &v1alpha1.ImpersonationProxyInfo{
						Endpoint:                 "https://" + endpoint,
						CertificateAuthorityData: base64.StdEncoding.EncodeToString(ca),
					},
				},
			}
		}

		var newAutoDisabledStrategy = func() v1alpha1.CredentialIssuerStrategy {
			return v1alpha1.CredentialIssuerStrategy{
				Type:           v1alpha1.ImpersonationProxyStrategyType,
				Status:         v1alpha1.ErrorStrategyStatus,
				Reason:         v1alpha1.DisabledStrategyReason,
				Message:        "automatically determined that impersonation proxy should be disabled",
				LastUpdateTime: metav1.NewTime(frozenNow),
				Frontend:       nil,
			}
		}

		var newManuallyDisabledStrategy = func() v1alpha1.CredentialIssuerStrategy {
			s := newAutoDisabledStrategy()
			s.Message = "impersonation proxy was explicitly disabled by configuration"
			return s
		}

		var newPendingStrategy = func() v1alpha1.CredentialIssuerStrategy {
			return v1alpha1.CredentialIssuerStrategy{
				Type:           v1alpha1.ImpersonationProxyStrategyType,
				Status:         v1alpha1.ErrorStrategyStatus,
				Reason:         v1alpha1.PendingStrategyReason,
				Message:        "waiting for load balancer Service to be assigned IP or hostname",
				LastUpdateTime: metav1.NewTime(frozenNow),
				Frontend:       nil,
			}
		}

		var newErrorStrategy = func(msg string) v1alpha1.CredentialIssuerStrategy {
			return v1alpha1.CredentialIssuerStrategy{
				Type:           v1alpha1.ImpersonationProxyStrategyType,
				Status:         v1alpha1.ErrorStrategyStatus,
				Reason:         v1alpha1.ErrorDuringSetupStrategyReason,
				Message:        msg,
				LastUpdateTime: metav1.NewTime(frozenNow),
				Frontend:       nil,
			}
		}

		var getCredentialIssuer = func() *v1alpha1.CredentialIssuer {
			credentialIssuerObj, err := pinnipedAPIClient.Tracker().Get(
				schema.GroupVersionResource{
					Group:    v1alpha1.SchemeGroupVersion.Group,
					Version:  v1alpha1.SchemeGroupVersion.Version,
					Resource: "credentialissuers",
				}, "", credentialIssuerResourceName,
			)
			r.NoError(err)
			credentialIssuer, ok := credentialIssuerObj.(*v1alpha1.CredentialIssuer)
			r.True(ok, "should have been able to cast this obj to CredentialIssuer: %v", credentialIssuerObj)
			return credentialIssuer
		}

		var requireCredentialIssuer = func(expectedStrategy v1alpha1.CredentialIssuerStrategy) {
			// Rather than looking at the specific API actions on pinnipedAPIClient, we just look
			// at the final result here.
			// This is because the implementation is using a helper from another package to create
			// and update the CredentialIssuer, and the specific API actions performed by that
			// implementation are pretty complex and are already tested by its own unit tests.
			// As long as we get the final result that we wanted then we are happy for the purposes
			// of this test.
			credentialIssuer := getCredentialIssuer()
			r.Equal(labels, credentialIssuer.Labels)
			r.Equal([]v1alpha1.CredentialIssuerStrategy{expectedStrategy}, credentialIssuer.Status.Strategies)
		}

		var requireLoadBalancerWasCreated = func(action coretesting.Action) {
			createAction, ok := action.(coretesting.CreateAction)
			r.True(ok, "should have been able to cast this action to CreateAction: %v", action)
			r.Equal("create", createAction.GetVerb())
			createdLoadBalancerService := createAction.GetObject().(*corev1.Service)
			r.Equal(loadBalancerServiceName, createdLoadBalancerService.Name)
			r.Equal(installedInNamespace, createdLoadBalancerService.Namespace)
			r.Equal(corev1.ServiceTypeLoadBalancer, createdLoadBalancerService.Spec.Type)
			r.Equal("app-name", createdLoadBalancerService.Spec.Selector["app"])
			r.Equal(labels, createdLoadBalancerService.Labels)
		}

		var requireLoadBalancerWasDeleted = func(action coretesting.Action) {
			deleteAction, ok := action.(coretesting.DeleteAction)
			r.True(ok, "should have been able to cast this action to DeleteAction: %v", action)
			r.Equal("delete", deleteAction.GetVerb())
			r.Equal(loadBalancerServiceName, deleteAction.GetName())
			r.Equal("services", deleteAction.GetResource().Resource)
		}

		var requireTLSSecretWasDeleted = func(action coretesting.Action) {
			deleteAction, ok := action.(coretesting.DeleteAction)
			r.True(ok, "should have been able to cast this action to DeleteAction: %v", action)
			r.Equal("delete", deleteAction.GetVerb())
			r.Equal(tlsSecretName, deleteAction.GetName())
			r.Equal("secrets", deleteAction.GetResource().Resource)
		}

		var requireCASecretWasCreated = func(action coretesting.Action) []byte {
			createAction, ok := action.(coretesting.CreateAction)
			r.True(ok, "should have been able to cast this action to CreateAction: %v", action)
			r.Equal("create", createAction.GetVerb())
			createdSecret := createAction.GetObject().(*corev1.Secret)
			r.Equal(caSecretName, createdSecret.Name)
			r.Equal(installedInNamespace, createdSecret.Namespace)
			r.Equal(corev1.SecretTypeOpaque, createdSecret.Type)
			r.Equal(labels, createdSecret.Labels)
			r.Len(createdSecret.Data, 2)
			createdCertPEM := createdSecret.Data["ca.crt"]
			createdKeyPEM := createdSecret.Data["ca.key"]
			r.NotNil(createdCertPEM)
			r.NotNil(createdKeyPEM)
			_, err := tls.X509KeyPair(createdCertPEM, createdKeyPEM)
			r.NoError(err, "key does not match cert")
			// Decode and parse the cert to check some of its fields.
			block, _ := pem.Decode(createdCertPEM)
			require.NotNil(t, block)
			caCert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			require.Equal(t, "Pinniped Impersonation Proxy CA", caCert.Subject.CommonName)
			require.WithinDuration(t, time.Now().Add(-10*time.Second), caCert.NotBefore, 10*time.Second)
			require.WithinDuration(t, time.Now().Add(100*time.Hour*24*365), caCert.NotAfter, 10*time.Second)
			return createdCertPEM
		}

		var requireTLSSecretWasCreated = func(action coretesting.Action, caCert []byte) {
			createAction, ok := action.(coretesting.CreateAction)
			r.True(ok, "should have been able to cast this action to CreateAction: %v", action)
			r.Equal("create", createAction.GetVerb())
			createdSecret := createAction.GetObject().(*corev1.Secret)
			r.Equal(tlsSecretName, createdSecret.Name)
			r.Equal(installedInNamespace, createdSecret.Namespace)
			r.Equal(corev1.SecretTypeTLS, createdSecret.Type)
			r.Equal(labels, createdSecret.Labels)
			r.Len(createdSecret.Data, 2)
			createdCertPEM := createdSecret.Data[corev1.TLSCertKey]
			createdKeyPEM := createdSecret.Data[corev1.TLSPrivateKeyKey]
			r.NotNil(createdKeyPEM)
			r.NotNil(createdCertPEM)
			validCert := testutil.ValidateCertificate(t, string(caCert), string(createdCertPEM))
			validCert.RequireMatchesPrivateKey(string(createdKeyPEM))
			validCert.RequireLifetime(time.Now().Add(-10*time.Second), time.Now().Add(100*time.Hour*24*365), 10*time.Second)
		}

		var runControllerSync = func() error {
			return controllerlib.TestSync(t, subject, *syncContext)
		}

		it.Before(func() {
			r = require.New(t)
			cancelContext, cancelContextCancelFunc = context.WithCancel(context.Background())
			kubeInformerClient = kubernetesfake.NewSimpleClientset()
			kubeInformers = kubeinformers.NewSharedInformerFactoryWithOptions(kubeInformerClient, 0,
				kubeinformers.WithNamespace(installedInNamespace),
			)
			kubeAPIClient = kubernetesfake.NewSimpleClientset()
			pinnipedAPIClient = pinnipedfake.NewSimpleClientset()
			frozenNow = time.Date(2021, time.March, 2, 7, 42, 0, 0, time.Local)
		})

		it.After(func() {
			cancelContextCancelFunc()
			closeTLSListener()
		})

		when("the ConfigMap does not yet exist in the installation namespace or it was deleted (defaults to auto mode)", func() {
			it.Before(func() {
				addImpersonatorConfigMapToTracker("some-other-unrelated-configmap", "foo: bar", kubeInformerClient)
			})

			when("there are visible control plane nodes", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("control-plane", kubeAPIClient)
				})

				it("does not start the impersonator or load balancer", func() {
					startInformersAndController()
					r.NoError(runControllerSync())
					requireTLSServerWasNeverStarted()
					r.Len(kubeAPIClient.Actions(), 1)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireCredentialIssuer(newAutoDisabledStrategy())
				})
			})

			when("there are visible control plane nodes and a loadbalancer and a tls Secret", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("control-plane", kubeAPIClient)
					addLoadBalancerServiceToTracker(loadBalancerServiceName, kubeInformerClient)
					addLoadBalancerServiceToTracker(loadBalancerServiceName, kubeAPIClient)
					addSecretToTrackers(newEmptySecret(tlsSecretName), kubeAPIClient, kubeInformerClient)
				})

				it("does not start the impersonator, deletes the loadbalancer, deletes the Secret", func() {
					startInformersAndController()
					r.NoError(runControllerSync())
					requireTLSServerWasNeverStarted()
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireLoadBalancerWasDeleted(kubeAPIClient.Actions()[1])
					requireTLSSecretWasDeleted(kubeAPIClient.Actions()[2])
					requireCredentialIssuer(newAutoDisabledStrategy())
				})
			})

			when("there are not visible control plane nodes", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					startInformersAndController()
					r.NoError(runControllerSync())
				})

				it("starts the load balancer automatically", func() {
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
					requireCASecretWasCreated(kubeAPIClient.Actions()[2])
					requireCredentialIssuer(newPendingStrategy())
				})
			})

			when("there are not visible control plane nodes and a load balancer already exists without an IP/hostname", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					addLoadBalancerServiceToTracker(loadBalancerServiceName, kubeInformerClient)
					addLoadBalancerServiceToTracker(loadBalancerServiceName, kubeAPIClient)
					startInformersAndController()
					r.NoError(runControllerSync())
				})

				it("does not start the load balancer automatically", func() {
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 2)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireCASecretWasCreated(kubeAPIClient.Actions()[1])
					requireCredentialIssuer(newPendingStrategy())
				})
			})

			when("there are not visible control plane nodes and a load balancer already exists with empty ingress", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "", Hostname: ""}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "", Hostname: ""}}, kubeAPIClient)
					startInformersAndController()
					r.NoError(runControllerSync())
				})

				it("does not start the load balancer automatically", func() {
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 2)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireCASecretWasCreated(kubeAPIClient.Actions()[1])
					requireCredentialIssuer(newPendingStrategy())
				})
			})

			when("there are not visible control plane nodes and a load balancer already exists with invalid ip", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "not-an-ip"}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "not-an-ip"}}, kubeAPIClient)
					startInformersAndController()
					r.EqualError(runControllerSync(), "could not find valid IP addresses or hostnames from load balancer some-namespace/some-service-resource-name")
				})

				it("does not start the load balancer automatically", func() {
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 1)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireCredentialIssuer(newErrorStrategy("could not find valid IP addresses or hostnames from load balancer some-namespace/some-service-resource-name"))
				})
			})

			when("there are not visible control plane nodes and a load balancer already exists with multiple ips", func() {
				const fakeIP = "127.0.0.123"
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: fakeIP}, {IP: "127.0.0.456"}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: fakeIP}, {IP: "127.0.0.456"}}, kubeAPIClient)
					startInformersAndController()
					r.NoError(runControllerSync())
				})

				it("starts the impersonator with certs that match the first IP address", func() {
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
					requireTLSServerIsRunning(ca, fakeIP, map[string]string{fakeIP + ":443": testServerAddr()})
					requireCredentialIssuer(newSuccessStrategy(fakeIP, ca))

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Secrets())
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

					// keeps the secret around after resync
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 3) // nothing changed
					requireCredentialIssuer(newSuccessStrategy(fakeIP, ca))
				})
			})

			when("there are not visible control plane nodes and a load balancer already exists with multiple hostnames", func() {
				firstHostname := "fake-1.example.com"
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{Hostname: firstHostname}, {Hostname: "fake-2.example.com"}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{Hostname: firstHostname}, {Hostname: "fake-2.example.com"}}, kubeAPIClient)
					startInformersAndController()
					r.NoError(runControllerSync())
				})

				it("starts the impersonator with certs that match the first hostname", func() {
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
					requireTLSServerIsRunning(ca, firstHostname, map[string]string{firstHostname + httpsPort: testServerAddr()})
					requireCredentialIssuer(newSuccessStrategy(firstHostname, ca))

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Secrets())
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

					// keeps the secret around after resync
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 3) // nothing changed
					requireCredentialIssuer(newSuccessStrategy(firstHostname, ca))
				})
			})

			when("there are not visible control plane nodes and a load balancer already exists with hostnames and ips", func() {
				firstHostname := "fake-1.example.com"
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "127.0.0.254"}, {Hostname: firstHostname}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "127.0.0.254"}, {Hostname: firstHostname}}, kubeAPIClient)
					startInformersAndController()
					r.NoError(runControllerSync())
				})

				it("starts the impersonator with certs that match the first hostname", func() {
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
					requireTLSServerIsRunning(ca, firstHostname, map[string]string{firstHostname + httpsPort: testServerAddr()})
					requireCredentialIssuer(newSuccessStrategy(firstHostname, ca))

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Secrets())
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

					// keeps the secret around after resync
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 3) // nothing changed
					requireCredentialIssuer(newSuccessStrategy(firstHostname, ca))
				})
			})

			when("there are not visible control plane nodes, a TLS secret exists with multiple hostnames and an IP", func() {
				var caCrt []byte
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeAPIClient)
					ca := newCA()
					caSecret := newActualCASecret(ca, caSecretName)
					caCrt = caSecret.Data["ca.crt"]
					addSecretToTrackers(caSecret, kubeAPIClient, kubeInformerClient)
					addSecretToTrackers(newActualTLSSecretWithMultipleHostnames(ca, tlsSecretName, localhostIP), kubeAPIClient, kubeInformerClient)
					startInformersAndController()
					r.NoError(runControllerSync())
				})

				it("deletes and recreates the secret to match the IP in the load balancer without the extra hostnames", func() {
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireTLSSecretWasDeleted(kubeAPIClient.Actions()[1])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], caCrt)
					requireTLSServerIsRunning(caCrt, testServerAddr(), nil)
					requireCredentialIssuer(newSuccessStrategy(localhostIP, caCrt))
				})
			})

			when("the cert's name needs to change but there is an error while deleting the tls Secret", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "127.0.0.42"}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "127.0.0.42"}}, kubeAPIClient)
					ca := newCA()
					addSecretToTrackers(newActualCASecret(ca, caSecretName), kubeAPIClient, kubeInformerClient)
					addSecretToTrackers(newActualTLSSecretWithMultipleHostnames(ca, tlsSecretName, localhostIP), kubeAPIClient, kubeInformerClient)
					kubeAPIClient.PrependReactor("delete", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("error on delete")
					})
				})

				it("returns an error and runs the proxy without certs", func() {
					startInformersAndController()
					r.Error(runControllerSync(), "error on delete")
					r.Len(kubeAPIClient.Actions(), 2)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireTLSSecretWasDeleted(kubeAPIClient.Actions()[1])
					requireTLSServerIsRunningWithoutCerts()
					requireCredentialIssuer(newErrorStrategy("error on delete"))
				})
			})

			when("the cert's name might need to change but there is an error while determining the new name", func() {
				var caCrt []byte
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeAPIClient)
					ca := newCA()
					caSecret := newActualCASecret(ca, caSecretName)
					caCrt = caSecret.Data["ca.crt"]
					addSecretToTrackers(caSecret, kubeAPIClient, kubeInformerClient)
					tlsSecret := newActualTLSSecret(ca, tlsSecretName, localhostIP)
					addSecretToTrackers(tlsSecret, kubeAPIClient, kubeInformerClient)
				})

				it("returns an error and keeps running the proxy with the old cert", func() {
					startInformersAndController()
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 1)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireTLSServerIsRunning(caCrt, testServerAddr(), nil)

					updateLoadBalancerServiceInInformerAndWait(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "not-an-ip"}}, kubeInformers.Core().V1().Services())

					errString := "could not find valid IP addresses or hostnames from load balancer some-namespace/some-service-resource-name"
					r.EqualError(runControllerSync(), errString)
					r.Len(kubeAPIClient.Actions(), 1) // no new actions
					requireTLSServerIsRunning(caCrt, testServerAddr(), nil)
					requireCredentialIssuer(newErrorStrategy(errString))
				})
			})
		})

		when("the ConfigMap is already in the installation namespace", func() {
			when("the configuration is auto mode with an endpoint", func() {
				it.Before(func() {
					configMapYAML := fmt.Sprintf("{mode: auto, endpoint: %s}", localhostIP)
					addImpersonatorConfigMapToTracker(configMapResourceName, configMapYAML, kubeInformerClient)
				})

				when("there are visible control plane nodes", func() {
					it.Before(func() {
						addNodeWithRoleToTracker("control-plane", kubeAPIClient)
					})

					it("does not start the impersonator", func() {
						startInformersAndController()
						r.NoError(runControllerSync())
						requireTLSServerWasNeverStarted()
						requireNodesListed(kubeAPIClient.Actions()[0])
						r.Len(kubeAPIClient.Actions(), 1)
						requireCredentialIssuer(newAutoDisabledStrategy())
					})
				})

				when("there are not visible control plane nodes", func() {
					it.Before(func() {
						addNodeWithRoleToTracker("worker", kubeAPIClient)
					})

					it("starts the impersonator according to the settings in the ConfigMap", func() {
						startInformersAndController()
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 3)
						requireNodesListed(kubeAPIClient.Actions()[0])
						ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
						requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
						requireTLSServerIsRunning(ca, testServerAddr(), nil)
						requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
					})
				})
			})

			when("the configuration is disabled mode", func() {
				it.Before(func() {
					addImpersonatorConfigMapToTracker(configMapResourceName, "mode: disabled", kubeInformerClient)
					addNodeWithRoleToTracker("worker", kubeAPIClient)
				})

				it("does not start the impersonator", func() {
					startInformersAndController()
					r.NoError(runControllerSync())
					requireTLSServerWasNeverStarted()
					requireNodesListed(kubeAPIClient.Actions()[0])
					r.Len(kubeAPIClient.Actions(), 1)
					requireCredentialIssuer(newManuallyDisabledStrategy())
				})
			})

			when("the configuration is enabled mode", func() {
				when("no load balancer", func() {
					it.Before(func() {
						addImpersonatorConfigMapToTracker(configMapResourceName, "mode: enabled", kubeInformerClient)
						addNodeWithRoleToTracker("control-plane", kubeAPIClient)
					})

					it("starts the impersonator and creates a load balancer", func() {
						startInformersAndController()
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 3)
						requireNodesListed(kubeAPIClient.Actions()[0])
						requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
						requireCASecretWasCreated(kubeAPIClient.Actions()[2])
						requireTLSServerIsRunningWithoutCerts()
						requireCredentialIssuer(newPendingStrategy())
					})

					it("returns an error when the tls listener fails to start", func() {
						startTLSListenerFuncError = errors.New("tls error")
						startInformersAndController()
						r.EqualError(runControllerSync(), "tls error")
						requireCredentialIssuer(newErrorStrategy("tls error"))
					})
				})

				when("a loadbalancer already exists", func() {
					it.Before(func() {
						addImpersonatorConfigMapToTracker(configMapResourceName, "mode: enabled", kubeInformerClient)
						addNodeWithRoleToTracker("worker", kubeAPIClient)
						addLoadBalancerServiceToTracker(loadBalancerServiceName, kubeInformerClient)
						addLoadBalancerServiceToTracker(loadBalancerServiceName, kubeAPIClient)
					})

					it("starts the impersonator without creating a load balancer", func() {
						startInformersAndController()
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 2)
						requireNodesListed(kubeAPIClient.Actions()[0])
						requireCASecretWasCreated(kubeAPIClient.Actions()[1])
						requireTLSServerIsRunningWithoutCerts()
						requireCredentialIssuer(newPendingStrategy())
					})

					it("returns an error when the tls listener fails to start", func() {
						startTLSListenerFuncError = errors.New("tls error")
						startInformersAndController()
						r.EqualError(runControllerSync(), "tls error")
						requireCredentialIssuer(newErrorStrategy("tls error"))
					})
				})

				when("a load balancer and a secret already exists", func() {
					var caCrt []byte
					it.Before(func() {
						addImpersonatorConfigMapToTracker(configMapResourceName, "mode: enabled", kubeInformerClient)
						addNodeWithRoleToTracker("worker", kubeAPIClient)
						ca := newCA()
						caSecret := newActualCASecret(ca, caSecretName)
						caCrt = caSecret.Data["ca.crt"]
						addSecretToTrackers(caSecret, kubeAPIClient, kubeInformerClient)
						tlsSecret := newActualTLSSecret(ca, tlsSecretName, localhostIP)
						addSecretToTrackers(tlsSecret, kubeAPIClient, kubeInformerClient)
						addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformerClient)
						addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeAPIClient)
					})

					it("starts the impersonator with the existing tls certs, does not start loadbalancer or make tls secret", func() {
						startInformersAndController()
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 1)
						requireNodesListed(kubeAPIClient.Actions()[0])
						requireTLSServerIsRunning(caCrt, testServerAddr(), nil)
						requireCredentialIssuer(newSuccessStrategy(localhostIP, caCrt))
					})
				})

				when("the configmap has a hostname specified for the endpoint", func() {
					const fakeHostname = "fake.example.com"
					it.Before(func() {
						configMapYAML := fmt.Sprintf("{mode: enabled, endpoint: %s}", fakeHostname)
						addImpersonatorConfigMapToTracker(configMapResourceName, configMapYAML, kubeInformerClient)
						addNodeWithRoleToTracker("worker", kubeAPIClient)
					})

					it("starts the impersonator, generates a valid cert for the specified hostname", func() {
						startInformersAndController()
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 3)
						requireNodesListed(kubeAPIClient.Actions()[0])
						ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
						requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
						// Check that the server is running and that TLS certs that are being served are are for fakeHostname.
						requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + httpsPort: testServerAddr()})
						requireCredentialIssuer(newSuccessStrategy(fakeHostname, ca))
					})
				})

				when("the configmap has a endpoint which is an IP address with a port", func() {
					const fakeIPWithPort = "127.0.0.1:3000"
					it.Before(func() {
						configMapYAML := fmt.Sprintf("{mode: enabled, endpoint: %s}", fakeIPWithPort)
						addImpersonatorConfigMapToTracker(configMapResourceName, configMapYAML, kubeInformerClient)
						addNodeWithRoleToTracker("worker", kubeAPIClient)
					})

					it("starts the impersonator, generates a valid cert for the specified IP address", func() {
						startInformersAndController()
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 3)
						requireNodesListed(kubeAPIClient.Actions()[0])
						ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
						requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
						// Check that the server is running and that TLS certs that are being served are are for fakeIPWithPort.
						requireTLSServerIsRunning(ca, fakeIPWithPort, map[string]string{fakeIPWithPort: testServerAddr()})
						requireCredentialIssuer(newSuccessStrategy(fakeIPWithPort, ca))
					})
				})

				when("the configmap has a endpoint which is a hostname with a port", func() {
					const fakeHostnameWithPort = "fake.example.com:3000"
					it.Before(func() {
						configMapYAML := fmt.Sprintf("{mode: enabled, endpoint: %s}", fakeHostnameWithPort)
						addImpersonatorConfigMapToTracker(configMapResourceName, configMapYAML, kubeInformerClient)
						addNodeWithRoleToTracker("worker", kubeAPIClient)
					})

					it("starts the impersonator, generates a valid cert for the specified hostname", func() {
						startInformersAndController()
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 3)
						requireNodesListed(kubeAPIClient.Actions()[0])
						ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
						requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
						// Check that the server is running and that TLS certs that are being served are are for fakeHostnameWithPort.
						requireTLSServerIsRunning(ca, fakeHostnameWithPort, map[string]string{fakeHostnameWithPort: testServerAddr()})
						requireCredentialIssuer(newSuccessStrategy(fakeHostnameWithPort, ca))
					})
				})

				when("switching the configmap from ip address endpoint to hostname endpoint and back to ip address", func() {
					const fakeHostname = "fake.example.com"
					const fakeIP = "127.0.0.42"
					var hostnameYAML = fmt.Sprintf("{mode: enabled, endpoint: %s}", fakeHostname)
					var ipAddressYAML = fmt.Sprintf("{mode: enabled, endpoint: %s}", fakeIP)
					it.Before(func() {
						addImpersonatorConfigMapToTracker(configMapResourceName, ipAddressYAML, kubeInformerClient)
						addNodeWithRoleToTracker("worker", kubeAPIClient)
					})

					it("regenerates the cert for the hostname, then regenerates it for the IP again", func() {
						startInformersAndController()
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 3)
						requireNodesListed(kubeAPIClient.Actions()[0])
						ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
						requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
						// Check that the server is running and that TLS certs that are being served are are for fakeIP.
						requireTLSServerIsRunning(ca, fakeIP, map[string]string{fakeIP + httpsPort: testServerAddr()})
						requireCredentialIssuer(newSuccessStrategy(fakeIP, ca))

						// Simulate the informer cache's background update from its watch.
						addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Secrets())
						addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

						// Switch the endpoint config to a hostname.
						updateImpersonatorConfigMapInInformerAndWait(configMapResourceName, hostnameYAML, kubeInformers.Core().V1().ConfigMaps())

						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 5)
						requireTLSSecretWasDeleted(kubeAPIClient.Actions()[3])
						requireTLSSecretWasCreated(kubeAPIClient.Actions()[4], ca) // reuses the old CA
						// Check that the server is running and that TLS certs that are being served are are for fakeHostname.
						requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + httpsPort: testServerAddr()})
						requireCredentialIssuer(newSuccessStrategy(fakeHostname, ca))

						// Simulate the informer cache's background update from its watch.
						deleteSecretFromTracker(tlsSecretName, kubeInformerClient)
						addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[4], kubeInformers.Core().V1().Secrets())

						// Switch the endpoint config back to an IP.
						updateImpersonatorConfigMapInInformerAndWait(configMapResourceName, ipAddressYAML, kubeInformers.Core().V1().ConfigMaps())

						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 7)
						requireTLSSecretWasDeleted(kubeAPIClient.Actions()[5])
						requireTLSSecretWasCreated(kubeAPIClient.Actions()[6], ca) // reuses the old CA again
						// Check that the server is running and that TLS certs that are being served are are for fakeIP.
						requireTLSServerIsRunning(ca, fakeIP, map[string]string{fakeIP + httpsPort: testServerAddr()})
						requireCredentialIssuer(newSuccessStrategy(fakeIP, ca))
					})
				})

				when("the TLS cert goes missing and needs to be recreated, e.g. when a user manually deleted it", func() {
					const fakeHostname = "fake.example.com"
					it.Before(func() {
						configMapYAML := fmt.Sprintf("{mode: enabled, endpoint: %s}", fakeHostname)
						addImpersonatorConfigMapToTracker(configMapResourceName, configMapYAML, kubeInformerClient)
						addNodeWithRoleToTracker("worker", kubeAPIClient)
						startInformersAndController()
					})

					it("uses the existing CA cert the make a new TLS cert", func() {
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 3)
						requireNodesListed(kubeAPIClient.Actions()[0])
						ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
						requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
						// Check that the server is running and that TLS certs that are being served are are for fakeHostname.
						requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + httpsPort: testServerAddr()})
						requireCredentialIssuer(newSuccessStrategy(fakeHostname, ca))

						// Simulate the informer cache's background update from its watch for the CA Secret.
						addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Secrets())

						// Delete the TLS Secret that was just created from the Kube API server. Note that we never
						// simulated it getting added to the informer cache, so we don't need to remove it from there.
						deleteSecretFromTracker(tlsSecretName, kubeAPIClient)

						// Run again. It should create a new TLS cert using the old CA cert.
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 4)
						requireTLSSecretWasCreated(kubeAPIClient.Actions()[3], ca)
						// Check that the server is running and that TLS certs that are being served are are for fakeHostname.
						requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + httpsPort: testServerAddr()})
						requireCredentialIssuer(newSuccessStrategy(fakeHostname, ca))
					})
				})

				when("the CA cert goes missing and needs to be recreated, e.g. when a user manually deleted it", func() {
					const fakeHostname = "fake.example.com"
					it.Before(func() {
						configMapYAML := fmt.Sprintf("{mode: enabled, endpoint: %s}", fakeHostname)
						addImpersonatorConfigMapToTracker(configMapResourceName, configMapYAML, kubeInformerClient)
						addNodeWithRoleToTracker("worker", kubeAPIClient)
						startInformersAndController()
					})

					it("makes a new CA cert, deletes the old TLS cert, and makes a new TLS cert using the new CA", func() {
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 3)
						requireNodesListed(kubeAPIClient.Actions()[0])
						ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
						requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
						// Check that the server is running and that TLS certs that are being served are are for fakeHostname.
						requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + httpsPort: testServerAddr()})
						requireCredentialIssuer(newSuccessStrategy(fakeHostname, ca))

						// Simulate the informer cache's background update from its watch for the CA Secret.
						addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

						// Delete the CA Secret that was just created from the Kube API server. Note that we never
						// simulated it getting added to the informer cache, so we don't need to remove it from there.
						deleteSecretFromTracker(caSecretName, kubeAPIClient)

						// Run again. It should create both a new CA cert and a new TLS cert using the new CA cert.
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 6)
						ca = requireCASecretWasCreated(kubeAPIClient.Actions()[3])
						requireTLSSecretWasDeleted(kubeAPIClient.Actions()[4])
						requireTLSSecretWasCreated(kubeAPIClient.Actions()[5], ca) // created using the new CA
						// Check that the server is running and that TLS certs that are being served are are for fakeHostname.
						requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + httpsPort: testServerAddr()})
						requireCredentialIssuer(newSuccessStrategy(fakeHostname, ca))
					})
				})

				when("the CA cert is overwritten by another valid CA cert", func() {
					const fakeHostname = "fake.example.com"
					var caCrt []byte
					it.Before(func() {
						configMapYAML := fmt.Sprintf("{mode: enabled, endpoint: %s}", fakeHostname)
						addImpersonatorConfigMapToTracker(configMapResourceName, configMapYAML, kubeInformerClient)
						addNodeWithRoleToTracker("worker", kubeAPIClient)
						startInformersAndController()
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 3)
						requireNodesListed(kubeAPIClient.Actions()[0])
						ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
						requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
						// Check that the server is running and that TLS certs that are being served are are for fakeHostname.
						requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + httpsPort: testServerAddr()})
						requireCredentialIssuer(newSuccessStrategy(fakeHostname, ca))

						// Simulate the informer cache's background update from its watch for the CA Secret.
						addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

						// Simulate someone updating the CA Secret out of band, e.g. when a human edits it with kubectl.
						// Delete the CA Secret that was just created from the Kube API server. Note that we never
						// simulated it getting added to the informer cache, so we don't need to remove it from there.
						// Then add a new one. Delete + new = update, since only the final state is observed.
						deleteSecretFromTracker(caSecretName, kubeAPIClient)
						anotherCA := newCA()
						newCASecret := newActualCASecret(anotherCA, caSecretName)
						caCrt = newCASecret.Data["ca.crt"]
						addSecretToTrackers(newCASecret, kubeAPIClient)
						addObjectToInformerAndWait(newCASecret, kubeInformers.Core().V1().Secrets())
					})

					it("deletes the old TLS cert and makes a new TLS cert using the new CA", func() {
						// Run again. It should use the updated CA cert to create a new TLS cert.
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 5)
						requireTLSSecretWasDeleted(kubeAPIClient.Actions()[3])
						requireTLSSecretWasCreated(kubeAPIClient.Actions()[4], caCrt) // created using the updated CA
						// Check that the server is running and that TLS certs that are being served are are for fakeHostname.
						requireTLSServerIsRunning(caCrt, fakeHostname, map[string]string{fakeHostname + httpsPort: testServerAddr()})
						requireCredentialIssuer(newSuccessStrategy(fakeHostname, caCrt))
					})

					when("deleting the TLS cert due to mismatched CA results in an error", func() {
						it.Before(func() {
							kubeAPIClient.PrependReactor("delete", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
								if action.(coretesting.DeleteAction).GetName() == tlsSecretName {
									return true, nil, fmt.Errorf("error on tls secret delete")
								}
								return false, nil, nil
							})
						})

						it("returns an error", func() {
							r.Error(runControllerSync(), "error on tls secret delete")
							r.Len(kubeAPIClient.Actions(), 4)
							requireTLSSecretWasDeleted(kubeAPIClient.Actions()[3]) // tried to delete cert but failed
							requireCredentialIssuer(newErrorStrategy("error on tls secret delete"))
						})
					})
				})
			})

			when("the configuration switches from enabled to disabled mode", func() {
				it.Before(func() {
					addImpersonatorConfigMapToTracker(configMapResourceName, "mode: enabled", kubeInformerClient)
					addNodeWithRoleToTracker("worker", kubeAPIClient)
				})

				it("starts the impersonator and loadbalancer, then shuts it down, then starts it again", func() {
					startInformersAndController()

					r.NoError(runControllerSync())
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
					requireCASecretWasCreated(kubeAPIClient.Actions()[2])
					requireCredentialIssuer(newPendingStrategy())

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Services())
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

					// Update the configmap.
					updateImpersonatorConfigMapInInformerAndWait(configMapResourceName, "mode: disabled", kubeInformers.Core().V1().ConfigMaps())

					r.NoError(runControllerSync())
					requireTLSServerIsNoLongerRunning()
					r.Len(kubeAPIClient.Actions(), 4)
					requireLoadBalancerWasDeleted(kubeAPIClient.Actions()[3])
					requireCredentialIssuer(newManuallyDisabledStrategy())

					deleteServiceFromTracker(loadBalancerServiceName, kubeInformerClient)
					waitForObjectToBeDeletedFromInformer(loadBalancerServiceName, kubeInformers.Core().V1().Services())

					// Update the configmap again.
					updateImpersonatorConfigMapInInformerAndWait(configMapResourceName, "mode: enabled", kubeInformers.Core().V1().ConfigMaps())

					r.NoError(runControllerSync())
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 5)
					requireLoadBalancerWasCreated(kubeAPIClient.Actions()[4])
					requireCredentialIssuer(newPendingStrategy())
				})

				when("there is an error while shutting down the server", func() {
					it.Before(func() {
						startTLSListenerUponCloseError = errors.New("fake server close error")
					})

					it("returns the error from the sync function", func() {
						startInformersAndController()
						r.NoError(runControllerSync())
						requireTLSServerIsRunningWithoutCerts()

						// Update the configmap.
						updateImpersonatorConfigMapInInformerAndWait(configMapResourceName, "mode: disabled", kubeInformers.Core().V1().ConfigMaps())

						r.EqualError(runControllerSync(), "fake server close error")
						requireTLSServerIsNoLongerRunning()
						requireCredentialIssuer(newErrorStrategy("fake server close error"))
					})
				})
			})

			when("the endpoint switches from specified, to not specified, to specified again", func() {
				it.Before(func() {
					configMapYAML := fmt.Sprintf("{mode: enabled, endpoint: %s}", localhostIP)
					addImpersonatorConfigMapToTracker(configMapResourceName, configMapYAML, kubeInformerClient)
					addNodeWithRoleToTracker("worker", kubeAPIClient)
				})

				it("doesn't create, then creates, then deletes the load balancer", func() {
					startInformersAndController()

					// Should have started in "enabled" mode with an "endpoint", so no load balancer is needed.
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1]) // created immediately because "endpoint" was specified
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
					requireTLSServerIsRunning(ca, testServerAddr(), nil)
					requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Secrets())
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

					// Switch to "enabled" mode without an "endpoint", so a load balancer is needed now.
					updateImpersonatorConfigMapInInformerAndWait(configMapResourceName, "mode: enabled", kubeInformers.Core().V1().ConfigMaps())

					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 5)
					requireLoadBalancerWasCreated(kubeAPIClient.Actions()[3])
					requireTLSSecretWasDeleted(kubeAPIClient.Actions()[4]) // the Secret was deleted because it contained a cert with the wrong IP
					requireTLSServerIsRunningWithoutCerts()
					requireCredentialIssuer(newPendingStrategy())

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[3], kubeInformers.Core().V1().Services())
					deleteSecretFromTracker(tlsSecretName, kubeInformerClient)
					waitForObjectToBeDeletedFromInformer(tlsSecretName, kubeInformers.Core().V1().Secrets())

					// The controller should be waiting for the load balancer's ingress to become available.
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 5) // no new actions while it is waiting for the load balancer's ingress
					requireTLSServerIsRunningWithoutCerts()
					requireCredentialIssuer(newPendingStrategy())

					// Update the ingress of the LB in the informer's client and run Sync again.
					fakeIP := "127.0.0.123"
					updateLoadBalancerServiceInInformerAndWait(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: fakeIP}}, kubeInformers.Core().V1().Services())
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 6)
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[5], ca) // reuses the existing CA
					// Check that the server is running and that TLS certs that are being served are are for fakeIP.
					requireTLSServerIsRunning(ca, fakeIP, map[string]string{fakeIP + httpsPort: testServerAddr()})
					requireCredentialIssuer(newSuccessStrategy(fakeIP, ca))

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[5], kubeInformers.Core().V1().Secrets())

					// Now switch back to having the "endpoint" specified, so the load balancer is not needed anymore.
					configMapYAML := fmt.Sprintf("{mode: enabled, endpoint: %s}", localhostIP)
					updateImpersonatorConfigMapInInformerAndWait(configMapResourceName, configMapYAML, kubeInformers.Core().V1().ConfigMaps())

					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 9)
					requireLoadBalancerWasDeleted(kubeAPIClient.Actions()[6])
					requireTLSSecretWasDeleted(kubeAPIClient.Actions()[7])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[8], ca) // recreated because the endpoint was updated, reused the old CA
					requireTLSServerIsRunning(ca, testServerAddr(), nil)
					requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
				})
			})
		})

		when("sync is called more than once", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("worker", kubeAPIClient)
			})

			it("only starts the impersonator once and only lists the cluster's nodes once", func() {
				startInformersAndController()
				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
				requireCASecretWasCreated(kubeAPIClient.Actions()[2])
				requireTLSServerIsRunningWithoutCerts()
				requireCredentialIssuer(newPendingStrategy())

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Services())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

				r.NoError(runControllerSync())
				r.Equal(1, startTLSListenerFuncWasCalled) // wasn't started a second time
				requireTLSServerIsRunningWithoutCerts()   // still running
				requireCredentialIssuer(newPendingStrategy())
				r.Len(kubeAPIClient.Actions(), 3) // no new API calls
			})

			it("creates certs from the ip address listed on the load balancer", func() {
				startInformersAndController()
				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
				ca := requireCASecretWasCreated(kubeAPIClient.Actions()[2])
				requireTLSServerIsRunningWithoutCerts()
				requireCredentialIssuer(newPendingStrategy())

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Services())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

				updateLoadBalancerServiceInInformerAndWait(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformers.Core().V1().Services())

				r.NoError(runControllerSync())
				r.Equal(1, startTLSListenerFuncWasCalled) // wasn't started a second time
				r.Len(kubeAPIClient.Actions(), 4)
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[3], ca) // uses the ca from last time
				requireTLSServerIsRunning(ca, testServerAddr(), nil)       // running with certs now
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[3], kubeInformers.Core().V1().Secrets())

				r.NoError(runControllerSync())
				r.Equal(1, startTLSListenerFuncWasCalled)            // wasn't started again
				r.Len(kubeAPIClient.Actions(), 4)                    // no more actions
				requireTLSServerIsRunning(ca, testServerAddr(), nil) // still running
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
			})

			it("creates certs from the hostname listed on the load balancer", func() {
				hostname := "fake.example.com"
				startInformersAndController()
				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
				ca := requireCASecretWasCreated(kubeAPIClient.Actions()[2])
				requireTLSServerIsRunningWithoutCerts()
				requireCredentialIssuer(newPendingStrategy())

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Services())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

				updateLoadBalancerServiceInInformerAndWait(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP, Hostname: hostname}}, kubeInformers.Core().V1().Services())

				r.NoError(runControllerSync())
				r.Equal(1, startTLSListenerFuncWasCalled) // wasn't started a second time
				r.Len(kubeAPIClient.Actions(), 4)
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[3], ca)                                         // uses the ca from last time
				requireTLSServerIsRunning(ca, hostname, map[string]string{hostname + httpsPort: testServerAddr()}) // running with certs now
				requireCredentialIssuer(newSuccessStrategy(hostname, ca))

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[3], kubeInformers.Core().V1().Secrets())

				r.NoError(runControllerSync())
				r.Equal(1, startTLSListenerFuncWasCalled)                                                          // wasn't started a third time
				r.Len(kubeAPIClient.Actions(), 4)                                                                  // no more actions
				requireTLSServerIsRunning(ca, hostname, map[string]string{hostname + httpsPort: testServerAddr()}) // still running
				requireCredentialIssuer(newSuccessStrategy(hostname, ca))
			})
		})

		when("getting the control plane nodes returns an error, e.g. when there are no nodes", func() {
			it("returns an error", func() {
				startInformersAndController()
				r.EqualError(runControllerSync(), "no nodes found")
				requireCredentialIssuer(newErrorStrategy("no nodes found"))
				requireTLSServerWasNeverStarted()
			})
		})

		when("the http handler factory function returns an error", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				httpHandlerFactoryFuncError = errors.New("some factory error")
			})

			it("returns an error", func() {
				startInformersAndController()
				r.EqualError(runControllerSync(), "some factory error")
				requireCredentialIssuer(newErrorStrategy("some factory error"))
				requireTLSServerWasNeverStarted()
			})
		})

		when("the configmap is invalid", func() {
			it.Before(func() {
				addImpersonatorConfigMapToTracker(configMapResourceName, "not yaml", kubeInformerClient)
			})

			it("returns an error", func() {
				startInformersAndController()
				errString := "invalid impersonator configuration: decode yaml: error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type impersonator.Config"
				r.EqualError(runControllerSync(), errString)
				requireCredentialIssuer(newErrorStrategy(errString))
				requireTLSServerWasNeverStarted()
			})
		})

		when("there is an error creating the load balancer", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				kubeAPIClient.PrependReactor("create", "services", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("error on create")
				})
			})

			it("returns an error", func() {
				startInformersAndController()
				r.EqualError(runControllerSync(), "error on create")
				requireCredentialIssuer(newErrorStrategy("error on create"))
				requireTLSServerIsRunningWithoutCerts()
			})
		})

		when("there is an error creating the tls secret", func() {
			it.Before(func() {
				addImpersonatorConfigMapToTracker(configMapResourceName, "{mode: enabled, endpoint: example.com}", kubeInformerClient)
				addNodeWithRoleToTracker("control-plane", kubeAPIClient)
				kubeAPIClient.PrependReactor("create", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					createdSecret := action.(coretesting.CreateAction).GetObject().(*corev1.Secret)
					if createdSecret.Name == tlsSecretName {
						return true, nil, fmt.Errorf("error on tls secret create")
					}
					return false, nil, nil
				})
			})

			it("starts the impersonator without certs and returns an error", func() {
				startInformersAndController()
				r.EqualError(runControllerSync(), "error on tls secret create")
				requireCredentialIssuer(newErrorStrategy("error on tls secret create"))
				requireTLSServerIsRunningWithoutCerts()
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
			})
		})

		when("there is an error creating the CA secret", func() {
			it.Before(func() {
				addImpersonatorConfigMapToTracker(configMapResourceName, "{mode: enabled, endpoint: example.com}", kubeInformerClient)
				addNodeWithRoleToTracker("control-plane", kubeAPIClient)
				kubeAPIClient.PrependReactor("create", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					createdSecret := action.(coretesting.CreateAction).GetObject().(*corev1.Secret)
					if createdSecret.Name == caSecretName {
						return true, nil, fmt.Errorf("error on ca secret create")
					}
					return false, nil, nil
				})
			})

			it("starts the impersonator without certs and returns an error", func() {
				startInformersAndController()
				r.EqualError(runControllerSync(), "error on ca secret create")
				requireCredentialIssuer(newErrorStrategy("error on ca secret create"))
				requireTLSServerIsRunningWithoutCerts()
				r.Len(kubeAPIClient.Actions(), 2)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireCASecretWasCreated(kubeAPIClient.Actions()[1])
			})
		})

		when("the CA secret exists but is invalid while the TLS secret needs to be created", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("control-plane", kubeAPIClient)
				addImpersonatorConfigMapToTracker(configMapResourceName, "{mode: enabled, endpoint: example.com}", kubeInformerClient)
				addSecretToTrackers(newEmptySecret(caSecretName), kubeAPIClient, kubeInformerClient)
			})

			it("starts the impersonator without certs and returns an error", func() {
				startInformersAndController()
				errString := "could not load CA: tls: failed to find any PEM data in certificate input"
				r.EqualError(runControllerSync(), errString)
				requireCredentialIssuer(newErrorStrategy(errString))
				requireTLSServerIsRunningWithoutCerts()
				r.Len(kubeAPIClient.Actions(), 1)
				requireNodesListed(kubeAPIClient.Actions()[0])
			})
		})

		when("there is an error deleting the tls secret", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("control-plane", kubeAPIClient)
				addLoadBalancerServiceToTracker(loadBalancerServiceName, kubeInformerClient)
				addLoadBalancerServiceToTracker(loadBalancerServiceName, kubeAPIClient)
				addSecretToTrackers(newEmptySecret(tlsSecretName), kubeAPIClient, kubeInformerClient)
				startInformersAndController()
				kubeAPIClient.PrependReactor("delete", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("error on delete")
				})
			})

			it("does not start the impersonator, deletes the loadbalancer, returns an error", func() {
				r.EqualError(runControllerSync(), "error on delete")
				requireCredentialIssuer(newErrorStrategy("error on delete"))
				requireTLSServerWasNeverStarted()
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireLoadBalancerWasDeleted(kubeAPIClient.Actions()[1])
				requireTLSSecretWasDeleted(kubeAPIClient.Actions()[2])
			})
		})

		when("the PEM formatted data in the TLS Secret is not a valid cert", func() {
			it.Before(func() {
				configMapYAML := fmt.Sprintf("{mode: enabled, endpoint: %s}", localhostIP)
				addImpersonatorConfigMapToTracker(configMapResourceName, configMapYAML, kubeInformerClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				tlsSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      tlsSecretName,
						Namespace: installedInNamespace,
					},
					Data: map[string][]byte{
						// "aGVsbG8gd29ybGQK" is "hello world" base64 encoded which is not a valid cert
						corev1.TLSCertKey: []byte("-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQK\n-----END CERTIFICATE-----\n"),
					},
				}
				addSecretToTrackers(tlsSecret, kubeAPIClient, kubeInformerClient)
			})

			it("deletes the invalid certs, creates new certs, and starts the impersonator", func() {
				startInformersAndController()
				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 4)
				requireNodesListed(kubeAPIClient.Actions()[0])
				ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
				requireTLSSecretWasDeleted(kubeAPIClient.Actions()[2]) // deleted the bad cert
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[3], ca)
				requireTLSServerIsRunning(ca, testServerAddr(), nil)
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
			})

			when("there is an error while the invalid cert is being deleted", func() {
				it.Before(func() {
					kubeAPIClient.PrependReactor("delete", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("error on delete")
					})
				})

				it("tries to delete the invalid cert, starts the impersonator without certs, and returns an error", func() {
					startInformersAndController()
					errString := "PEM data represented an invalid cert, but got error while deleting it: error on delete"
					r.EqualError(runControllerSync(), errString)
					requireCredentialIssuer(newErrorStrategy(errString))
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireCASecretWasCreated(kubeAPIClient.Actions()[1])
					requireTLSSecretWasDeleted(kubeAPIClient.Actions()[2]) // tried deleted the bad cert, which failed
					requireTLSServerIsRunningWithoutCerts()
				})
			})
		})

		when("a tls secret already exists but it is not valid", func() {
			var caCrt []byte
			it.Before(func() {
				addImpersonatorConfigMapToTracker(configMapResourceName, "mode: enabled", kubeInformerClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				ca := newCA()
				caSecret := newActualCASecret(ca, caSecretName)
				caCrt = caSecret.Data["ca.crt"]
				addSecretToTrackers(caSecret, kubeAPIClient, kubeInformerClient)
				addSecretToTrackers(newEmptySecret(tlsSecretName), kubeAPIClient, kubeInformerClient) // secret exists but lacks certs
				addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformerClient)
				addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeAPIClient)
			})

			it("deletes the invalid certs, creates new certs, and starts the impersonator", func() {
				startInformersAndController()
				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireTLSSecretWasDeleted(kubeAPIClient.Actions()[1]) // deleted the bad cert
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], caCrt)
				requireTLSServerIsRunning(caCrt, testServerAddr(), nil)
				requireCredentialIssuer(newSuccessStrategy(localhostIP, caCrt))
			})

			when("there is an error while the invalid cert is being deleted", func() {
				it.Before(func() {
					kubeAPIClient.PrependReactor("delete", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("error on delete")
					})
				})

				it("tries to delete the invalid cert, starts the impersonator without certs, and returns an error", func() {
					startInformersAndController()
					errString := "found missing or not PEM-encoded data in TLS Secret, but got error while deleting it: error on delete"
					r.EqualError(runControllerSync(), errString)
					requireCredentialIssuer(newErrorStrategy(errString))
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 2)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireTLSSecretWasDeleted(kubeAPIClient.Actions()[1]) // tried deleted the bad cert, which failed
					requireTLSServerIsRunningWithoutCerts()
				})
			})
		})

		when("a tls secret already exists but the private key is not valid", func() {
			var caCrt []byte
			it.Before(func() {
				addImpersonatorConfigMapToTracker(configMapResourceName, "mode: enabled", kubeInformerClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				ca := newCA()
				caSecret := newActualCASecret(ca, caSecretName)
				caCrt = caSecret.Data["ca.crt"]
				addSecretToTrackers(caSecret, kubeAPIClient, kubeInformerClient)
				tlsSecret := newActualTLSSecret(ca, tlsSecretName, localhostIP)
				tlsSecret.Data["tls.key"] = nil
				addSecretToTrackers(tlsSecret, kubeAPIClient, kubeInformerClient)
				addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformerClient)
				addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeAPIClient)
			})

			it("deletes the invalid certs, creates new certs, and starts the impersonator", func() {
				startInformersAndController()
				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireTLSSecretWasDeleted(kubeAPIClient.Actions()[1]) // deleted the bad cert
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], caCrt)
				requireTLSServerIsRunning(caCrt, testServerAddr(), nil)
				requireCredentialIssuer(newSuccessStrategy(localhostIP, caCrt))
			})

			when("there is an error while the invalid cert is being deleted", func() {
				it.Before(func() {
					kubeAPIClient.PrependReactor("delete", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("error on delete")
					})
				})

				it("tries to delete the invalid cert, starts the impersonator without certs, and returns an error", func() {
					startInformersAndController()
					errString := "cert had an invalid private key, but got error while deleting it: error on delete"
					r.EqualError(runControllerSync(), errString)
					requireCredentialIssuer(newErrorStrategy(errString))
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 2)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireTLSSecretWasDeleted(kubeAPIClient.Actions()[1]) // tried deleted the bad cert, which failed
					requireTLSServerIsRunningWithoutCerts()
				})
			})
		})

		when("there is an error while creating or updating the CredentialIssuer status", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				pinnipedAPIClient.PrependReactor("create", "credentialissuers", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("error on create")
				})
			})

			it("returns the error", func() {
				startInformersAndController()
				r.EqualError(runControllerSync(), "could not create or update credentialissuer: create failed: error on create")
			})

			when("there is also a more fundamental error while starting the impersonator", func() {
				it.Before(func() {
					kubeAPIClient.PrependReactor("create", "services", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("error on service creation")
					})
				})

				it("returns the more fundamental error instead of the CredentialIssuer error", func() {
					startInformersAndController()
					r.EqualError(runControllerSync(), "error on service creation")
				})
			})
		})

		when("there is already a CredentialIssuer", func() {
			preExistingStrategy := v1alpha1.CredentialIssuerStrategy{
				Type:           v1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         v1alpha1.SuccessStrategyStatus,
				Reason:         v1alpha1.FetchedKeyStrategyReason,
				Message:        "happy other unrelated strategy",
				LastUpdateTime: metav1.NewTime(frozenNow),
				Frontend: &v1alpha1.CredentialIssuerFrontend{
					Type: v1alpha1.TokenCredentialRequestAPIFrontendType,
				},
			}

			it.Before(func() {
				r.NoError(pinnipedAPIClient.Tracker().Add(&v1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Status:     v1alpha1.CredentialIssuerStatus{Strategies: []v1alpha1.CredentialIssuerStrategy{preExistingStrategy}},
				}))
				addNodeWithRoleToTracker("worker", kubeAPIClient)
			})

			it("merges into the existing strategy array on the CredentialIssuer", func() {
				startInformersAndController()
				r.NoError(runControllerSync())
				requireTLSServerIsRunningWithoutCerts()
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
				requireCASecretWasCreated(kubeAPIClient.Actions()[2])
				credentialIssuer := getCredentialIssuer()
				r.Equal([]v1alpha1.CredentialIssuerStrategy{preExistingStrategy, newPendingStrategy()}, credentialIssuer.Status.Strategies)
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
