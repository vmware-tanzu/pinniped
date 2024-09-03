// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonatorconfig

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8sinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"

	conciergeconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	conciergefake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	conciergeinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/controller/apicerts"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/tokenclient"
)

func TestImpersonatorConfigControllerOptions(t *testing.T) {
	spec.Run(t, "options", func(t *testing.T, when spec.G, it spec.S) {
		const installedInNamespace = "some-namespace"
		const impersonationProxyPort = 8444
		const credentialIssuerResourceName = "some-credential-issuer-resource-name" //nolint:gosec // this is not a credential
		const generatedLoadBalancerServiceName = "some-service-resource-name"
		const generatedClusterIPServiceName = "some-cluster-ip-resource-name"
		const tlsSecretName = "some-tls-secret-name" //nolint:gosec // this is not a credential
		const caSecretName = "some-ca-secret-name"
		const caSignerName = "some-ca-signer-name"

		var r *require.Assertions
		var observableWithInformerOption *testutil.ObservableWithInformerOption
		var credIssuerInformerFilter controllerlib.Filter
		var servicesInformerFilter controllerlib.Filter
		var secretsInformerFilter controllerlib.Filter

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = testutil.NewObservableWithInformerOption()
			pinnipedInformerFactory := conciergeinformers.NewSharedInformerFactory(nil, 0)
			sharedInformerFactory := k8sinformers.NewSharedInformerFactory(nil, 0)
			credIssuerInformer := pinnipedInformerFactory.Config().V1alpha1().CredentialIssuers()
			servicesInformer := sharedInformerFactory.Core().V1().Services()
			secretsInformer := sharedInformerFactory.Core().V1().Secrets()

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			_ = NewImpersonatorConfigController(
				installedInNamespace,
				credentialIssuerResourceName,
				nil,
				nil,
				credIssuerInformer,
				servicesInformer,
				secretsInformer,
				observableWithInformerOption.WithInformer,
				impersonationProxyPort,
				generatedLoadBalancerServiceName,
				generatedClusterIPServiceName,
				tlsSecretName,
				caSecretName,
				nil,
				nil,
				nil,
				caSignerName,
				nil,
				logger,
				nil,
			)
			credIssuerInformerFilter = observableWithInformerOption.GetFilterForInformer(credIssuerInformer)
			servicesInformerFilter = observableWithInformerOption.GetFilterForInformer(servicesInformer)
			secretsInformerFilter = observableWithInformerOption.GetFilterForInformer(secretsInformer)
		})

		when("watching CredentialIssuer objects", func() {
			var subject controllerlib.Filter
			var target, wrongName, otherWrongName *conciergeconfigv1alpha1.CredentialIssuer

			it.Before(func() {
				subject = credIssuerInformerFilter
				target = &conciergeconfigv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName}}
				wrongName = &conciergeconfigv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "wrong-name"}}
				otherWrongName = &conciergeconfigv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "other-wrong-name"}}
			})

			when("the target CredentialIssuer changes", func() {
				it("returns true to trigger the sync method", func() {
					r.True(subject.Add(target))
					r.True(subject.Update(target, wrongName))
					r.True(subject.Update(wrongName, target))
					r.True(subject.Delete(target))
				})
			})

			when("a CredentialIssuer with a different name changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(wrongName))
					r.False(subject.Update(wrongName, otherWrongName))
					r.False(subject.Update(otherWrongName, wrongName))
					r.False(subject.Delete(wrongName))
				})
			})
		})

		when("watching Service objects", func() {
			var subject controllerlib.Filter
			var targetLBService, targetClusterIPService, wrongNamespace, wrongName, unrelated *corev1.Service

			it.Before(func() {
				subject = servicesInformerFilter
				targetLBService = &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: generatedLoadBalancerServiceName, Namespace: installedInNamespace}}
				targetClusterIPService = &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: generatedClusterIPServiceName, Namespace: installedInNamespace}}
				wrongNamespace = &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: generatedLoadBalancerServiceName, Namespace: "wrong-namespace"}}
				wrongName = &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: installedInNamespace}}
				unrelated = &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: "wrong-namespace"}}
			})

			when("the target Service changes", func() {
				it("returns true to trigger the sync method", func() {
					r.True(subject.Add(targetLBService))
					r.True(subject.Update(targetLBService, unrelated))
					r.True(subject.Update(unrelated, targetLBService))
					r.True(subject.Delete(targetLBService))
					r.True(subject.Add(targetClusterIPService))
					r.True(subject.Update(targetClusterIPService, unrelated))
					r.True(subject.Update(unrelated, targetClusterIPService))
					r.True(subject.Delete(targetClusterIPService))
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
			var target1, target2, target3, wrongNamespace1, wrongNamespace2, wrongName, unrelated, typeTLS, typeTLSWrongNamespace *corev1.Secret

			it.Before(func() {
				subject = secretsInformerFilter
				target1 = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: tlsSecretName, Namespace: installedInNamespace}}
				target2 = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: caSecretName, Namespace: installedInNamespace}}
				target3 = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: caSignerName, Namespace: installedInNamespace}}
				wrongNamespace1 = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: tlsSecretName, Namespace: "wrong-namespace"}}
				wrongNamespace2 = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: caSecretName, Namespace: "wrong-namespace"}}
				wrongName = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: installedInNamespace}}
				unrelated = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "wrong-name", Namespace: "wrong-namespace"}}
				typeTLS = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "any-name", Namespace: installedInNamespace}, Type: corev1.SecretTypeTLS}
				typeTLSWrongNamespace = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "any-name", Namespace: "wrong-namespace"}, Type: corev1.SecretTypeTLS}
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
					r.True(subject.Add(target3))
					r.True(subject.Update(target3, unrelated))
					r.True(subject.Update(unrelated, target3))
					r.True(subject.Delete(target3))
					r.True(subject.Add(typeTLS))
					r.True(subject.Update(typeTLS, unrelated))
					r.True(subject.Update(unrelated, typeTLS))
					r.True(subject.Delete(typeTLS))
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
					r.False(subject.Add(typeTLSWrongNamespace))
					r.False(subject.Update(typeTLSWrongNamespace, unrelated))
					r.False(subject.Update(unrelated, typeTLSWrongNamespace))
					r.False(subject.Delete(typeTLSWrongNamespace))
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

func TestImpersonatorConfigControllerSync(t *testing.T) {
	name := t.Name()
	spec.Run(t, "Sync", func(t *testing.T, when spec.G, it spec.S) {
		const installedInNamespace = "some-namespace"
		const impersonationProxyPort = 8444
		const credentialIssuerResourceName = "some-credential-issuer-resource-name" //nolint:gosec // this is not a credential
		const loadBalancerServiceName = "some-service-resource-name"
		const clusterIPServiceName = "some-cluster-ip-resource-name"
		const internallyGeneratedTLSServingCertSecretName = "some-tls-secret-name" //nolint:gosec // this is not a credential
		const internallyGeneratedTLSServingCASecretName = "some-ca-secret-name"
		const mTLSClientCertCASecretName = "some-ca-signer-name" //nolint:gosec // this is not a credential
		const localhostIP = "127.0.0.1"
		const httpsPort = ":443"
		const fakeServerResponseBody = "hello, world!"
		const externallyProvidedTLSSecretName = "external-tls-secret" //nolint:gosec // this is not a credential
		var fakeExpiringSingletonTokenCacheGet = tokenclient.NewExpiringSingletonTokenCache()
		var labels = map[string]string{"app": "app-name", "other-key": "other-value"}

		var r *require.Assertions

		var subject controllerlib.Controller
		var kubeAPIClient *kubernetesfake.Clientset
		var pinnipedAPIClient *conciergefake.Clientset
		var pinnipedInformerClient *conciergefake.Clientset
		var pinnipedInformers conciergeinformers.SharedInformerFactory
		var kubeInformerClient *kubernetesfake.Clientset
		var kubeInformers k8sinformers.SharedInformerFactory
		var cancelContext context.Context
		var cancelContextCancelFunc context.CancelFunc
		var syncContext *controllerlib.Context
		var frozenNow time.Time
		var tlsServingCertDynamicCertProvider dynamiccert.Private
		var mTLSClientCertProvider dynamiccert.Provider
		var mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM []byte
		var mTLSClientCertCASecret *corev1.Secret
		var impersonatorFuncWasCalled int
		var impersonatorFuncError error
		var impersonatorFuncReturnedFuncError error
		var startedTLSListener net.Listener
		var startedTLSListenerMutex sync.RWMutex
		var testHTTPServer *http.Server
		var testHTTPServerMutex sync.RWMutex
		var testHTTPServerInterruptCh chan struct{}
		var queue *testQueue
		var validClientCert *tls.Certificate
		var externalCA *certauthority.CA
		var externalTLSSecret *corev1.Secret

		var impersonatorFunc = func(
			port int,
			dynamicCertProvider dynamiccert.Private,
			impersonationProxySignerCAProvider dynamiccert.Public,
			expiringSingletonTokenCacheGet tokenclient.ExpiringSingletonTokenCacheGet,
		) (func(ctx context.Context) error, error) {
			impersonatorFuncWasCalled++
			r.Equal(8444, port)
			r.NotNil(dynamicCertProvider)
			r.NotNil(impersonationProxySignerCAProvider)
			r.Equal(fakeExpiringSingletonTokenCacheGet, expiringSingletonTokenCacheGet)

			if impersonatorFuncError != nil {
				return nil, impersonatorFuncError
			}

			startedTLSListenerMutex.Lock() // this is to satisfy the race detector
			defer startedTLSListenerMutex.Unlock()
			var err error
			// Bind a listener to the port. Automatically choose the port for unit tests instead of using the real port.
			startedTLSListener, err = tls.Listen("tcp", localhostIP+":0", &tls.Config{
				MinVersion: tls.VersionTLS12,
				GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
					certPEM, keyPEM := dynamicCertProvider.CurrentCertKeyContent()
					if certPEM != nil && keyPEM != nil {
						tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
						r.NoError(err)
						return &tlsCert, nil
					}
					return nil, nil // no cached TLS certs
				},
				ClientAuth: tls.RequestClientCert,
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					// Docs say that this will always be called in tls.RequestClientCert mode
					// and that the second parameter will always be nil in that case.
					// rawCerts will be raw ASN.1 certificates provided by the peer.
					if len(rawCerts) != 1 {
						return fmt.Errorf("expected to get one client cert on incoming request to test server, found %d", len(rawCerts))
					}
					clientCert := rawCerts[0]
					currentClientCertCA := impersonationProxySignerCAProvider.CurrentCABundleContent()
					if currentClientCertCA == nil {
						return fmt.Errorf("impersonationProxySignerCAProvider does not have a current CA certificate")
					}
					// Assert that the client's cert was signed by the CA cert that the controller put into
					// the CAContentProvider that was passed in.
					parsed, err := x509.ParseCertificate(clientCert)
					require.NoError(t, err)
					roots := x509.NewCertPool()
					require.True(t, roots.AppendCertsFromPEM(currentClientCertCA))
					opts := x509.VerifyOptions{
						Roots:     roots,
						KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
					}
					_, err = parsed.Verify(opts)
					require.NoError(t, err)
					return nil
				},
			})
			r.NoError(err)

			// Return a func that starts a fake server when called, and shuts down the fake server when ctx is cancelled.
			// This fake server is enough like the real impersonation proxy server for this unit test because it
			// uses the supplied providers to serve TLS. The goal of this unit test is to make sure that the server
			// was started/stopped/configured correctly, not to test the actual impersonation behavior.
			return func(ctx context.Context) error {
				if impersonatorFuncReturnedFuncError != nil {
					return impersonatorFuncReturnedFuncError
				}

				testHTTPServerMutex.Lock() // this is to satisfy the race detector
				testHTTPServer = &http.Server{
					Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						_, err := fmt.Fprint(w, fakeServerResponseBody)
						r.NoError(err)
					}),
					ReadHeaderTimeout: 10 * time.Second,
				}
				testHTTPServerMutex.Unlock()

				// Start serving requests in the background.
				go func() {
					startedTLSListenerMutex.RLock() // this is to satisfy the race detector
					listener := startedTLSListener
					startedTLSListenerMutex.RUnlock()
					err := testHTTPServer.Serve(listener)
					if !errors.Is(err, http.ErrServerClosed) {
						t.Log("Got an unexpected error while starting the fake http server!")
						r.NoError(err) // causes the test to crash, which is good enough because this should never happen
					}
				}()

				if testHTTPServerInterruptCh == nil {
					// Wait in the foreground for the context to be done, and kill the server when that happens.
					// This is similar to the behavior of the real impersonation server.
					<-ctx.Done()
				} else {
					// The test supplied an interrupt channel because it wants to test unexpected termination
					// of the server, so wait for that channel to close instead of waiting for the one that
					// was passed in from the production code.
					<-testHTTPServerInterruptCh
				}

				err := testHTTPServer.Close()
				t.Log("Got an unexpected error while stopping the fake http server!")
				r.NoError(err) // causes the test to crash, which is good enough because this should never happen

				return nil
			}, nil
		}

		var testServerAddr = func() string {
			var listener net.Listener
			require.Eventually(t, func() bool {
				startedTLSListenerMutex.RLock() // this is to satisfy the race detector
				listener = startedTLSListener
				defer startedTLSListenerMutex.RUnlock()
				return listener != nil
			}, 20*time.Second, 50*time.Millisecond, "TLS listener never became not nil")

			return listener.Addr().String()
		}

		var closeTestHTTPServer = func() {
			// If a test left it running, then close it.
			testHTTPServerMutex.RLock() // this is to satisfy the race detector
			defer testHTTPServerMutex.RUnlock()
			if testHTTPServer != nil {
				err := testHTTPServer.Close()
				r.NoError(err)
			}
		}

		var requireTLSSecretProviderHasLoadedCerts = func() {
			actualCert, actualKey := tlsServingCertDynamicCertProvider.CurrentCertKeyContent()
			r.NotEmpty(actualCert)
			r.NotEmpty(actualKey)
			_, err := tls.X509KeyPair(actualCert, actualKey)
			r.NoError(err)
		}

		var requireTLSSecretProviderIsEmpty = func() {
			actualCert, actualKey := tlsServingCertDynamicCertProvider.CurrentCertKeyContent()
			r.Nil(actualCert)
			r.Nil(actualKey)
		}

		var requireTLSServerIsRunning = func(caCrt []byte, addr string, dnsOverrides map[string]string) {
			r.Greater(impersonatorFuncWasCalled, 0)

			realDialer := &net.Dialer{}
			overrideDialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
				replacementAddr, hasKey := dnsOverrides[addr]
				if hasKey {
					t.Logf("DialContext replacing addr %s with %s", addr, replacementAddr)
					addr = replacementAddr
				} else if dnsOverrides != nil {
					t.Fatalf("dnsOverrides was provided but not used, which was probably a mistake. addr %s", addr)
				}
				return realDialer.DialContext(ctx, network, addr)
			}

			var tr *http.Transport
			if caCrt == nil {
				tr = &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, //nolint:gosec // this is used to test when the impersonation proxy does not advertise a CA bundle
						// Client cert which is supposed to work against the server's dynamic CAContentProvider
						Certificates: []tls.Certificate{*validClientCert},
					},
					DialContext: overrideDialContext,
				}
			} else {
				rootCAs := x509.NewCertPool()
				rootCAs.AppendCertsFromPEM(caCrt)
				tr = &http.Transport{
					TLSClientConfig: &tls.Config{ //nolint:gosec // not concerned with TLS MinVersion here
						// Server's TLS serving cert CA
						RootCAs: rootCAs,
						// Client cert which is supposed to work against the server's dynamic CAContentProvider
						Certificates: []tls.Certificate{*validClientCert},
					},
					DialContext: overrideDialContext,
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
			body, err := io.ReadAll(resp.Body)
			r.NoError(resp.Body.Close())
			r.NoError(err)
			r.Equal(fakeServerResponseBody, string(body))

			requireTLSSecretProviderHasLoadedCerts()
		}

		var requireTLSServerIsRunningWithoutCerts = func() {
			r.Greater(impersonatorFuncWasCalled, 0)
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

			requireTLSSecretProviderIsEmpty()
		}

		var requireTLSServerIsNoLongerRunning = func() {
			r.Greater(impersonatorFuncWasCalled, 0)
			var err error
			expectedErrorRegex := "dial tcp .*: connect: connection refused"
			expectedErrorRegexCompiled, err := regexp.Compile(expectedErrorRegex)
			r.NoError(err)
			assert.Eventually(t, func() bool {
				_, err = tls.Dial(
					"tcp",
					testServerAddr(),
					&tls.Config{InsecureSkipVerify: true}, //nolint:gosec
				)
				return err != nil && expectedErrorRegexCompiled.MatchString(err.Error())
			}, 20*time.Second, 50*time.Millisecond)
			r.Error(err)
			r.Regexp(expectedErrorRegex, err.Error())

			requireTLSSecretProviderIsEmpty()
		}

		var requireTLSServerWasNeverStarted = func() {
			r.Equal(0, impersonatorFuncWasCalled)

			requireTLSSecretProviderIsEmpty()
		}

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			// Set this at the last second to allow for injection of server override.
			subject = NewImpersonatorConfigController(
				installedInNamespace,
				credentialIssuerResourceName,
				kubeAPIClient,
				pinnipedAPIClient,
				pinnipedInformers.Config().V1alpha1().CredentialIssuers(),
				kubeInformers.Core().V1().Services(),
				kubeInformers.Core().V1().Secrets(),
				controllerlib.WithInformer,
				impersonationProxyPort,
				loadBalancerServiceName,
				clusterIPServiceName,
				internallyGeneratedTLSServingCertSecretName,
				internallyGeneratedTLSServingCASecretName,
				labels,
				clocktesting.NewFakeClock(frozenNow),
				impersonatorFunc,
				mTLSClientCertCASecretName,
				mTLSClientCertProvider,
				logger,
				fakeExpiringSingletonTokenCacheGet,
			)
			controllerlib.TestWrap(t, subject, func(syncer controllerlib.Syncer) controllerlib.Syncer {
				tlsServingCertDynamicCertProvider = syncer.(*impersonatorConfigController).tlsServingCertDynamicCertProvider
				return syncer
			})

			// Set this at the last second to support calling subject.Name().
			syncContext = &controllerlib.Context{
				Context: cancelContext,
				Name:    subject.Name(),
				Key: controllerlib.Key{
					Name: credentialIssuerResourceName,
				},
				Queue: queue,
			}

			// Must start informers before calling TestRunSynchronously()
			kubeInformers.Start(cancelContext.Done())
			pinnipedInformers.Start(cancelContext.Done())
			controllerlib.TestRunSynchronously(t, subject)
		}

		var addCredentialIssuerToTrackers = func(credIssuer conciergeconfigv1alpha1.CredentialIssuer, informerClient *conciergefake.Clientset, mainClient *conciergefake.Clientset) {
			t.Logf("adding CredentialIssuer %s to informer and main clientsets", credIssuer.Name)
			r.NoError(informerClient.Tracker().Add(&credIssuer))
			r.NoError(mainClient.Tracker().Add(&credIssuer))
		}

		var newSecretWithData = func(resourceName string, data map[string][]byte) *corev1.Secret {
			return &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            resourceName,
					Namespace:       installedInNamespace,
					UID:             "uid-1234", // simulate KAS filling out UID and RV
					ResourceVersion: "rv-5678",
				},
				Data: data,
			}
		}

		var newEmptySecret = func(resourceName string) *corev1.Secret {
			return newSecretWithData(resourceName, map[string][]byte{})
		}

		var newCA = func() *certauthority.CA {
			ca, err := certauthority.New("test CA", 24*time.Hour)
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
			impersonationCert, err := ca.IssueServerCert(dnsNames, []net.IP{net.ParseIP(ip)}, 24*time.Hour)
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

		var newSigningKeySecret = func(resourceName string, certPEM, keyPEM []byte) *corev1.Secret {
			return newSecretWithData(resourceName, map[string][]byte{
				apicerts.CACertificateSecretKey:           certPEM,
				apicerts.CACertificatePrivateKeySecretKey: keyPEM,
			})
		}

		var newLoadBalancerService = func(resourceName string, status corev1.ServiceStatus) *corev1.Service {
			return &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: installedInNamespace,
					Labels:    labels,
				},
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{
						{
							TargetPort: intstr.FromInt(impersonationProxyPort),
							Port:       defaultHTTPSPort,
							Protocol:   corev1.ProtocolTCP,
						},
					},
					Selector: map[string]string{appLabelKey: labels[appLabelKey]},
				},
				Status: status,
			}
		}

		var newClusterIPService = func(resourceName string, status corev1.ServiceStatus, spec corev1.ServiceSpec) *corev1.Service {
			return &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: installedInNamespace,
					Labels:    labels,
				},
				Spec:   spec,
				Status: status,
			}
		}

		// Anytime an object is added/updated/deleted in the informer's client *after* the informer is started, then we
		// need to wait for the informer's cache to asynchronously pick up that change from its "watch".
		// If an object is added to the informer's client *before* the informer is started, then waiting is
		// not needed because the informer's initial "list" will pick up the object.
		var waitForObjectToAppearInInformer = func(obj kubeclient.Object, informer controllerlib.InformerGetter) {
			var objFromInformer any
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

		var waitForClusterScopedObjectToAppearInInformer = func(obj kubeclient.Object, informer controllerlib.InformerGetter) {
			var objFromInformer any
			var exists bool
			var err error
			assert.Eventually(t, func() bool {
				objFromInformer, exists, err = informer.Informer().GetIndexer().GetByKey(obj.GetName())
				return err == nil && exists && reflect.DeepEqual(objFromInformer.(kubeclient.Object), obj)
			}, 30*time.Second, 10*time.Millisecond)
			r.NoError(err)
			r.True(exists, "this object should have existed in informer but didn't: %+v", obj)
			r.Equal(obj, objFromInformer, "was waiting for expected to be found in informer, but found actual")
		}

		// See comment for waitForObjectToAppearInInformer above.
		var waitForObjectToBeDeletedFromInformer = func(resourceName string, informer controllerlib.InformerGetter) {
			var objFromInformer any
			var exists bool
			var err error
			assert.Eventually(t, func() bool {
				objFromInformer, exists, err = informer.Informer().GetIndexer().GetByKey(installedInNamespace + "/" + resourceName)
				return err == nil && !exists
			}, 30*time.Second, 10*time.Millisecond)
			r.NoError(err)
			r.False(exists, "this object should have been deleted from informer but wasn't: %s", objFromInformer)
		}

		var addObjectToKubeInformerAndWait = func(obj kubeclient.Object, informer controllerlib.InformerGetter) {
			r.NoError(kubeInformerClient.Tracker().Add(obj))
			waitForObjectToAppearInInformer(obj, informer)
		}

		var addObjectFromCreateActionToInformerAndWait = func(action coretesting.Action, informer controllerlib.InformerGetter) {
			createdObject, ok := action.(coretesting.CreateAction).GetObject().(kubeclient.Object)
			r.True(ok, "should have been able to cast this action's object to kubeclient.Object: %v", action)

			if secret, ok := createdObject.(*corev1.Secret); ok && len(secret.ResourceVersion) == 0 {
				secret = secret.DeepCopy()
				secret.UID = "uid-1234" // simulate KAS filling out UID and RV
				secret.ResourceVersion = "rv-5678"
				createdObject = secret
			}

			addObjectToKubeInformerAndWait(createdObject, informer)
		}

		var updateCredentialIssuerInInformerAndWait = func(resourceName string, credIssuerSpec conciergeconfigv1alpha1.CredentialIssuerSpec, informer controllerlib.InformerGetter) {
			credIssuersGVR := conciergeconfigv1alpha1.Resource("credentialissuers").WithVersion("v1alpha1")
			credIssuerObj, err := pinnipedInformerClient.Tracker().Get(credIssuersGVR, "", resourceName)
			r.NoError(err, "could not find CredentialIssuer to update for test")

			credIssuer := credIssuerObj.(*conciergeconfigv1alpha1.CredentialIssuer)
			credIssuer = credIssuer.DeepCopy() // don't edit the original from the tracker
			credIssuer.Spec = credIssuerSpec
			r.NoError(pinnipedInformerClient.Tracker().Update(credIssuersGVR, credIssuer, ""))
			waitForClusterScopedObjectToAppearInInformer(credIssuer, informer)
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

		var addClusterIPServiceToTracker = func(resourceName string, clusterIP string, client *kubernetesfake.Clientset) {
			clusterIPService := newClusterIPService(resourceName, corev1.ServiceStatus{}, corev1.ServiceSpec{
				Type:      corev1.ServiceTypeClusterIP,
				ClusterIP: clusterIP,
				Ports: []corev1.ServicePort{
					{
						TargetPort: intstr.FromInt(impersonationProxyPort),
						Port:       defaultHTTPSPort,
						Protocol:   corev1.ProtocolTCP,
					},
				},
				Selector: map[string]string{appLabelKey: labels[appLabelKey]},
			})
			r.NoError(client.Tracker().Add(clusterIPService))
		}

		var addDualStackClusterIPServiceToTracker = func(resourceName string, clusterIP0 string, clusterIP1 string, client *kubernetesfake.Clientset) {
			clusterIPService := newClusterIPService(resourceName, corev1.ServiceStatus{}, corev1.ServiceSpec{
				Type:       corev1.ServiceTypeClusterIP,
				ClusterIP:  clusterIP0,
				ClusterIPs: []string{clusterIP0, clusterIP1},
				Ports: []corev1.ServicePort{
					{
						TargetPort: intstr.FromInt(impersonationProxyPort),
						Port:       defaultHTTPSPort,
						Protocol:   corev1.ProtocolTCP,
					},
				},
				Selector: map[string]string{appLabelKey: labels[appLabelKey]},
			})
			r.NoError(client.Tracker().Add(clusterIPService))
		}

		var addSecretToTrackers = func(secret *corev1.Secret, clients ...*kubernetesfake.Clientset) {
			for _, client := range clients {
				secretCopy := secret.DeepCopy()
				r.NoError(client.Tracker().Add(secretCopy))
			}
		}

		var addServiceToTrackers = func(service *corev1.Service, clients ...*kubernetesfake.Clientset) {
			for _, client := range clients {
				serviceCopy := service.DeepCopy()
				r.NoError(client.Tracker().Add(serviceCopy))
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

		var newSuccessStrategy = func(endpoint string, ca []byte) conciergeconfigv1alpha1.CredentialIssuerStrategy {
			return conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.ImpersonationProxyStrategyType,
				Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
				Reason:         conciergeconfigv1alpha1.ListeningStrategyReason,
				Message:        "impersonation proxy is ready to accept client connections",
				LastUpdateTime: metav1.NewTime(frozenNow),
				Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
					Type: conciergeconfigv1alpha1.ImpersonationProxyFrontendType,
					ImpersonationProxyInfo: &conciergeconfigv1alpha1.ImpersonationProxyInfo{
						Endpoint:                 "https://" + endpoint,
						CertificateAuthorityData: base64.StdEncoding.EncodeToString(ca),
					},
				},
			}
		}

		var newAutoDisabledStrategy = func() conciergeconfigv1alpha1.CredentialIssuerStrategy {
			return conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.ImpersonationProxyStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.DisabledStrategyReason,
				Message:        "automatically determined that impersonation proxy should be disabled",
				LastUpdateTime: metav1.NewTime(frozenNow),
				Frontend:       nil,
			}
		}

		var newManuallyDisabledStrategy = func() conciergeconfigv1alpha1.CredentialIssuerStrategy {
			s := newAutoDisabledStrategy()
			s.Message = "impersonation proxy was explicitly disabled by configuration"
			return s
		}

		var newPendingStrategy = func(msg string) conciergeconfigv1alpha1.CredentialIssuerStrategy {
			return conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.ImpersonationProxyStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.PendingStrategyReason,
				Message:        msg,
				LastUpdateTime: metav1.NewTime(frozenNow),
				Frontend:       nil,
			}
		}

		var newPendingStrategyWaitingForLB = func() conciergeconfigv1alpha1.CredentialIssuerStrategy {
			return newPendingStrategy("waiting for load balancer Service to be assigned IP or hostname")
		}

		var newErrorStrategy = func(msg string) conciergeconfigv1alpha1.CredentialIssuerStrategy {
			return conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.ImpersonationProxyStrategyType,
				Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
				Reason:         conciergeconfigv1alpha1.ErrorDuringSetupStrategyReason,
				Message:        msg,
				LastUpdateTime: metav1.NewTime(frozenNow),
				Frontend:       nil,
			}
		}

		var getCredentialIssuer = func() *conciergeconfigv1alpha1.CredentialIssuer {
			credentialIssuerObj, err := pinnipedAPIClient.Tracker().Get(
				schema.GroupVersionResource{
					Group:    conciergeconfigv1alpha1.SchemeGroupVersion.Group,
					Version:  conciergeconfigv1alpha1.SchemeGroupVersion.Version,
					Resource: "credentialissuers",
				}, "", credentialIssuerResourceName,
			)
			r.NoError(err)
			credentialIssuer, ok := credentialIssuerObj.(*conciergeconfigv1alpha1.CredentialIssuer)
			r.True(ok, "should have been able to cast this obj to CredentialIssuer: %v", credentialIssuerObj)
			return credentialIssuer
		}

		var requireCredentialIssuer = func(expectedStrategy conciergeconfigv1alpha1.CredentialIssuerStrategy) {
			// Rather than looking at the specific API actions on pinnipedAPIClient, we just look
			// at the final result here.
			// This is because the implementation is using a helper from another package to create
			// and update the CredentialIssuer, and the specific API actions performed by that
			// implementation are pretty complex and are already tested by its own unit tests.
			// As long as we get the final result that we wanted then we are happy for the purposes
			// of this test.
			credentialIssuer := getCredentialIssuer()
			r.Equal([]conciergeconfigv1alpha1.CredentialIssuerStrategy{expectedStrategy}, credentialIssuer.Status.Strategies)
		}

		var requireServiceWasDeleted = func(action coretesting.Action, serviceName string) {
			deleteAction, ok := action.(coretesting.DeleteAction)
			r.True(ok, "should have been able to cast this action to DeleteAction: %v", action)
			r.Equal("delete", deleteAction.GetVerb())
			r.Equal(serviceName, deleteAction.GetName())
			r.Equal("services", deleteAction.GetResource().Resource)
		}

		var requireLoadBalancerWasCreated = func(action coretesting.Action) *corev1.Service {
			createAction, ok := action.(coretesting.CreateAction)
			r.True(ok, "should have been able to cast this action to CreateAction: %v", action)
			r.Equal("create", createAction.GetVerb())
			createdLoadBalancerService := createAction.GetObject().(*corev1.Service)
			r.Equal(loadBalancerServiceName, createdLoadBalancerService.Name)
			r.Equal(installedInNamespace, createdLoadBalancerService.Namespace)
			r.Equal(corev1.ServiceTypeLoadBalancer, createdLoadBalancerService.Spec.Type)
			r.Equal("app-name", createdLoadBalancerService.Spec.Selector["app"])
			r.Equal(labels, createdLoadBalancerService.Labels)
			return createdLoadBalancerService
		}

		var requireLoadBalancerWasUpdated = func(action coretesting.Action) *corev1.Service {
			updateAction, ok := action.(coretesting.UpdateAction)
			r.True(ok, "should have been able to cast this action to UpdateAction: %v", action)
			r.Equal("update", updateAction.GetVerb())
			updatedLoadBalancerService := updateAction.GetObject().(*corev1.Service)
			r.Equal(loadBalancerServiceName, updatedLoadBalancerService.Name)
			r.Equal(installedInNamespace, updatedLoadBalancerService.Namespace)
			r.Equal(corev1.ServiceTypeLoadBalancer, updatedLoadBalancerService.Spec.Type)
			r.Equal("app-name", updatedLoadBalancerService.Spec.Selector["app"])
			r.Equal(labels, updatedLoadBalancerService.Labels)
			return updatedLoadBalancerService
		}

		var requireClusterIPWasCreated = func(action coretesting.Action) *corev1.Service {
			createAction, ok := action.(coretesting.CreateAction)
			r.True(ok, "should have been able to cast this action to CreateAction: %v", action)
			r.Equal("create", createAction.GetVerb())
			createdClusterIPService := createAction.GetObject().(*corev1.Service)
			r.Equal(clusterIPServiceName, createdClusterIPService.Name)
			r.Equal(corev1.ServiceTypeClusterIP, createdClusterIPService.Spec.Type)
			r.Equal("app-name", createdClusterIPService.Spec.Selector["app"])
			r.Equal(labels, createdClusterIPService.Labels)
			return createdClusterIPService
		}

		var requireClusterIPWasUpdated = func(action coretesting.Action) *corev1.Service {
			updateAction, ok := action.(coretesting.UpdateAction)
			r.True(ok, "should have been able to cast this action to UpdateAction: %v", action)
			r.Equal("update", updateAction.GetVerb())
			updatedLoadBalancerService := updateAction.GetObject().(*corev1.Service)
			r.Equal(clusterIPServiceName, updatedLoadBalancerService.Name)
			r.Equal(installedInNamespace, updatedLoadBalancerService.Namespace)
			r.Equal(corev1.ServiceTypeClusterIP, updatedLoadBalancerService.Spec.Type)
			r.Equal("app-name", updatedLoadBalancerService.Spec.Selector["app"])
			r.Equal(labels, updatedLoadBalancerService.Labels)
			return updatedLoadBalancerService
		}

		var requireTLSSecretWasDeleted = func(action coretesting.Action) {
			deleteAction, ok := action.(coretesting.DeleteAction)
			r.True(ok, "should have been able to cast this action to DeleteAction: %v", action)
			r.Equal("delete", deleteAction.GetVerb())
			r.Equal(internallyGeneratedTLSServingCertSecretName, deleteAction.GetName())
			r.Equal("secrets", deleteAction.GetResource().Resource)

			// validate that we set delete preconditions correctly
			r.Equal(testutil.NewPreconditions("uid-1234", "rv-5678"), deleteAction.GetDeleteOptions())
		}

		var requireCASecretWasCreated = func(action coretesting.Action) []byte {
			createAction, ok := action.(coretesting.CreateAction)
			r.True(ok, "should have been able to cast this action to CreateAction: %v", action)
			r.Equal("create", createAction.GetVerb())
			createdSecret := createAction.GetObject().(*corev1.Secret)
			r.Equal(internallyGeneratedTLSServingCASecretName, createdSecret.Name)
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
			require.Equal(t, "Pinniped Impersonation Proxy Serving CA", caCert.Subject.CommonName)
			require.WithinDuration(t, time.Now().Add(-5*time.Minute), caCert.NotBefore, 10*time.Second)
			require.WithinDuration(t, time.Now().Add(100*time.Hour*24*365), caCert.NotAfter, 10*time.Second)
			return createdCertPEM
		}

		var requireTLSSecretWasCreated = func(action coretesting.Action, caCert []byte) {
			createAction, ok := action.(coretesting.CreateAction)
			r.True(ok, "should have been able to cast this action to CreateAction: %v", action)
			r.Equal("create", createAction.GetVerb())
			createdSecret := createAction.GetObject().(*corev1.Secret)
			r.Equal(internallyGeneratedTLSServingCertSecretName, createdSecret.Name)
			r.Equal(installedInNamespace, createdSecret.Namespace)
			r.Equal(corev1.SecretTypeTLS, createdSecret.Type)
			r.Equal(labels, createdSecret.Labels)
			r.Len(createdSecret.Data, 2)
			createdCertPEM := createdSecret.Data[corev1.TLSCertKey]
			createdKeyPEM := createdSecret.Data[corev1.TLSPrivateKeyKey]
			r.NotNil(createdKeyPEM)
			r.NotNil(createdCertPEM)
			validCert := testutil.ValidateServerCertificate(t, string(caCert), string(createdCertPEM))
			validCert.RequireMatchesPrivateKey(string(createdKeyPEM))
			validCert.RequireLifetime(time.Now().Add(-5*time.Minute), time.Now().Add(100*time.Hour*24*365), 10*time.Second)
		}

		var requireMTLSClientCertProviderHasLoadedCerts = func(certPEM, keyPEM []byte) {
			actualCert, actualKey := mTLSClientCertProvider.CurrentCertKeyContent()
			// Cast to string for better failure messages.
			r.Equal(string(certPEM), string(actualCert))
			r.Equal(string(keyPEM), string(actualKey))
		}

		var requireMTLSClientCertProviderIsEmpty = func() {
			actualCert, actualKey := mTLSClientCertProvider.CurrentCertKeyContent()
			r.Nil(actualCert)
			r.Nil(actualKey)
		}

		var runControllerSync = func() error {
			return controllerlib.TestSync(t, subject, *syncContext)
		}

		it.Before(func() {
			r = require.New(t)
			queue = &testQueue{}
			cancelContext, cancelContextCancelFunc = context.WithCancel(context.Background())

			pinnipedInformerClient = conciergefake.NewSimpleClientset()
			pinnipedInformers = conciergeinformers.NewSharedInformerFactoryWithOptions(pinnipedInformerClient, 0)

			kubeInformerClient = kubernetesfake.NewSimpleClientset()
			kubeInformers = k8sinformers.NewSharedInformerFactoryWithOptions(kubeInformerClient, 0,
				k8sinformers.WithNamespace(installedInNamespace),
			)
			kubeAPIClient = kubernetesfake.NewSimpleClientset()
			pinnipedAPIClient = conciergefake.NewSimpleClientset()
			frozenNow = time.Date(2021, time.March, 2, 7, 42, 0, 0, time.Local)
			mTLSClientCertProvider = dynamiccert.NewCA(name)

			mTLSClientCertCA := newCA()
			mTLSClientCertCACertPEM = mTLSClientCertCA.Bundle()
			var err error
			mTLSClientCertCAPrivateKeyPEM, err = mTLSClientCertCA.PrivateKeyToPEM()
			r.NoError(err)
			mTLSClientCertCASecret = newSigningKeySecret(mTLSClientCertCASecretName, mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
			validClientCert, err = mTLSClientCertCA.IssueClientCert("username", nil, time.Hour)
			r.NoError(err)

			externalCA = newCA()
			externalTLSSecret = newActualTLSSecret(externalCA, externallyProvidedTLSSecretName, localhostIP)
		})

		it.After(func() {
			cancelContextCancelFunc()
			closeTestHTTPServer()
		})

		when("the CredentialIssuer does not yet exist or it was deleted (sync returns an error)", func() {
			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
			})

			when("there are visible control plane nodes and a loadbalancer and a tls Secret", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("control-plane", kubeAPIClient)
					addLoadBalancerServiceToTracker(loadBalancerServiceName, kubeInformerClient)
					addLoadBalancerServiceToTracker(loadBalancerServiceName, kubeAPIClient)
					addSecretToTrackers(newEmptySecret(internallyGeneratedTLSServingCertSecretName), kubeAPIClient, kubeInformerClient)
				})

				it("errors and does nothing else", func() {
					startInformersAndController()
					r.EqualError(runControllerSync(), `could not get CredentialIssuer to update: credentialissuer.config.concierge.pinniped.dev "some-credential-issuer-resource-name" not found`)
					requireTLSServerWasNeverStarted()
					r.Len(kubeAPIClient.Actions(), 0)
				})
			})
		})

		when("the configuration is auto mode with an endpoint and service type none", func() {
			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
							ExternalEndpoint: localhostIP,
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
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
					requireMTLSClientCertProviderIsEmpty()
				})
			})

			when("there are not visible control plane nodes", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
				})

				it("starts the impersonator according to the settings in the CredentialIssuer", func() {
					startInformersAndController()
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
					requireTLSServerIsRunning(ca, testServerAddr(), nil)
					requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})
		})

		when("using external TLS secrets", func() {
			when("the configuration is auto mode with an endpoint and service type none", func() {
				it.Before(func() {
					addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
					addSecretToTrackers(externalTLSSecret, kubeInformerClient)
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
								ExternalEndpoint: localhostIP,
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
								},
								TLS: &conciergeconfigv1alpha1.ImpersonationProxyTLSSpec{
									CertificateAuthorityData: base64.StdEncoding.EncodeToString(externalCA.Bundle()),
									SecretName:               externallyProvidedTLSSecretName,
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
				})

				when("there are not visible control plane nodes", func() {
					it.Before(func() {
						addNodeWithRoleToTracker("worker", kubeAPIClient)
					})

					it("starts the impersonator according to the settings in the CredentialIssuer", func() {
						startInformersAndController()
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 1)
						requireNodesListed(kubeAPIClient.Actions()[0])
						requireTLSServerIsRunning(externalCA.Bundle(), testServerAddr(), nil)
						requireCredentialIssuer(newSuccessStrategy(localhostIP, externalCA.Bundle()))
						requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
					})

					when("there is an existing generated TLS secret", func() {
						it.Before(func() {
							addSecretToTrackers(newEmptySecret(internallyGeneratedTLSServingCertSecretName), kubeInformerClient)
						})

						it("removes the existing generated TLS secret", func() {
							startInformersAndController()
							r.NoError(runControllerSync())
							r.Len(kubeAPIClient.Actions(), 2)
							requireNodesListed(kubeAPIClient.Actions()[0])
							requireTLSSecretWasDeleted(kubeAPIClient.Actions()[1])
							requireTLSServerIsRunning(externalCA.Bundle(), testServerAddr(), nil)
							requireCredentialIssuer(newSuccessStrategy(localhostIP, externalCA.Bundle()))
							requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
						})
					})
				})
			})

			when("the CertificateAuthorityData is configured with invalid data", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
				})

				when("CertificateAuthorityData is not base64 encoded", func() {
					it.Before(func() {
						addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
						addSecretToTrackers(externalTLSSecret, kubeInformerClient)
						addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
							ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
							Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
								ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
									Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
									ExternalEndpoint: localhostIP,
									Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
										Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
									},
									TLS: &conciergeconfigv1alpha1.ImpersonationProxyTLSSpec{
										CertificateAuthorityData: string(externalCA.Bundle()),
										SecretName:               externallyProvidedTLSSecretName,
									},
								},
							},
						}, pinnipedInformerClient, pinnipedAPIClient)
					})

					it("returns an error", func() {
						startInformersAndController()
						r.Error(runControllerSync(), "could not decode impersonationSpec.TLS.certificateAuthorityData: illegal base64 data at input byte 0")
						r.Len(kubeAPIClient.Actions(), 1)
						requireNodesListed(kubeAPIClient.Actions()[0])
						requireCredentialIssuer(newErrorStrategy("could not decode impersonationSpec.TLS.certificateAuthorityData: illegal base64 data at input byte 0"))
						requireMTLSClientCertProviderHasLoadedCerts([]byte{}, []byte{})
					})
				})

				when("CertificateAuthorityData is not a cert", func() {
					it.Before(func() {
						addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
						addSecretToTrackers(externalTLSSecret, kubeInformerClient)
						addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
							ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
							Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
								ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
									Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
									ExternalEndpoint: localhostIP,
									Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
										Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
									},
									TLS: &conciergeconfigv1alpha1.ImpersonationProxyTLSSpec{
										CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte("hello")),
										SecretName:               externallyProvidedTLSSecretName,
									},
								},
							},
						}, pinnipedInformerClient, pinnipedAPIClient)
					})

					it("returns an error", func() {
						startInformersAndController()
						r.Error(runControllerSync(), "could not decode impersonationSpec.TLS.certificateAuthorityData: data is not a certificate")
						r.Len(kubeAPIClient.Actions(), 1)
						requireNodesListed(kubeAPIClient.Actions()[0])
						requireCredentialIssuer(newErrorStrategy("could not decode impersonationSpec.TLS.certificateAuthorityData: data is not a certificate"))
						requireMTLSClientCertProviderHasLoadedCerts([]byte{}, []byte{})
					})
				})
			})

			when("the CertificateAuthorityData is not configured", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
				})

				when("the externally provided TLS secret has a ca.crt field", func() {
					it.Before(func() {
						addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
						externalTLSSecret.Data["ca.crt"] = externalCA.Bundle()
						addSecretToTrackers(externalTLSSecret, kubeInformerClient)
						addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
							ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
							Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
								ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
									Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
									ExternalEndpoint: localhostIP,
									Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
										Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
									},
									TLS: &conciergeconfigv1alpha1.ImpersonationProxyTLSSpec{
										SecretName: externallyProvidedTLSSecretName,
									},
								},
							},
						}, pinnipedInformerClient, pinnipedAPIClient)
					})

					it("will advertise ca.crt from the externally provided secret", func() {
						startInformersAndController()
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 1)
						requireNodesListed(kubeAPIClient.Actions()[0])
						requireTLSServerIsRunning(externalCA.Bundle(), testServerAddr(), nil)
						requireCredentialIssuer(newSuccessStrategy(localhostIP, externalCA.Bundle()))
						requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
					})
				})

				when("the externally provided TLS secret has a ca.crt field that is not a valid cert", func() {
					it.Before(func() {
						addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
						externalTLSSecret.Data["ca.crt"] = []byte("hello")
						addSecretToTrackers(externalTLSSecret, kubeInformerClient)
						addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
							ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
							Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
								ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
									Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
									ExternalEndpoint: localhostIP,
									Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
										Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
									},
									TLS: &conciergeconfigv1alpha1.ImpersonationProxyTLSSpec{
										SecretName: externallyProvidedTLSSecretName,
									},
								},
							},
						}, pinnipedInformerClient, pinnipedAPIClient)
					})

					it("returns an error", func() {
						startInformersAndController()
						r.Error(runControllerSync(), "could not load the externally provided TLS secret for the impersonation proxy: unable to read provided ca.crt: data is not a certificate")
						r.Len(kubeAPIClient.Actions(), 1)
						requireNodesListed(kubeAPIClient.Actions()[0])
						requireCredentialIssuer(newErrorStrategy("could not load the externally provided TLS secret for the impersonation proxy: unable to read provided ca.crt: data is not a certificate"))
						requireMTLSClientCertProviderHasLoadedCerts([]byte{}, []byte{})
					})
				})

				when("the externally provided TLS secret does not have a ca.crt field", func() {
					it.Before(func() {
						addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
						addSecretToTrackers(externalTLSSecret, kubeInformerClient)
						addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
							ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
							Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
								ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
									Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
									ExternalEndpoint: localhostIP,
									Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
										Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
									},
									TLS: &conciergeconfigv1alpha1.ImpersonationProxyTLSSpec{
										SecretName: externallyProvidedTLSSecretName,
									},
								},
							},
						}, pinnipedInformerClient, pinnipedAPIClient)
					})

					it("will advertise an empty CA bundle", func() {
						startInformersAndController()
						r.NoError(runControllerSync())
						r.Len(kubeAPIClient.Actions(), 1)
						requireNodesListed(kubeAPIClient.Actions()[0])
						requireTLSServerIsRunning(nil, testServerAddr(), nil)
						requireCredentialIssuer(newSuccessStrategy(localhostIP, nil))
						requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
					})
				})
			})
		})

		when("the configuration is auto mode", func() {
			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
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
					requireMTLSClientCertProviderIsEmpty()
				})
			})

			when("there are visible control plane nodes and a loadbalancer and a tls Secret", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("control-plane", kubeAPIClient)
					addLoadBalancerServiceToTracker(loadBalancerServiceName, kubeInformerClient)
					addLoadBalancerServiceToTracker(loadBalancerServiceName, kubeAPIClient)
					addSecretToTrackers(newEmptySecret(internallyGeneratedTLSServingCertSecretName), kubeAPIClient, kubeInformerClient)
				})

				it("does not start the impersonator, deletes the loadbalancer, deletes the Secret", func() {
					startInformersAndController()
					r.NoError(runControllerSync())
					requireTLSServerWasNeverStarted()
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireServiceWasDeleted(kubeAPIClient.Actions()[1], loadBalancerServiceName)
					requireTLSSecretWasDeleted(kubeAPIClient.Actions()[2])
					requireCredentialIssuer(newAutoDisabledStrategy())
					requireMTLSClientCertProviderIsEmpty()
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
					requireCredentialIssuer(newPendingStrategyWaitingForLB())
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
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
					requireCredentialIssuer(newPendingStrategyWaitingForLB())
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
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
					requireCredentialIssuer(newPendingStrategyWaitingForLB())
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
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
					requireMTLSClientCertProviderIsEmpty()
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
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Secrets())
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

					// keeps the secret around after resync
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 3) // nothing changed
					requireCredentialIssuer(newSuccessStrategy(fakeIP, ca))
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
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
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Secrets())
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

					// keeps the secret around after resync
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 3) // nothing changed
					requireCredentialIssuer(newSuccessStrategy(firstHostname, ca))
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
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
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Secrets())
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

					// keeps the secret around after resync
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 3) // nothing changed
					requireCredentialIssuer(newSuccessStrategy(firstHostname, ca))
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})

			when("there are not visible control plane nodes, a TLS secret exists with multiple hostnames and an IP", func() {
				var caCrt []byte
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeAPIClient)
					ca := newCA()
					caSecret := newActualCASecret(ca, internallyGeneratedTLSServingCASecretName)
					caCrt = caSecret.Data["ca.crt"]
					addSecretToTrackers(caSecret, kubeAPIClient, kubeInformerClient)
					addSecretToTrackers(newActualTLSSecretWithMultipleHostnames(ca, internallyGeneratedTLSServingCertSecretName, localhostIP), kubeAPIClient, kubeInformerClient)
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
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})

			when("the cert's name needs to change but there is an error while deleting the tls Secret", func() {
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "127.0.0.42"}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "127.0.0.42"}}, kubeAPIClient)
					ca := newCA()
					addSecretToTrackers(newActualCASecret(ca, internallyGeneratedTLSServingCASecretName), kubeAPIClient, kubeInformerClient)
					addSecretToTrackers(newActualTLSSecretWithMultipleHostnames(ca, internallyGeneratedTLSServingCertSecretName, localhostIP), kubeAPIClient, kubeInformerClient)
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
					requireMTLSClientCertProviderIsEmpty()
				})
			})

			when("the cert's name might need to change but there is an error while determining the new name", func() {
				var caCrt []byte
				it.Before(func() {
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformerClient)
					addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeAPIClient)
					ca := newCA()
					caSecret := newActualCASecret(ca, internallyGeneratedTLSServingCASecretName)
					caCrt = caSecret.Data["ca.crt"]
					addSecretToTrackers(caSecret, kubeAPIClient, kubeInformerClient)
					tlsSecret := newActualTLSSecret(ca, internallyGeneratedTLSServingCertSecretName, localhostIP)
					addSecretToTrackers(tlsSecret, kubeAPIClient, kubeInformerClient)
				})

				it("returns an error and keeps the proxy running but now without certs", func() {
					startInformersAndController()
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 1)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireTLSServerIsRunning(caCrt, testServerAddr(), nil)

					updateLoadBalancerServiceInInformerAndWait(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: "not-an-ip"}}, kubeInformers.Core().V1().Services())

					errString := "could not find valid IP addresses or hostnames from load balancer some-namespace/some-service-resource-name"
					r.EqualError(runControllerSync(), errString)
					r.Len(kubeAPIClient.Actions(), 1)                       // no new actions
					requireTLSServerIsRunning(caCrt, testServerAddr(), nil) // serving certificate is not unloaded in this case
					requireCredentialIssuer(newErrorStrategy(errString))
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})
		})

		when("the configuration is disabled mode", func() {
			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeDisabled,
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
			})

			it("does not start the impersonator", func() {
				startInformersAndController()
				r.NoError(runControllerSync())
				requireTLSServerWasNeverStarted()
				requireNodesListed(kubeAPIClient.Actions()[0])
				r.Len(kubeAPIClient.Actions(), 1)
				requireCredentialIssuer(newManuallyDisabledStrategy())
				requireMTLSClientCertProviderIsEmpty()
			})
		})

		when("the configuration is enabled mode", func() {
			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
			})
			when("no load balancer", func() {
				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
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
					requireCredentialIssuer(newPendingStrategyWaitingForLB())
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})

				it("returns an error when the impersonation TLS server fails to start", func() {
					impersonatorFuncError = errors.New("impersonation server start error")
					startInformersAndController()
					r.EqualError(runControllerSync(), "impersonation server start error")
					requireCredentialIssuer(newErrorStrategy("impersonation server start error"))
					requireMTLSClientCertProviderIsEmpty()
				})
			})

			when("a loadbalancer already exists", func() {
				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
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
					requireCredentialIssuer(newPendingStrategyWaitingForLB())
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})

				it("returns an error when the impersonation TLS server fails to start", func() {
					impersonatorFuncError = errors.New("impersonation server start error")
					startInformersAndController()
					r.EqualError(runControllerSync(), "impersonation server start error")
					requireCredentialIssuer(newErrorStrategy("impersonation server start error"))
					requireMTLSClientCertProviderIsEmpty()
				})
			})

			when("a clusterip already exists with ingress", func() {
				const fakeIP = "127.0.0.123"
				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP,
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					addClusterIPServiceToTracker(clusterIPServiceName, fakeIP, kubeInformerClient)
					addClusterIPServiceToTracker(clusterIPServiceName, fakeIP, kubeAPIClient)
				})

				it("starts the impersonator without creating a clusterip", func() {
					startInformersAndController()
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
					requireTLSServerIsRunning(ca, fakeIP, map[string]string{fakeIP + ":443": testServerAddr()})
					requireCredentialIssuer(newSuccessStrategy(fakeIP, ca))
					// requireMTLSClientCertProviderHasLoadedCerts()
				})
			})

			when("a clusterip service exists with dual stack ips", func() {
				const fakeIP1 = "127.0.0.123"
				const fakeIP2 = "fd00::5118"
				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP,
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					addDualStackClusterIPServiceToTracker(clusterIPServiceName, fakeIP1, fakeIP2, kubeInformerClient)
					addDualStackClusterIPServiceToTracker(clusterIPServiceName, fakeIP1, fakeIP2, kubeAPIClient)
				})

				it("certs are valid for both ip addresses", func() {
					startInformersAndController()
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
					requireTLSServerIsRunning(ca, "["+fakeIP2+"]", map[string]string{"[fd00::5118]:443": testServerAddr()})
					requireTLSServerIsRunning(ca, fakeIP1, map[string]string{fakeIP1 + ":443": testServerAddr()})
					requireCredentialIssuer(newSuccessStrategy(fakeIP1, ca))
				})
			})

			when("a load balancer and a secret already exists", func() {
				var caCrt []byte
				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
					addNodeWithRoleToTracker("worker", kubeAPIClient)
					ca := newCA()
					caSecret := newActualCASecret(ca, internallyGeneratedTLSServingCASecretName)
					caCrt = caSecret.Data["ca.crt"]
					addSecretToTrackers(caSecret, kubeAPIClient, kubeInformerClient)
					tlsSecret := newActualTLSSecret(ca, internallyGeneratedTLSServingCertSecretName, localhostIP)
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
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})

			when("credentialissuer has service type loadbalancer and custom annotations", func() {
				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type:        conciergeconfigv1alpha1.ImpersonationProxyServiceTypeLoadBalancer,
									Annotations: map[string]string{"some-annotation-key": "some-annotation-value"},
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
					addNodeWithRoleToTracker("worker", kubeAPIClient)
				})

				it("starts the impersonator, generates a valid cert for the specified hostname, starts a loadbalancer", func() {
					startInformersAndController()
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					lbService := requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
					require.Equal(t, lbService.Annotations, map[string]string{
						"some-annotation-key":                           "some-annotation-value",
						"credentialissuer.pinniped.dev/annotation-keys": `["some-annotation-key"]`,
					})
					requireCASecretWasCreated(kubeAPIClient.Actions()[2])
					requireTLSServerIsRunningWithoutCerts()
					requireCredentialIssuer(newPendingStrategyWaitingForLB())
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})

			when("the CredentialIssuer has a hostname specified and service type none", func() {
				const fakeHostname = "fake.example.com"
				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
								ExternalEndpoint: fakeHostname,
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
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
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})

			when("the CredentialIssuer has a hostname specified and service type loadbalancer", func() {
				const fakeHostname = "fake.example.com"
				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
								ExternalEndpoint: fakeHostname,
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeLoadBalancer,
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
					addNodeWithRoleToTracker("worker", kubeAPIClient)
				})

				it("starts the impersonator, generates a valid cert for the specified hostname, starts a loadbalancer", func() {
					startInformersAndController()
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 4)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
					ca := requireCASecretWasCreated(kubeAPIClient.Actions()[2])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[3], ca)
					// Check that the server is running and that TLS certs that are being served are are for fakeHostname.
					requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + httpsPort: testServerAddr()})
					requireCredentialIssuer(newSuccessStrategy(fakeHostname, ca))
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})

			when("the CredentialIssuer has a hostname specified and service type clusterip", func() {
				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP,
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
					addNodeWithRoleToTracker("worker", kubeAPIClient)
				})

				it("starts the impersonator and creates a clusterip service", func() {
					startInformersAndController()
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireClusterIPWasCreated(kubeAPIClient.Actions()[1])
					requireCASecretWasCreated(kubeAPIClient.Actions()[2])
					// Check that the server is running without certs.
					requireTLSServerIsRunningWithoutCerts()
					requireCredentialIssuer(newPendingStrategyWaitingForLB())
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})

			when("the CredentialIssuer has a endpoint which is an IP address with a port", func() {
				const fakeIPWithPort = "127.0.0.1:3000"
				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
								ExternalEndpoint: fakeIPWithPort,
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
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
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})

			when("the CredentialIssuer has a endpoint which is a hostname with a port, service type none", func() {
				const fakeHostnameWithPort = "fake.example.com:3000"
				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
								ExternalEndpoint: fakeHostnameWithPort,
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
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
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})

			when("the CredentialIssuer has a endpoint which is a hostname with a port, service type loadbalancer with loadbalancerip", func() {
				const fakeHostnameWithPort = "fake.example.com:3000"
				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
								ExternalEndpoint: fakeHostnameWithPort,
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type:           conciergeconfigv1alpha1.ImpersonationProxyServiceTypeLoadBalancer,
									LoadBalancerIP: localhostIP,
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
					addNodeWithRoleToTracker("worker", kubeAPIClient)
				})

				it("starts the impersonator, starts the loadbalancer, generates a valid cert for the specified hostname", func() {
					startInformersAndController()
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 4)
					requireNodesListed(kubeAPIClient.Actions()[0])
					lbService := requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
					require.Equal(t, lbService.Spec.LoadBalancerIP, localhostIP)
					ca := requireCASecretWasCreated(kubeAPIClient.Actions()[2])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[3], ca)
					// Check that the server is running and that TLS certs that are being served are are for fakeHostnameWithPort.
					requireTLSServerIsRunning(ca, fakeHostnameWithPort, map[string]string{fakeHostnameWithPort: testServerAddr()})
					requireCredentialIssuer(newSuccessStrategy(fakeHostnameWithPort, ca))
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})

			when("switching the CredentialIssuer from ip address endpoint to hostname endpoint and back to ip address", func() {
				const fakeHostname = "fake.example.com"
				const fakeIP = "127.0.0.42"

				var hostnameConfig = conciergeconfigv1alpha1.CredentialIssuerSpec{
					ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
						Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
						ExternalEndpoint: fakeHostname,
						Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
							Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
						},
					},
				}
				var ipAddressConfig = conciergeconfigv1alpha1.CredentialIssuerSpec{
					ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
						Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
						ExternalEndpoint: fakeIP,
						Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
							Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
						},
					},
				}

				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec:       ipAddressConfig,
					}, pinnipedInformerClient, pinnipedAPIClient)
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
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Secrets())
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

					// Switch the endpoint config to a hostname.
					updateCredentialIssuerInInformerAndWait(credentialIssuerResourceName, hostnameConfig, pinnipedInformers.Config().V1alpha1().CredentialIssuers())

					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 5)
					requireTLSSecretWasDeleted(kubeAPIClient.Actions()[3])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[4], ca) // reuses the old CA
					// Check that the server is running and that TLS certs that are being served are are for fakeHostname.
					requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + httpsPort: testServerAddr()})
					requireCredentialIssuer(newSuccessStrategy(fakeHostname, ca))
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

					// Simulate the informer cache's background update from its watch.
					deleteSecretFromTracker(internallyGeneratedTLSServingCertSecretName, kubeInformerClient)
					waitForObjectToBeDeletedFromInformer(internallyGeneratedTLSServingCertSecretName, kubeInformers.Core().V1().Secrets())
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[4], kubeInformers.Core().V1().Secrets())

					// Switch the endpoint config back to an IP.
					updateCredentialIssuerInInformerAndWait(credentialIssuerResourceName, ipAddressConfig, pinnipedInformers.Config().V1alpha1().CredentialIssuers())

					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 7)
					requireTLSSecretWasDeleted(kubeAPIClient.Actions()[5])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[6], ca) // reuses the old CA again
					// Check that the server is running and that TLS certs that are being served are are for fakeIP.
					requireTLSServerIsRunning(ca, fakeIP, map[string]string{fakeIP + httpsPort: testServerAddr()})
					requireCredentialIssuer(newSuccessStrategy(fakeIP, ca))
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})

			when("the TLS cert goes missing and needs to be recreated, e.g. when a user manually deleted it", func() {
				const fakeHostname = "fake.example.com"
				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
								ExternalEndpoint: fakeHostname,
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
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
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Secrets())

					// Delete the TLS Secret that was just created from the Kube API server. Note that we never
					// simulated it getting added to the informer cache, so we don't need to remove it from there.
					deleteSecretFromTracker(internallyGeneratedTLSServingCertSecretName, kubeAPIClient)

					// Run again. It should create a new TLS cert using the old CA cert.
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 4)
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[3], ca)
					// Check that the server is running and that TLS certs that are being served are are for fakeHostname.
					requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + httpsPort: testServerAddr()})
					requireCredentialIssuer(newSuccessStrategy(fakeHostname, ca))
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})

			when("the CA cert goes missing and needs to be recreated, e.g. when a user manually deleted it", func() {
				const fakeHostname = "fake.example.com"
				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
								ExternalEndpoint: fakeHostname,
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
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
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

					// Delete the CA Secret that was just created from the Kube API server. Note that we never
					// simulated it getting added to the informer cache, so we don't need to remove it from there.
					deleteSecretFromTracker(internallyGeneratedTLSServingCASecretName, kubeAPIClient)

					// Run again. It should create both a new CA cert and a new TLS cert using the new CA cert.
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 6)
					ca = requireCASecretWasCreated(kubeAPIClient.Actions()[3])
					requireTLSSecretWasDeleted(kubeAPIClient.Actions()[4])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[5], ca) // created using the new CA
					// Check that the server is running and that TLS certs that are being served are are for fakeHostname.
					requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + httpsPort: testServerAddr()})
					requireCredentialIssuer(newSuccessStrategy(fakeHostname, ca))
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})

			when("the CA cert is overwritten by another valid CA cert", func() {
				const fakeHostname = "fake.example.com"
				var caCrt []byte
				it.Before(func() {
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
								ExternalEndpoint: fakeHostname,
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
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
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

					// Simulate someone updating the CA Secret out of band, e.g. when a human edits it with kubectl.
					// Delete the CA Secret that was just created from the Kube API server. Note that we never
					// simulated it getting added to the informer cache, so we don't need to remove it from there.
					// Then add a new one. Delete + new = update, since only the final state is observed.
					deleteSecretFromTracker(internallyGeneratedTLSServingCASecretName, kubeAPIClient)
					anotherCA := newCA()
					newCASecret := newActualCASecret(anotherCA, internallyGeneratedTLSServingCASecretName)
					caCrt = newCASecret.Data["ca.crt"]
					addSecretToTrackers(newCASecret, kubeAPIClient)
					addObjectToKubeInformerAndWait(newCASecret, kubeInformers.Core().V1().Secrets())
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
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})

				when("deleting the TLS cert due to mismatched CA results in an error", func() {
					it.Before(func() {
						kubeAPIClient.PrependReactor("delete", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
							if action.(coretesting.DeleteAction).GetName() == internallyGeneratedTLSServingCertSecretName {
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
						requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
					})
				})
			})
		})

		when("the configuration switches from enabled to disabled mode", func() {
			when("service type loadbalancer", func() {
				it.Before(func() {
					addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
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
					requireCredentialIssuer(newPendingStrategyWaitingForLB())
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM) // load when enabled

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Services())
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

					// Update the CredentialIssuer.
					updateCredentialIssuerInInformerAndWait(credentialIssuerResourceName, conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeDisabled,
						},
					}, pinnipedInformers.Config().V1alpha1().CredentialIssuers())

					r.NoError(runControllerSync())
					requireTLSServerIsNoLongerRunning()
					r.Len(kubeAPIClient.Actions(), 4)
					requireServiceWasDeleted(kubeAPIClient.Actions()[3], loadBalancerServiceName)
					requireCredentialIssuer(newManuallyDisabledStrategy())
					requireMTLSClientCertProviderIsEmpty() // only unload when disabled

					deleteServiceFromTracker(loadBalancerServiceName, kubeInformerClient)
					waitForObjectToBeDeletedFromInformer(loadBalancerServiceName, kubeInformers.Core().V1().Services())

					// Update the CredentialIssuer again.
					updateCredentialIssuerInInformerAndWait(credentialIssuerResourceName, conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
						},
					}, pinnipedInformers.Config().V1alpha1().CredentialIssuers())

					r.NoError(runControllerSync())
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 5)
					requireLoadBalancerWasCreated(kubeAPIClient.Actions()[4])
					requireCredentialIssuer(newPendingStrategyWaitingForLB())
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM) // load again when enabled
				})
			})

			when("service type clusterip", func() {
				it.Before(func() {
					addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP,
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
					addNodeWithRoleToTracker("worker", kubeAPIClient)
				})

				it("starts the impersonator and clusterip, then shuts it down, then starts it again", func() {
					startInformersAndController()

					r.NoError(runControllerSync())
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					requireClusterIPWasCreated(kubeAPIClient.Actions()[1])
					requireCASecretWasCreated(kubeAPIClient.Actions()[2])
					requireCredentialIssuer(newPendingStrategyWaitingForLB())
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM) // load when enabled

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Services())
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

					// Update the CredentialIssuer.
					updateCredentialIssuerInInformerAndWait(credentialIssuerResourceName, conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeDisabled,
						},
					}, pinnipedInformers.Config().V1alpha1().CredentialIssuers())

					r.NoError(runControllerSync())
					requireTLSServerIsNoLongerRunning()
					r.Len(kubeAPIClient.Actions(), 4)
					requireServiceWasDeleted(kubeAPIClient.Actions()[3], clusterIPServiceName)
					requireCredentialIssuer(newManuallyDisabledStrategy())
					requireMTLSClientCertProviderIsEmpty() // only unload when disabled

					deleteServiceFromTracker(clusterIPServiceName, kubeInformerClient)
					waitForObjectToBeDeletedFromInformer(clusterIPServiceName, kubeInformers.Core().V1().Services())

					// Update the CredentialIssuer again.
					updateCredentialIssuerInInformerAndWait(credentialIssuerResourceName, conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP,
							},
						},
					}, pinnipedInformers.Config().V1alpha1().CredentialIssuers())

					r.NoError(runControllerSync())
					requireTLSServerIsRunningWithoutCerts()
					r.Len(kubeAPIClient.Actions(), 5)
					requireClusterIPWasCreated(kubeAPIClient.Actions()[4])
					requireCredentialIssuer(newPendingStrategyWaitingForLB())
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM) // load again when enabled
				})
			})

			when("service type none with a hostname", func() {
				const fakeHostname = "hello.com"
				it.Before(func() {
					addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
								ExternalEndpoint: fakeHostname,
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
					addNodeWithRoleToTracker("worker", kubeAPIClient)
				})

				it("starts the impersonator, then shuts it down, then starts it again", func() {
					startInformersAndController()

					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
					requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + httpsPort: testServerAddr()})
					requireCredentialIssuer(newSuccessStrategy(fakeHostname, ca))

					// load when enabled
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
					requireTLSSecretProviderHasLoadedCerts()

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Secrets())
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

					// Update the CredentialIssuer.
					updateCredentialIssuerInInformerAndWait(credentialIssuerResourceName, conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeDisabled,
						},
					}, pinnipedInformers.Config().V1alpha1().CredentialIssuers())

					r.NoError(runControllerSync())
					requireTLSServerIsNoLongerRunning()
					r.Len(kubeAPIClient.Actions(), 4)
					requireTLSSecretWasDeleted(kubeAPIClient.Actions()[3])
					requireCredentialIssuer(newManuallyDisabledStrategy())

					// only unload when disabled
					requireMTLSClientCertProviderIsEmpty()
					requireTLSSecretProviderIsEmpty()

					deleteSecretFromTracker(internallyGeneratedTLSServingCertSecretName, kubeInformerClient)
					waitForObjectToBeDeletedFromInformer(internallyGeneratedTLSServingCertSecretName, kubeInformers.Core().V1().Secrets())

					// Update the CredentialIssuer again.
					updateCredentialIssuerInInformerAndWait(credentialIssuerResourceName, conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							ExternalEndpoint: fakeHostname,
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
							},
						},
					}, pinnipedInformers.Config().V1alpha1().CredentialIssuers())

					r.NoError(runControllerSync())
					requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + httpsPort: testServerAddr()})
					r.Len(kubeAPIClient.Actions(), 5)
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[4], ca)
					requireCredentialIssuer(newSuccessStrategy(fakeHostname, ca))

					// load again when enabled
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
					requireTLSSecretProviderHasLoadedCerts()
				})
			})
		})

		when("the endpoint and mode switch from specified with no service, to not specified, to specified again", func() {
			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							ExternalEndpoint: localhostIP,
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
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
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Secrets())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

				// Switch to "enabled" mode without an "endpoint", so a load balancer is needed now.
				updateCredentialIssuerInInformerAndWait(credentialIssuerResourceName, conciergeconfigv1alpha1.CredentialIssuerSpec{
					ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
						Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
					},
				}, pinnipedInformers.Config().V1alpha1().CredentialIssuers())

				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 5)
				requireLoadBalancerWasCreated(kubeAPIClient.Actions()[3])
				requireTLSSecretWasDeleted(kubeAPIClient.Actions()[4]) // the Secret was deleted because it contained a cert with the wrong IP
				requireTLSServerIsRunning(ca, testServerAddr(), nil)   // serving certificate is not unloaded in this case
				requireCredentialIssuer(newPendingStrategyWaitingForLB())
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[3], kubeInformers.Core().V1().Services())
				deleteSecretFromTracker(internallyGeneratedTLSServingCertSecretName, kubeInformerClient)
				waitForObjectToBeDeletedFromInformer(internallyGeneratedTLSServingCertSecretName, kubeInformers.Core().V1().Secrets())

				// The controller should be waiting for the load balancer's ingress to become available.
				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 5)                    // no new actions while it is waiting for the load balancer's ingress
				requireTLSServerIsRunning(ca, testServerAddr(), nil) // serving certificate is not unloaded in this case
				requireCredentialIssuer(newPendingStrategyWaitingForLB())
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Update the ingress of the LB in the informer's client and run Sync again.
				fakeIP := "127.0.0.123"
				updateLoadBalancerServiceInInformerAndWait(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: fakeIP}}, kubeInformers.Core().V1().Services())
				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 6)
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[5], ca) // reuses the existing CA
				// Check that the server is running and that TLS certs that are being served are are for fakeIP.
				requireTLSServerIsRunning(ca, fakeIP, map[string]string{fakeIP + httpsPort: testServerAddr()})
				requireCredentialIssuer(newSuccessStrategy(fakeIP, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[5], kubeInformers.Core().V1().Secrets())

				// Now switch back to having the "endpoint" specified and explicitly saying that we don't want the load balancer service.
				updateCredentialIssuerInInformerAndWait(credentialIssuerResourceName, conciergeconfigv1alpha1.CredentialIssuerSpec{
					ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
						Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
						ExternalEndpoint: localhostIP,
						Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
							Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
						},
					},
				}, pinnipedInformers.Config().V1alpha1().CredentialIssuers())

				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 9)
				requireServiceWasDeleted(kubeAPIClient.Actions()[6], loadBalancerServiceName)
				requireTLSSecretWasDeleted(kubeAPIClient.Actions()[7])
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[8], ca) // recreated because the endpoint was updated, reused the old CA
				requireTLSServerIsRunning(ca, testServerAddr(), nil)
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
			})
		})

		when("requesting a load balancer via CredentialIssuer, then updating the annotations", func() {
			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							ExternalEndpoint: localhostIP,
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeLoadBalancer,
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
			})

			it("creates the load balancer without annotations, then adds them", func() {
				startInformersAndController()

				// Should have started in "enabled" mode with service type load balancer, so one is created.
				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 4)
				requireNodesListed(kubeAPIClient.Actions()[0])
				lbService := requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
				require.Equal(t, map[string]string(nil), lbService.Annotations) // there should be no annotations at first
				ca := requireCASecretWasCreated(kubeAPIClient.Actions()[2])
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[3], ca)
				requireTLSServerIsRunning(ca, testServerAddr(), nil)
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Simulate another actor in the system, like a human user or a non-Pinniped controller,
				// updating the new Service's annotations. The map was nil, so we can overwrite the whole thing,
				lbService.Annotations = map[string]string{
					"annotation-from-unrelated-controller-key": "annotation-from-unrelated-controller-val",
					"my-annotation-key":                        "my-annotation-from-unrelated-controller-val",
				}

				// Simulate the informer cache's background update from its watch.
				addObjectToKubeInformerAndWait(lbService, kubeInformers.Core().V1().Services())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[3], kubeInformers.Core().V1().Secrets())

				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 4) // no new actions because the controller decides there is nothing to update on the Service

				// Add annotations to the CredentialIssuer spec.
				credentialIssuerAnnotations := map[string]string{"my-annotation-key": "my-annotation-val"}
				updateCredentialIssuerInInformerAndWait(credentialIssuerResourceName, conciergeconfigv1alpha1.CredentialIssuerSpec{
					ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
						Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
						ExternalEndpoint: localhostIP,
						Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
							Type:        conciergeconfigv1alpha1.ImpersonationProxyServiceTypeLoadBalancer,
							Annotations: credentialIssuerAnnotations,
						},
					},
				}, pinnipedInformers.Config().V1alpha1().CredentialIssuers())

				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 5) // one more item to update the loadbalancer
				lbService = requireLoadBalancerWasUpdated(kubeAPIClient.Actions()[4])
				require.Equal(t, map[string]string{
					// Now the CredentialIssuer annotations should be merged on the load balancer.
					// In the unlikely case where keys conflict, the CredentialIssuer value overwrites the other value.
					// Otherwise the annotations from the other actor should not be modified.
					"annotation-from-unrelated-controller-key":      "annotation-from-unrelated-controller-val",
					"my-annotation-key":                             "my-annotation-val",
					"credentialissuer.pinniped.dev/annotation-keys": `["my-annotation-key"]`,
				}, lbService.Annotations)
				requireTLSServerIsRunning(ca, testServerAddr(), nil)
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
			})
		})

		when("requesting a cluster ip via CredentialIssuer, then updating the annotations", func() {
			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							ExternalEndpoint: localhostIP,
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP,
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
			})

			it("creates the cluster ip without annotations, then adds them", func() {
				startInformersAndController()

				// Should have started in "enabled" mode with service type load balancer, so one is created.
				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 4)
				requireNodesListed(kubeAPIClient.Actions()[0])
				clusterIPService := requireClusterIPWasCreated(kubeAPIClient.Actions()[1])
				require.Equal(t, map[string]string(nil), clusterIPService.Annotations) // there should be no annotations at first
				ca := requireCASecretWasCreated(kubeAPIClient.Actions()[2])
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[3], ca)
				requireTLSServerIsRunning(ca, testServerAddr(), nil)
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Simulate another actor in the system, like a human user or a non-Pinniped controller,
				// updating the new Service's annotations.
				clusterIPService.Annotations = map[string]string{
					"annotation-from-unrelated-controller-key": "annotation-from-unrelated-controller-val",
					"my-annotation-key":                        "my-annotation-from-unrelated-controller-val",
				}

				// Simulate the informer cache's background update from its watch.
				addObjectToKubeInformerAndWait(clusterIPService, kubeInformers.Core().V1().Services())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[3], kubeInformers.Core().V1().Secrets())

				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 4) // no new actions because the controller decides there is nothing to update on the Service

				// Add annotations to the CredentialIssuer spec.
				credentialIssuerAnnotations := map[string]string{"my-annotation-key": "my-annotation-val"}
				updateCredentialIssuerInInformerAndWait(credentialIssuerResourceName, conciergeconfigv1alpha1.CredentialIssuerSpec{
					ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
						Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
						ExternalEndpoint: localhostIP,
						Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
							Type:        conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP,
							Annotations: credentialIssuerAnnotations,
						},
					},
				}, pinnipedInformers.Config().V1alpha1().CredentialIssuers())

				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 5) // one more item to update the loadbalancer
				clusterIPService = requireClusterIPWasUpdated(kubeAPIClient.Actions()[4])
				require.Equal(t, map[string]string{
					// Now the CredentialIssuer annotations should be merged on the load balancer.
					// In the unlikely case where keys conflict, the CredentialIssuer value overwrites the other value.
					// Otherwise the annotations from the other actor should not be modified.
					"annotation-from-unrelated-controller-key":      "annotation-from-unrelated-controller-val",
					"my-annotation-key":                             "my-annotation-val",
					"credentialissuer.pinniped.dev/annotation-keys": `["my-annotation-key"]`,
				}, clusterIPService.Annotations)
				requireTLSServerIsRunning(ca, testServerAddr(), nil)
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
			})
		})

		when("requesting a load balancer via CredentialIssuer with annotations, then updating the CredentialIssuer annotations to remove one", func() {
			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							ExternalEndpoint: localhostIP,
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeLoadBalancer,
								Annotations: map[string]string{
									"my-initial-annotation1-key": "my-initial-annotation1-val",
									"my-initial-annotation2-key": "my-initial-annotation2-val",
									"my-initial-annotation3-key": "my-initial-annotation3-val",
								},
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
			})

			it("creates the load balancer with annotations, then removes the removed annotation", func() {
				startInformersAndController()

				// Should have started in "enabled" mode with service type load balancer, so one is created.
				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 4)
				requireNodesListed(kubeAPIClient.Actions()[0])
				lbService := requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
				require.Equal(t, map[string]string{
					"my-initial-annotation1-key":                    "my-initial-annotation1-val",
					"my-initial-annotation2-key":                    "my-initial-annotation2-val",
					"my-initial-annotation3-key":                    "my-initial-annotation3-val",
					"credentialissuer.pinniped.dev/annotation-keys": `["my-initial-annotation1-key","my-initial-annotation2-key","my-initial-annotation3-key"]`,
				}, lbService.Annotations) // there should be some annotations at first
				ca := requireCASecretWasCreated(kubeAPIClient.Actions()[2])
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[3], ca)
				requireTLSServerIsRunning(ca, testServerAddr(), nil)
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Simulate another actor in the system, like a human user or a non-Pinniped controller,
				// updating the new Service to add another annotation.
				lbService.Annotations["annotation-from-unrelated-controller-key"] = "annotation-from-unrelated-controller-val"

				// Simulate the informer cache's background update from its watch.
				addObjectToKubeInformerAndWait(lbService, kubeInformers.Core().V1().Services())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[3], kubeInformers.Core().V1().Secrets())

				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 4) // no new actions because the controller decides there is nothing to update on the Service

				// Remove one of the annotations from the CredentialIssuer spec.
				updateCredentialIssuerInInformerAndWait(credentialIssuerResourceName, conciergeconfigv1alpha1.CredentialIssuerSpec{
					ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
						Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
						ExternalEndpoint: localhostIP,
						Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
							Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeLoadBalancer,
							Annotations: map[string]string{
								"my-initial-annotation1-key": "my-initial-annotation1-val",
								"my-initial-annotation3-key": "my-initial-annotation3-val",
							},
						},
					},
				}, pinnipedInformers.Config().V1alpha1().CredentialIssuers())

				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 5) // one more item to update the loadbalancer
				lbService = requireLoadBalancerWasUpdated(kubeAPIClient.Actions()[4])
				require.Equal(t, map[string]string{
					// Now the CredentialIssuer annotations should be merged on the load balancer.
					// Since the user removed the "my-initial-annotation2-key" key from the CredentialIssuer spec,
					// it should be removed from the Service.
					// The annotations from the other actor should not be modified.
					"annotation-from-unrelated-controller-key":      "annotation-from-unrelated-controller-val",
					"my-initial-annotation1-key":                    "my-initial-annotation1-val",
					"my-initial-annotation3-key":                    "my-initial-annotation3-val",
					"credentialissuer.pinniped.dev/annotation-keys": `["my-initial-annotation1-key","my-initial-annotation3-key"]`,
				}, lbService.Annotations)
				requireTLSServerIsRunning(ca, testServerAddr(), nil)
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Remove all the rest of the annotations from the CredentialIssuer spec so there are none remaining.
				updateCredentialIssuerInInformerAndWait(credentialIssuerResourceName, conciergeconfigv1alpha1.CredentialIssuerSpec{
					ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
						Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
						ExternalEndpoint: localhostIP,
						Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
							Type:        conciergeconfigv1alpha1.ImpersonationProxyServiceTypeLoadBalancer,
							Annotations: map[string]string{},
						},
					},
				}, pinnipedInformers.Config().V1alpha1().CredentialIssuers())

				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 6) // one more item to update the loadbalancer
				lbService = requireLoadBalancerWasUpdated(kubeAPIClient.Actions()[5])
				require.Equal(t, map[string]string{
					// Since the user removed all annotations from the CredentialIssuer spec,
					// they should all be removed from the Service, along with the special bookkeeping annotation too.
					// The annotations from the other actor should not be modified.
					"annotation-from-unrelated-controller-key": "annotation-from-unrelated-controller-val",
				}, lbService.Annotations)
				requireTLSServerIsRunning(ca, testServerAddr(), nil)
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
			})
		})

		when("requesting a load balancer via CredentialIssuer, but there is already a load balancer with an invalid bookkeeping annotation value", func() {
			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							ExternalEndpoint: localhostIP,
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type:        conciergeconfigv1alpha1.ImpersonationProxyServiceTypeLoadBalancer,
								Annotations: map[string]string{"some-annotation": "annotation-value"},
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				// Add a Service with a messed up bookkeeping annotation.
				loadBalancerService := newLoadBalancerService(loadBalancerServiceName, corev1.ServiceStatus{})
				loadBalancerService.Annotations = map[string]string{
					annotationKeysKey: `["this is not valid json`,
				}
				addServiceToTrackers(loadBalancerService, kubeInformerClient, kubeAPIClient)
			})

			it("just acts like the annotation wasn't present since that is better than becoming inoperable", func() {
				startInformersAndController()

				// Should have started in "enabled" mode with service type load balancer, so one is created.
				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 4)
				requireNodesListed(kubeAPIClient.Actions()[0])
				lbService := requireLoadBalancerWasUpdated(kubeAPIClient.Actions()[1])
				require.Equal(t, map[string]string{
					"some-annotation": "annotation-value",
					"credentialissuer.pinniped.dev/annotation-keys": `["some-annotation"]`,
				}, lbService.Annotations)
				ca := requireCASecretWasCreated(kubeAPIClient.Actions()[2])
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[3], ca)
				requireTLSServerIsRunning(ca, testServerAddr(), nil)
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
			})
		})

		when("requesting a load balancer via CredentialIssuer, then adding a static loadBalancerIP to the spec", func() {
			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							ExternalEndpoint: localhostIP,
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeLoadBalancer,
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
			})

			it("creates the load balancer without loadBalancerIP set, then adds it", func() {
				startInformersAndController()

				// Should have started in "enabled" mode with service type load balancer, so one is created.
				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 4)
				requireNodesListed(kubeAPIClient.Actions()[0])
				lbService := requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
				require.Equal(t, map[string]string(nil), lbService.Annotations) // there should be no annotations at first
				require.Equal(t, "", lbService.Spec.LoadBalancerIP)
				ca := requireCASecretWasCreated(kubeAPIClient.Actions()[2])
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[3], ca)
				requireTLSServerIsRunning(ca, testServerAddr(), nil)
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Services())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[3], kubeInformers.Core().V1().Secrets())

				// Add annotations to the spec.
				loadBalancerIP := "1.2.3.4"
				updateCredentialIssuerInInformerAndWait(credentialIssuerResourceName, conciergeconfigv1alpha1.CredentialIssuerSpec{
					ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
						Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
						ExternalEndpoint: localhostIP,
						Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
							Type:           conciergeconfigv1alpha1.ImpersonationProxyServiceTypeLoadBalancer,
							LoadBalancerIP: loadBalancerIP,
						},
					},
				}, pinnipedInformers.Config().V1alpha1().CredentialIssuers())

				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 5) // one more item to update the loadbalancer
				lbService = requireLoadBalancerWasUpdated(kubeAPIClient.Actions()[4])
				require.Equal(t, loadBalancerIP, lbService.Spec.LoadBalancerIP)
				requireTLSServerIsRunning(ca, testServerAddr(), nil)
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
			})
		})

		when("sync is called more than once", func() {
			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
			})

			it("only starts the impersonator once and only lists the cluster's nodes once", func() {
				startInformersAndController()
				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
				requireCASecretWasCreated(kubeAPIClient.Actions()[2])
				requireTLSServerIsRunningWithoutCerts()
				requireCredentialIssuer(newPendingStrategyWaitingForLB())
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Services())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

				r.NoError(runControllerSync())
				r.Equal(1, impersonatorFuncWasCalled)   // wasn't started a second time
				requireTLSServerIsRunningWithoutCerts() // still running
				requireCredentialIssuer(newPendingStrategyWaitingForLB())
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
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
				requireCredentialIssuer(newPendingStrategyWaitingForLB())
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Services())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

				updateLoadBalancerServiceInInformerAndWait(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformers.Core().V1().Services())

				r.NoError(runControllerSync())
				r.Equal(1, impersonatorFuncWasCalled) // wasn't started a second time
				r.Len(kubeAPIClient.Actions(), 4)
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[3], ca) // uses the ca from last time
				requireTLSServerIsRunning(ca, testServerAddr(), nil)       // running with certs now
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[3], kubeInformers.Core().V1().Secrets())

				r.NoError(runControllerSync())
				r.Equal(1, impersonatorFuncWasCalled)                // wasn't started again
				r.Len(kubeAPIClient.Actions(), 4)                    // no more actions
				requireTLSServerIsRunning(ca, testServerAddr(), nil) // still running
				requireCredentialIssuer(newSuccessStrategy(localhostIP, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
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
				requireCredentialIssuer(newPendingStrategyWaitingForLB())
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Services())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

				updateLoadBalancerServiceInInformerAndWait(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP, Hostname: hostname}}, kubeInformers.Core().V1().Services())

				r.NoError(runControllerSync())
				r.Equal(1, impersonatorFuncWasCalled) // wasn't started a second time
				r.Len(kubeAPIClient.Actions(), 4)
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[3], ca)                                         // uses the ca from last time
				requireTLSServerIsRunning(ca, hostname, map[string]string{hostname + httpsPort: testServerAddr()}) // running with certs now
				requireCredentialIssuer(newSuccessStrategy(hostname, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[3], kubeInformers.Core().V1().Secrets())

				r.NoError(runControllerSync())
				r.Equal(1, impersonatorFuncWasCalled)                                                              // wasn't started a third time
				r.Len(kubeAPIClient.Actions(), 4)                                                                  // no more actions
				requireTLSServerIsRunning(ca, hostname, map[string]string{hostname + httpsPort: testServerAddr()}) // still running
				requireCredentialIssuer(newSuccessStrategy(hostname, ca))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
			})
		})

		when("there is already a CredentialIssuer", func() {
			preExistingStrategy := conciergeconfigv1alpha1.CredentialIssuerStrategy{
				Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
				Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
				Reason:         conciergeconfigv1alpha1.FetchedKeyStrategyReason,
				Message:        "happy other unrelated strategy",
				LastUpdateTime: metav1.NewTime(frozenNow),
				Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
					Type: conciergeconfigv1alpha1.TokenCredentialRequestAPIFrontendType,
				},
			}

			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
						},
					},
					Status: conciergeconfigv1alpha1.CredentialIssuerStatus{
						Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{
							preExistingStrategy,
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
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
				r.Equal([]conciergeconfigv1alpha1.CredentialIssuerStrategy{preExistingStrategy, newPendingStrategyWaitingForLB()}, credentialIssuer.Status.Strategies)
			})
		})

		when("getting the control plane nodes returns an error, e.g. when there are no nodes", func() {
			it("returns an error", func() {
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				startInformersAndController()
				r.EqualError(runControllerSync(), "no nodes found")
				requireCredentialIssuer(newErrorStrategy("no nodes found"))
				requireMTLSClientCertProviderIsEmpty()
				requireTLSServerWasNeverStarted()
			})
		})

		when("the impersonator start function returned by the impersonatorFunc returns an error immediately", func() {
			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				impersonatorFuncReturnedFuncError = errors.New("some immediate impersonator startup error")
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
			})

			it("causes an immediate resync, returns an error on that next sync, and then restarts the server in a following sync", func() {
				startInformersAndController()
				// The failure happens in a background goroutine, so the first sync succeeds.
				r.NoError(runControllerSync())
				// The imperonatorFunc was called to construct an impersonator.
				r.Equal(impersonatorFuncWasCalled, 1)
				// Without waiting too long because we don't want the test to be slow, check if it seems like the
				// server never started.
				r.Never(func() bool {
					testHTTPServerMutex.RLock() // this is to satisfy the race detector
					defer testHTTPServerMutex.RUnlock()
					return testHTTPServer != nil
				}, 2*time.Second, 50*time.Millisecond)
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
				requireCASecretWasCreated(kubeAPIClient.Actions()[2])
				requireCredentialIssuer(newPendingStrategyWaitingForLB())
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Services())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

				// The controller's first sync should have started a background routine which, when the server dies,
				// requests to re-enqueue the original sync key to cause its sync method to get called again in the near future.
				r.Eventually(func() bool {
					queue.mutex.RLock() // this is to satisfy the race detector
					defer queue.mutex.RUnlock()
					return syncContext.Key == queue.key
				}, 10*time.Second, 10*time.Millisecond)

				// The next sync should error because the server died in the background. This second
				// sync should be able to detect the error and return it.
				r.EqualError(runControllerSync(), "some immediate impersonator startup error")
				requireCredentialIssuer(newErrorStrategy("some immediate impersonator startup error"))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Next time the controller starts the server, the server will start successfully.
				impersonatorFuncReturnedFuncError = nil

				// One more sync and the controller should try to restart the server.
				// Now everything should be working correctly.
				r.NoError(runControllerSync())
				requireTLSServerIsRunningWithoutCerts()
				requireCredentialIssuer(newPendingStrategyWaitingForLB())
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
			})
		})

		when("the impersonator server dies for no apparent reason after running for a while", func() {
			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
			})

			it("causes an immediate resync, returns an error on that next sync, and then restarts the server in a following sync", func() {
				// Prepare to be able to cause the server to die for no apparent reason.
				testHTTPServerInterruptCh = make(chan struct{})

				startInformersAndController()
				r.NoError(runControllerSync())
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireLoadBalancerWasCreated(kubeAPIClient.Actions()[1])
				requireCASecretWasCreated(kubeAPIClient.Actions()[2])
				requireCredentialIssuer(newPendingStrategyWaitingForLB())
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				requireTLSServerIsRunningWithoutCerts()

				// Simulate the informer cache's background update from its watch.
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Services())
				addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

				// Simulate that impersonation server dies for no apparent reason.
				close(testHTTPServerInterruptCh)

				// The controller's first sync should have started a background routine which, when the server dies,
				// requests to re-enqueue the original sync key to cause its sync method to get called again in the near future.
				r.Eventually(func() bool {
					queue.mutex.RLock() // this is to satisfy the race detector
					defer queue.mutex.RUnlock()
					return syncContext.Key == queue.key
				}, 10*time.Second, 10*time.Millisecond)

				// The next sync should error because the server died in the background. This second
				// sync should be able to detect the error and return it.
				r.EqualError(runControllerSync(), "unexpected shutdown of proxy server")
				requireCredentialIssuer(newErrorStrategy("unexpected shutdown of proxy server"))
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

				// Next time the controller starts the server, the server should behave as normal.
				testHTTPServerInterruptCh = nil

				// One more sync and the controller should try to restart the server.
				// Now everything should be working correctly.
				r.NoError(runControllerSync())
				requireTLSServerIsRunningWithoutCerts()
				requireCredentialIssuer(newPendingStrategyWaitingForLB())
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
			})
		})

		when("the CredentialIssuer has nil impersonation spec", func() {
			it.Before(func() {
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: nil,
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
			})

			it("returns an error", func() {
				startInformersAndController()
				errString := `could not load CredentialIssuer: spec.impersonationProxy is nil`
				r.EqualError(runControllerSync(), errString)
				requireCredentialIssuer(newErrorStrategy(errString))
				requireMTLSClientCertProviderIsEmpty()
				requireTLSServerWasNeverStarted()
			})
		})

		when("the CredentialIssuer has invalid mode", func() {
			it.Before(func() {
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: "not-valid",
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
			})

			it("returns an error", func() {
				startInformersAndController()
				errString := `could not load CredentialIssuer spec.impersonationProxy: invalid proxy mode "not-valid" (expected auto, disabled, or enabled)`
				r.EqualError(runControllerSync(), errString)
				requireCredentialIssuer(newErrorStrategy(errString))
				requireMTLSClientCertProviderIsEmpty()
				requireTLSServerWasNeverStarted()
			})
		})

		when("the CredentialIssuer has invalid service type", func() {
			it.Before(func() {
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type: "not-valid",
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
			})

			it("returns an error", func() {
				startInformersAndController()
				errString := `could not load CredentialIssuer spec.impersonationProxy: invalid service type "not-valid" (expected None, LoadBalancer, or ClusterIP)`
				r.EqualError(runControllerSync(), errString)
				requireCredentialIssuer(newErrorStrategy(errString))
				requireMTLSClientCertProviderIsEmpty()
				requireTLSServerWasNeverStarted()
			})
		})

		when("the CredentialIssuer has invalid LoadBalancerIP", func() {
			it.Before(func() {
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								LoadBalancerIP: "invalid-ip-address",
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
			})

			it("returns an error", func() {
				startInformersAndController()
				errString := `could not load CredentialIssuer spec.impersonationProxy: invalid LoadBalancerIP "invalid-ip-address"`
				r.EqualError(runControllerSync(), errString)
				requireCredentialIssuer(newErrorStrategy(errString))
				requireMTLSClientCertProviderIsEmpty()
				requireTLSServerWasNeverStarted()
			})
		})

		when("the CredentialIssuer has invalid ExternalEndpoint", func() {
			it.Before(func() {
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							ExternalEndpoint: "[invalid",
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
			})

			it("returns an error", func() {
				startInformersAndController()
				errString := `could not load CredentialIssuer spec.impersonationProxy: invalid ExternalEndpoint "[invalid": address [invalid:443: missing ']' in address`
				r.EqualError(runControllerSync(), errString)
				requireCredentialIssuer(newErrorStrategy(errString))
				requireMTLSClientCertProviderIsEmpty()
				requireTLSServerWasNeverStarted()
			})
		})

		when("there is an error creating the load balancer", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				kubeAPIClient.PrependReactor("create", "services", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, apierrors.NewAlreadyExists(
						action.GetResource().GroupResource(),
						action.(coretesting.CreateAction).GetObject().(*corev1.Service).Name,
					)
				})
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
			})

			it("returns an error", func() {
				startInformersAndController()
				r.EqualError(runControllerSync(), `services "some-service-resource-name" already exists`)
				requireCredentialIssuer(newPendingStrategy(`services "some-service-resource-name" already exists`))
				requireMTLSClientCertProviderIsEmpty()
				requireTLSServerIsRunningWithoutCerts()
			})
		})

		when("there is an error deleting the load balancer", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				kubeAPIClient.PrependReactor("delete", "services", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("error on delete")
				})
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeDisabled,
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				addLoadBalancerServiceToTracker(loadBalancerServiceName, kubeAPIClient)
				addLoadBalancerServiceToTracker(loadBalancerServiceName, kubeInformerClient)
			})

			it("returns an error", func() {
				startInformersAndController()
				r.EqualError(runControllerSync(), "error on delete")
				requireCredentialIssuer(newErrorStrategy("error on delete"))
				requireMTLSClientCertProviderIsEmpty()
			})
		})

		when("there is an error creating the cluster ip", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				kubeAPIClient.PrependReactor("create", "services", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("error on create")
				})
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP,
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
			})

			it("returns an error", func() {
				startInformersAndController()
				r.EqualError(runControllerSync(), "error on create")
				requireCredentialIssuer(newErrorStrategy("error on create"))
				requireMTLSClientCertProviderIsEmpty()
				requireTLSServerIsRunningWithoutCerts()
			})
		})

		when("there is an error updating the cluster ip", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				kubeAPIClient.PrependReactor("update", "services", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("error on update")
				})
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type:        conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP,
								Annotations: map[string]string{"key": "val"},
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				addClusterIPServiceToTracker(clusterIPServiceName, localhostIP, kubeAPIClient)
				addClusterIPServiceToTracker(clusterIPServiceName, localhostIP, kubeInformerClient)
			})

			it("returns an error", func() {
				startInformersAndController()
				r.EqualError(runControllerSync(), "error on update")
				requireCredentialIssuer(newErrorStrategy("error on update"))
				requireMTLSClientCertProviderIsEmpty()
				requireTLSServerIsRunningWithoutCerts()
			})
		})

		when("there is an error deleting the cluster ip", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				kubeAPIClient.PrependReactor("delete", "services", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("error on delete")
				})
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeDisabled,
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				addClusterIPServiceToTracker(clusterIPServiceName, localhostIP, kubeAPIClient)
				addClusterIPServiceToTracker(clusterIPServiceName, localhostIP, kubeInformerClient)
			})

			it("returns an error", func() {
				startInformersAndController()
				r.EqualError(runControllerSync(), "error on delete")
				requireCredentialIssuer(newErrorStrategy("error on delete"))
				requireMTLSClientCertProviderIsEmpty()
			})
		})

		when("there is an error creating the tls secret", func() {
			it.Before(func() {
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							ExternalEndpoint: "example.com",
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				addNodeWithRoleToTracker("control-plane", kubeAPIClient)
				kubeAPIClient.PrependReactor("create", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					createdSecret := action.(coretesting.CreateAction).GetObject().(*corev1.Secret)
					if createdSecret.Name == internallyGeneratedTLSServingCertSecretName {
						return true, nil, fmt.Errorf("error on tls secret create")
					}
					return false, nil, nil
				})
			})

			it("starts the impersonator without certs and returns an error", func() {
				startInformersAndController()
				r.EqualError(runControllerSync(), "error on tls secret create")
				requireCredentialIssuer(newErrorStrategy("error on tls secret create"))
				requireMTLSClientCertProviderIsEmpty()
				requireTLSServerIsRunningWithoutCerts()
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
				requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
			})
		})

		when("there is an error creating the CA secret", func() {
			it.Before(func() {
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							ExternalEndpoint: "example.com",
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				addNodeWithRoleToTracker("control-plane", kubeAPIClient)
				kubeAPIClient.PrependReactor("create", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					createdSecret := action.(coretesting.CreateAction).GetObject().(*corev1.Secret)
					if createdSecret.Name == internallyGeneratedTLSServingCASecretName {
						return true, nil, fmt.Errorf("error on ca secret create")
					}
					return false, nil, nil
				})
			})

			it("starts the impersonator without certs and returns an error", func() {
				startInformersAndController()
				r.EqualError(runControllerSync(), "error on ca secret create")
				requireCredentialIssuer(newErrorStrategy("error on ca secret create"))
				requireMTLSClientCertProviderIsEmpty()
				requireTLSServerIsRunningWithoutCerts()
				r.Len(kubeAPIClient.Actions(), 2)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireCASecretWasCreated(kubeAPIClient.Actions()[1])
			})
		})

		when("the CA secret exists but is invalid while the TLS secret needs to be created", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("control-plane", kubeAPIClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							ExternalEndpoint: "example.com",
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				addSecretToTrackers(newEmptySecret(internallyGeneratedTLSServingCASecretName), kubeAPIClient, kubeInformerClient)
			})

			it("starts the impersonator without certs and returns an error", func() {
				startInformersAndController()
				errString := "could not load CA: tls: failed to find any PEM data in certificate input"
				r.EqualError(runControllerSync(), errString)
				requireCredentialIssuer(newErrorStrategy(errString))
				requireMTLSClientCertProviderIsEmpty()
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
				addSecretToTrackers(newEmptySecret(internallyGeneratedTLSServingCertSecretName), kubeAPIClient, kubeInformerClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				startInformersAndController()
				kubeAPIClient.PrependReactor("delete", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("error on delete")
				})
			})

			it("does not start the impersonator, deletes the loadbalancer, returns an error", func() {
				r.EqualError(runControllerSync(), "error on delete")
				requireCredentialIssuer(newErrorStrategy("error on delete"))
				requireMTLSClientCertProviderIsEmpty()
				requireTLSServerWasNeverStarted()
				r.Len(kubeAPIClient.Actions(), 3)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireServiceWasDeleted(kubeAPIClient.Actions()[1], loadBalancerServiceName)
				requireTLSSecretWasDeleted(kubeAPIClient.Actions()[2])
			})
		})

		when("deleting the tls secret when informer and api are out of sync", func() {
			it.Before(func() {
				addNodeWithRoleToTracker("control-plane", kubeAPIClient)
				addSecretToTrackers(newEmptySecret(internallyGeneratedTLSServingCertSecretName), kubeInformerClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeDisabled,
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
			})

			it("does not pass the not found error through", func() {
				startInformersAndController()
				r.NoError(runControllerSync())
				requireTLSServerWasNeverStarted()
				r.Len(kubeAPIClient.Actions(), 2)
				requireNodesListed(kubeAPIClient.Actions()[0])
				requireTLSSecretWasDeleted(kubeAPIClient.Actions()[1])
				requireCredentialIssuer(newManuallyDisabledStrategy())
				requireMTLSClientCertProviderIsEmpty()
			})
		})

		when("the PEM formatted data in the TLS Secret is not a valid cert", func() {
			it.Before(func() {
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							ExternalEndpoint: localhostIP,
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				tlsSecret := newSecretWithData(internallyGeneratedTLSServingCertSecretName, map[string][]byte{
					// "aGVsbG8gd29ybGQK" is "hello world" base64 encoded which is not a valid cert
					corev1.TLSCertKey: []byte("-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQK\n-----END CERTIFICATE-----\n"),
				})
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
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
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
					requireMTLSClientCertProviderIsEmpty()
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
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				ca := newCA()
				caSecret := newActualCASecret(ca, internallyGeneratedTLSServingCASecretName)
				caCrt = caSecret.Data["ca.crt"]
				addSecretToTrackers(caSecret, kubeAPIClient, kubeInformerClient)
				addSecretToTrackers(newEmptySecret(internallyGeneratedTLSServingCertSecretName), kubeAPIClient, kubeInformerClient) // secret exists but lacks certs
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
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
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
					requireMTLSClientCertProviderIsEmpty()
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
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				ca := newCA()
				caSecret := newActualCASecret(ca, internallyGeneratedTLSServingCASecretName)
				caCrt = caSecret.Data["ca.crt"]
				addSecretToTrackers(caSecret, kubeAPIClient, kubeInformerClient)
				tlsSecret := newActualTLSSecret(ca, internallyGeneratedTLSServingCertSecretName, localhostIP)
				tlsSecret.Data["tls.key"] = nil
				addSecretToTrackers(tlsSecret, kubeAPIClient, kubeInformerClient)
				addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeInformerClient)
				addLoadBalancerServiceWithIngressToTracker(loadBalancerServiceName, []corev1.LoadBalancerIngress{{IP: localhostIP}}, kubeAPIClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
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
				requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
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
					requireMTLSClientCertProviderIsEmpty()
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
				addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode: conciergeconfigv1alpha1.ImpersonationProxyModeAuto,
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				pinnipedAPIClient.PrependReactor("update", "credentialissuers", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("error on update")
				})
			})

			it("returns the error", func() {
				startInformersAndController()
				r.EqualError(runControllerSync(), "failed to update CredentialIssuer status: error on update")
			})

			when("there is also a more fundamental error while starting the impersonator", func() {
				it.Before(func() {
					kubeAPIClient.PrependReactor("create", "services", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, fmt.Errorf("error on service creation")
					})
				})

				it("returns both errors", func() {
					startInformersAndController()
					r.EqualError(runControllerSync(), "[error on service creation, failed to update CredentialIssuer status: error on update]")
				})
			})
		})

		when("the impersonator is ready but there is a problem with the signing secret, which should be created by another controller", func() {
			const fakeHostname = "foo.example.com"
			it.Before(func() {
				addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
					ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
					Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
						ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
							Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
							ExternalEndpoint: fakeHostname,
							Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
								Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
							},
						},
					},
				}, pinnipedInformerClient, pinnipedAPIClient)
				addNodeWithRoleToTracker("worker", kubeAPIClient)
			})

			when("it does not exist in the informers", func() {
				it("returns the error", func() {
					startInformersAndController()
					errString := `could not load the impersonator's credential signing secret: secret "some-ca-signer-name" not found`
					r.EqualError(runControllerSync(), errString)
					requireCredentialIssuer(newErrorStrategy(errString))
					requireMTLSClientCertProviderIsEmpty()
				})
			})

			when("it does not have the expected fields", func() {
				it.Before(func() {
					addSecretToTrackers(newEmptySecret(mTLSClientCertCASecretName), kubeInformerClient)
				})

				it("returns the error", func() {
					startInformersAndController()
					errString := `could not set the impersonator's credential signing secret: TestImpersonatorConfigControllerSync: attempt to set invalid key pair: tls: failed to find any PEM data in certificate input`
					r.EqualError(runControllerSync(), errString)
					requireCredentialIssuer(newErrorStrategy(errString))
					requireMTLSClientCertProviderIsEmpty()
				})
			})

			when("the cert is invalid", func() {
				it.Before(func() {
					mTLSClientCertCASecret.Data[apicerts.CACertificateSecretKey] = []byte("not a valid PEM formatted cert")
					addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				})

				it("returns the error", func() {
					startInformersAndController()
					errString := `could not set the impersonator's credential signing secret: TestImpersonatorConfigControllerSync: attempt to set invalid key pair: tls: failed to find any PEM data in certificate input`
					r.EqualError(runControllerSync(), errString)
					requireCredentialIssuer(newErrorStrategy(errString))
					requireMTLSClientCertProviderIsEmpty()
				})
			})

			when("the cert goes from being valid to being invalid", func() {
				const fakeHostname = "foo.example.com"
				it.Before(func() {
					addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
				})

				it("returns the error and clears the dynamic provider", func() {
					startInformersAndController()
					r.NoError(runControllerSync())
					r.Len(kubeAPIClient.Actions(), 3)
					requireNodesListed(kubeAPIClient.Actions()[0])
					ca := requireCASecretWasCreated(kubeAPIClient.Actions()[1])
					requireTLSSecretWasCreated(kubeAPIClient.Actions()[2], ca)
					// Check that the server is running and that TLS certs that are being served are are for fakeHostname.
					requireTLSServerIsRunning(ca, fakeHostname, map[string]string{fakeHostname + httpsPort: testServerAddr()})
					requireCredentialIssuer(newSuccessStrategy(fakeHostname, ca))
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)

					// Simulate the informer cache's background update from its watch.
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[1], kubeInformers.Core().V1().Secrets())
					addObjectFromCreateActionToInformerAndWait(kubeAPIClient.Actions()[2], kubeInformers.Core().V1().Secrets())

					// Now update the signer CA to something invalid.
					deleteSecretFromTracker(mTLSClientCertCASecretName, kubeInformerClient)
					waitForObjectToBeDeletedFromInformer(mTLSClientCertCASecretName, kubeInformers.Core().V1().Secrets())
					updatedSigner := newEmptySecret(mTLSClientCertCASecretName)
					addSecretToTrackers(updatedSigner, kubeInformerClient)
					waitForObjectToAppearInInformer(updatedSigner, kubeInformers.Core().V1().Secrets())

					errString := `could not set the impersonator's credential signing secret: TestImpersonatorConfigControllerSync: attempt to set invalid key pair: tls: failed to find any PEM data in certificate input`
					r.EqualError(runControllerSync(), errString)
					requireCredentialIssuer(newErrorStrategy(errString))
					requireMTLSClientCertProviderHasLoadedCerts(mTLSClientCertCACertPEM, mTLSClientCertCAPrivateKeyPEM)
				})
			})
		})

		when("CredentialIssuer spec validation", func() {
			when("the impersonator is enabled but the service type is none and the external endpoint is empty", func() {
				it.Before(func() {
					addSecretToTrackers(mTLSClientCertCASecret, kubeInformerClient)
					addCredentialIssuerToTrackers(conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: credentialIssuerResourceName},
						Spec: conciergeconfigv1alpha1.CredentialIssuerSpec{
							ImpersonationProxy: &conciergeconfigv1alpha1.ImpersonationProxySpec{
								Mode:             conciergeconfigv1alpha1.ImpersonationProxyModeEnabled,
								ExternalEndpoint: "",
								Service: conciergeconfigv1alpha1.ImpersonationProxyServiceSpec{
									Type: conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone,
								},
							},
						},
					}, pinnipedInformerClient, pinnipedAPIClient)
					addNodeWithRoleToTracker("control-plane", kubeAPIClient)
				})

				it("returns a validation error", func() {
					startInformersAndController()
					r.EqualError(runControllerSync(), "could not load CredentialIssuer spec.impersonationProxy: externalEndpoint must be set when service.type is None")
					r.Len(kubeAPIClient.Actions(), 0)
				})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}

type testQueue struct {
	key   controllerlib.Key
	mutex sync.RWMutex

	controllerlib.Queue
}

func (q *testQueue) AddRateLimited(key controllerlib.Key) {
	q.mutex.Lock() // this is to satisfy the race detector
	defer q.mutex.Unlock()

	if q.key != (controllerlib.Key{}) {
		panic("called more than once")
	}

	if key == (controllerlib.Key{}) {
		panic("unexpected empty key")
	}

	q.key = key
}
