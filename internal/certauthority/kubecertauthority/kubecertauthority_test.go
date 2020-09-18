// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubecertauthority

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"sync"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/klog/v2"

	"go.pinniped.dev/internal/testutil"
)

type fakePodExecutor struct {
	resultsToReturn []string
	errorsToReturn  []error

	calledWithPodName        []string
	calledWithPodNamespace   []string
	calledWithCommandAndArgs [][]string

	callCount int
}

func (s *fakePodExecutor) Exec(podNamespace string, podName string, commandAndArgs ...string) (string, error) {
	s.calledWithPodNamespace = append(s.calledWithPodNamespace, podNamespace)
	s.calledWithPodName = append(s.calledWithPodName, podName)
	s.calledWithCommandAndArgs = append(s.calledWithCommandAndArgs, commandAndArgs)
	result := s.resultsToReturn[s.callCount]
	var err error = nil
	if s.errorsToReturn != nil {
		err = s.errorsToReturn[s.callCount]
	}
	s.callCount++
	if err != nil {
		return "", err
	}
	return result, nil
}

type callbackRecorder struct {
	numberOfTimesSuccessCalled int
	numberOfTimesFailureCalled int
	failureErrors              []error
	mutex                      sync.Mutex
}

func (c *callbackRecorder) OnSuccess() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.numberOfTimesSuccessCalled++
}

func (c *callbackRecorder) OnFailure(err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.numberOfTimesFailureCalled++
	c.failureErrors = append(c.failureErrors, err)
}

func (c *callbackRecorder) NumberOfTimesSuccessCalled() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.numberOfTimesSuccessCalled
}

func (c *callbackRecorder) NumberOfTimesFailureCalled() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.numberOfTimesFailureCalled
}

func (c *callbackRecorder) FailureErrors() []error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var errs = make([]error, len(c.failureErrors))
	copy(errs, c.failureErrors)
	return errs
}

func TestCA(t *testing.T) {
	spec.Run(t, "CA", func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions
		var fakeCertPEM, fakeKeyPEM string
		var fakeCert2PEM, fakeKey2PEM string
		var fakePod *corev1.Pod
		var kubeAPIClient *kubernetesfake.Clientset
		var fakeExecutor *fakePodExecutor
		var neverTicker <-chan time.Time
		var callbacks *callbackRecorder
		var logger *testutil.TranscriptLogger

		var requireInitialFailureLogMessage = func(specificErrorMessage string) {
			r.Len(logger.Transcript(), 1)
			r.Equal(
				fmt.Sprintf("could not initially fetch the API server's signing key: %s\n", specificErrorMessage),
				logger.Transcript()[0].Message,
			)
			r.Equal(logger.Transcript()[0].Level, "error")
		}

		var requireNotCapableOfIssuingCerts = func(subject *CA) {
			certPEM, keyPEM, err := subject.IssuePEM(
				pkix.Name{CommonName: "Test Server"},
				[]string{"example.com"},
				10*time.Minute,
			)
			r.Nil(certPEM)
			r.Nil(keyPEM)
			r.EqualError(err, "this cluster is not currently capable of issuing certificates")
		}

		it.Before(func() {
			r = require.New(t)

			loadFile := func(filename string) string {
				bytes, err := ioutil.ReadFile(filename)
				r.NoError(err)
				return string(bytes)
			}
			fakeCertPEM = loadFile("./testdata/test.crt")
			fakeKeyPEM = loadFile("./testdata/test.key")
			fakeCert2PEM = loadFile("./testdata/test2.crt")
			fakeKey2PEM = loadFile("./testdata/test2.key")

			fakePod = &corev1.Pod{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-pod",
					Namespace: "kube-system",
					Labels:    map[string]string{"component": "kube-controller-manager"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "kube-controller-manager"}},
				},
				Status: corev1.PodStatus{
					Phase: "Running",
				},
			}

			kubeAPIClient = kubernetesfake.NewSimpleClientset()

			fakeExecutor = &fakePodExecutor{
				resultsToReturn: []string{
					fakeCertPEM,
					fakeKeyPEM,
					fakeCert2PEM,
					fakeKey2PEM,
				},
			}

			callbacks = &callbackRecorder{}

			logger = testutil.NewTranscriptLogger(t)
			klog.SetLogger(logger) // this is unfortunately a global logger, so can't run these tests in parallel :(
		})

		it.After(func() {
			klog.SetLogger(nil)
		})

		when("the kube-controller-manager pod is found with default CLI flag values", func() {
			it.Before(func() {
				err := kubeAPIClient.Tracker().Add(fakePod)
				r.NoError(err)
			})

			when("the exec commands return the API server's keypair", func() {
				it("finds the API server's signing key and uses it to issue certificates", func() {
					fakeTicker := make(chan time.Time)

					subject, shutdownFunc := New(kubeAPIClient, fakeExecutor, fakeTicker, callbacks.OnSuccess, callbacks.OnFailure)
					defer shutdownFunc()

					r.Equal(2, fakeExecutor.callCount)

					r.Equal("kube-system", fakeExecutor.calledWithPodNamespace[0])
					r.Equal("fake-pod", fakeExecutor.calledWithPodName[0])
					r.Equal([]string{"cat", "/etc/kubernetes/ca/ca.pem"}, fakeExecutor.calledWithCommandAndArgs[0])

					r.Equal("kube-system", fakeExecutor.calledWithPodNamespace[1])
					r.Equal("fake-pod", fakeExecutor.calledWithPodName[1])
					r.Equal([]string{"cat", "/etc/kubernetes/ca/ca.key"}, fakeExecutor.calledWithCommandAndArgs[1])

					r.Equal(1, callbacks.NumberOfTimesSuccessCalled())
					r.Equal(0, callbacks.NumberOfTimesFailureCalled())

					// Validate that we can issue a certificate signed by the original API server CA.
					certPEM, keyPEM, err := subject.IssuePEM(
						pkix.Name{CommonName: "Test Server"},
						[]string{"example.com"},
						10*time.Minute,
					)
					r.NoError(err)
					validCert := testutil.ValidateCertificate(t, fakeCertPEM, string(certPEM))
					validCert.RequireDNSName("example.com")
					validCert.RequireLifetime(time.Now(), time.Now().Add(10*time.Minute), 6*time.Minute)
					validCert.RequireMatchesPrivateKey(string(keyPEM))

					// Tick the timer and wait for another refresh loop to complete.
					fakeTicker <- time.Now()

					// Eventually it starts issuing certs using the new signing key.
					var secondCertPEM, secondKeyPEM string
					r.Eventually(func() bool {
						certPEM, keyPEM, err := subject.IssuePEM(
							pkix.Name{CommonName: "Test Server"},
							[]string{"example.com"},
							10*time.Minute,
						)
						r.NoError(err)
						secondCertPEM = string(certPEM)
						secondKeyPEM = string(keyPEM)

						block, _ := pem.Decode(certPEM)
						require.NotNil(t, block)
						parsed, err := x509.ParseCertificate(block.Bytes)
						require.NoError(t, err)

						// Validate the created cert using the second API server CA.
						roots := x509.NewCertPool()
						require.True(t, roots.AppendCertsFromPEM([]byte(fakeCert2PEM)))
						opts := x509.VerifyOptions{Roots: roots}
						_, err = parsed.Verify(opts)
						return err == nil
					}, 5*time.Second, 100*time.Millisecond)

					r.Equal(2, callbacks.NumberOfTimesSuccessCalled())
					r.Equal(0, callbacks.NumberOfTimesFailureCalled())

					validCert2 := testutil.ValidateCertificate(t, fakeCert2PEM, secondCertPEM)
					validCert2.RequireDNSName("example.com")
					validCert2.RequireLifetime(time.Now(), time.Now().Add(15*time.Minute), 6*time.Minute)
					validCert2.RequireMatchesPrivateKey(secondKeyPEM)
				})
			})

			when("the exec commands return the API server's keypair the first time but subsequently fails", func() {
				it.Before(func() {
					fakeExecutor.errorsToReturn = []error{nil, nil, fmt.Errorf("some exec error")}
				})

				it("logs an error message", func() {
					fakeTicker := make(chan time.Time)

					subject, shutdownFunc := New(kubeAPIClient, fakeExecutor, fakeTicker, callbacks.OnSuccess, callbacks.OnFailure)
					defer shutdownFunc()
					r.Equal(2, fakeExecutor.callCount)
					r.Equal(1, callbacks.NumberOfTimesSuccessCalled())
					r.Equal(0, callbacks.NumberOfTimesFailureCalled())

					// Tick the timer and wait for another refresh loop to complete.
					fakeTicker <- time.Now()

					// Wait for there to be a log output and require that it matches our expectation.
					r.Eventually(func() bool { return len(logger.Transcript()) >= 1 }, 5*time.Second, 10*time.Millisecond)
					r.Contains(logger.Transcript()[0].Message, "could not create signer with API server secret: some exec error")
					r.Equal(logger.Transcript()[0].Level, "error")

					r.Equal(1, callbacks.NumberOfTimesSuccessCalled())
					r.Equal(1, callbacks.NumberOfTimesFailureCalled())
					r.EqualError(callbacks.FailureErrors()[0], "some exec error")

					// Validate that we can still issue a certificate signed by the original API server CA.
					certPEM, _, err := subject.IssuePEM(
						pkix.Name{CommonName: "Test Server"},
						[]string{"example.com"},
						10*time.Minute,
					)
					r.NoError(err)
					testutil.ValidateCertificate(t, fakeCertPEM, string(certPEM))
				})
			})

			when("the exec commands fail the first time but subsequently returns the API server's keypair", func() {
				it.Before(func() {
					fakeExecutor.errorsToReturn = []error{fmt.Errorf("some exec error"), nil, nil}
					fakeExecutor.resultsToReturn = []string{"", fakeCertPEM, fakeKeyPEM}
				})

				it("logs an error message and fails to issue certs until it can get the API server's keypair", func() {
					fakeTicker := make(chan time.Time)

					subject, shutdownFunc := New(kubeAPIClient, fakeExecutor, fakeTicker, callbacks.OnSuccess, callbacks.OnFailure)
					defer shutdownFunc()
					r.Equal(1, fakeExecutor.callCount)
					r.Equal(0, callbacks.NumberOfTimesSuccessCalled())
					r.Equal(1, callbacks.NumberOfTimesFailureCalled())
					r.EqualError(callbacks.FailureErrors()[0], "some exec error")

					requireInitialFailureLogMessage("some exec error")
					requireNotCapableOfIssuingCerts(subject)

					// Tick the timer and wait for another refresh loop to complete.
					fakeTicker <- time.Now()

					// Wait until it can start to issue certs, and then validate the issued cert.
					var certPEM, keyPEM []byte
					r.Eventually(func() bool {
						var err error
						certPEM, keyPEM, err = subject.IssuePEM(
							pkix.Name{CommonName: "Test Server"},
							[]string{"example.com"},
							10*time.Minute,
						)
						return err == nil
					}, 5*time.Second, 10*time.Millisecond)
					validCert := testutil.ValidateCertificate(t, fakeCertPEM, string(certPEM))
					validCert.RequireDNSName("example.com")
					validCert.RequireLifetime(time.Now().Add(-5*time.Minute), time.Now().Add(10*time.Minute), 1*time.Minute)
					validCert.RequireMatchesPrivateKey(string(keyPEM))

					r.Equal(1, callbacks.NumberOfTimesSuccessCalled())
					r.Equal(1, callbacks.NumberOfTimesFailureCalled())
				})
			})

			when("the exec commands succeed but return garbage", func() {
				it.Before(func() {
					fakeExecutor.resultsToReturn = []string{"not a cert", "not a private key"}
				})

				it("returns a CA who cannot issue certs", func() {
					subject, shutdownFunc := New(kubeAPIClient, fakeExecutor, neverTicker, callbacks.OnSuccess, callbacks.OnFailure)
					defer shutdownFunc()
					requireInitialFailureLogMessage("could not load CA: tls: failed to find any PEM data in certificate input")
					requireNotCapableOfIssuingCerts(subject)
					r.Equal(0, callbacks.NumberOfTimesSuccessCalled())
					r.Equal(1, callbacks.NumberOfTimesFailureCalled())
					r.EqualError(callbacks.FailureErrors()[0], "could not load CA: tls: failed to find any PEM data in certificate input")
				})
			})

			when("the first exec command returns an error", func() {
				it.Before(func() {
					fakeExecutor.errorsToReturn = []error{fmt.Errorf("some error"), nil}
				})

				it("returns a CA who cannot issue certs", func() {
					subject, shutdownFunc := New(kubeAPIClient, fakeExecutor, neverTicker, callbacks.OnSuccess, callbacks.OnFailure)
					defer shutdownFunc()
					requireInitialFailureLogMessage("some error")
					requireNotCapableOfIssuingCerts(subject)
					r.Equal(0, callbacks.NumberOfTimesSuccessCalled())
					r.Equal(1, callbacks.NumberOfTimesFailureCalled())
					r.EqualError(callbacks.FailureErrors()[0], "some error")
				})
			})

			when("the second exec command returns an error", func() {
				it.Before(func() {
					fakeExecutor.errorsToReturn = []error{nil, fmt.Errorf("some error")}
				})

				it("returns a CA who cannot issue certs", func() {
					subject, shutdownFunc := New(kubeAPIClient, fakeExecutor, neverTicker, callbacks.OnSuccess, callbacks.OnFailure)
					defer shutdownFunc()
					requireInitialFailureLogMessage("some error")
					requireNotCapableOfIssuingCerts(subject)
					r.Equal(0, callbacks.NumberOfTimesSuccessCalled())
					r.Equal(1, callbacks.NumberOfTimesFailureCalled())
					r.EqualError(callbacks.FailureErrors()[0], "some error")
				})
			})
		})

		when("the kube-controller-manager pod is found with non-default CLI flag values", func() {
			it.Before(func() {
				fakePod.Spec.Containers[0].Command = []string{
					"kube-controller-manager",
					"--cluster-signing-cert-file=/etc/kubernetes/ca/non-default.pem",
				}
				fakePod.Spec.Containers[0].Args = []string{
					"--cluster-signing-key-file=/etc/kubernetes/ca/non-default.key",
				}
				err := kubeAPIClient.Tracker().Add(fakePod)
				r.NoError(err)
			})

			it("finds the API server's signing key and uses it to issue certificates", func() {
				_, shutdownFunc := New(kubeAPIClient, fakeExecutor, neverTicker, callbacks.OnSuccess, callbacks.OnFailure)
				defer shutdownFunc()

				r.Equal(2, fakeExecutor.callCount)

				r.Equal("kube-system", fakeExecutor.calledWithPodNamespace[0])
				r.Equal("fake-pod", fakeExecutor.calledWithPodName[0])
				r.Equal([]string{"cat", "/etc/kubernetes/ca/non-default.pem"}, fakeExecutor.calledWithCommandAndArgs[0])

				r.Equal("kube-system", fakeExecutor.calledWithPodNamespace[1])
				r.Equal("fake-pod", fakeExecutor.calledWithPodName[1])
				r.Equal([]string{"cat", "/etc/kubernetes/ca/non-default.key"}, fakeExecutor.calledWithCommandAndArgs[1])
			})
		})

		when("the kube-controller-manager pod is found with non-default CLI flag values separated by spaces", func() {
			it.Before(func() {
				fakePod.Spec.Containers[0].Command = []string{
					"kube-controller-manager",
					"--cluster-signing-cert-file", "/etc/kubernetes/ca/non-default.pem",
					"--cluster-signing-key-file", "/etc/kubernetes/ca/non-default.key",
					"--foo=bar",
				}
				err := kubeAPIClient.Tracker().Add(fakePod)
				r.NoError(err)
			})

			it("finds the API server's signing key and uses it to issue certificates", func() {
				_, shutdownFunc := New(kubeAPIClient, fakeExecutor, neverTicker, callbacks.OnSuccess, callbacks.OnFailure)
				defer shutdownFunc()

				r.Equal(2, fakeExecutor.callCount)

				r.Equal("kube-system", fakeExecutor.calledWithPodNamespace[0])
				r.Equal("fake-pod", fakeExecutor.calledWithPodName[0])
				r.Equal([]string{"cat", "/etc/kubernetes/ca/non-default.pem"}, fakeExecutor.calledWithCommandAndArgs[0])

				r.Equal("kube-system", fakeExecutor.calledWithPodNamespace[1])
				r.Equal("fake-pod", fakeExecutor.calledWithPodName[1])
				r.Equal([]string{"cat", "/etc/kubernetes/ca/non-default.key"}, fakeExecutor.calledWithCommandAndArgs[1])
			})
		})

		when("the kube-controller-manager pod is not found", func() {
			it("returns an error", func() {
				subject, shutdownFunc := New(kubeAPIClient, fakeExecutor, neverTicker, callbacks.OnSuccess, callbacks.OnFailure)
				defer shutdownFunc()
				requireInitialFailureLogMessage("did not find kube-controller-manager pod")
				requireNotCapableOfIssuingCerts(subject)
				r.Equal(0, callbacks.NumberOfTimesSuccessCalled())
				r.Equal(1, callbacks.NumberOfTimesFailureCalled())
				r.EqualError(callbacks.FailureErrors()[0], "did not find kube-controller-manager pod")
			})
		})
	}, spec.Sequential(), spec.Report(report.Terminal{}))
}
