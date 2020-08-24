/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package kubecertauthority

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/klog/v2"

	"github.com/suzerain-io/pinniped/internal/testutil"
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

func TestCA(t *testing.T) {
	spec.Run(t, "CA", func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions
		var fakeCertPEM, fakeKeyPEM string
		var fakeCert2PEM, fakeKey2PEM string
		var fakePod *corev1.Pod
		var kubeAPIClient *kubernetesfake.Clientset
		var fakeExecutor *fakePodExecutor
		var neverTicker <-chan time.Time

		var logger *testutil.TranscriptLogger

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

					subject, shutdownFunc, err := New(kubeAPIClient, fakeExecutor, fakeTicker)
					r.NoError(err)
					r.NotNil(shutdownFunc)
					defer shutdownFunc()

					r.Equal(2, fakeExecutor.callCount)

					r.Equal("kube-system", fakeExecutor.calledWithPodNamespace[0])
					r.Equal("fake-pod", fakeExecutor.calledWithPodName[0])
					r.Equal([]string{"cat", "/etc/kubernetes/ca/ca.pem"}, fakeExecutor.calledWithCommandAndArgs[0])

					r.Equal("kube-system", fakeExecutor.calledWithPodNamespace[1])
					r.Equal("fake-pod", fakeExecutor.calledWithPodName[1])
					r.Equal([]string{"cat", "/etc/kubernetes/ca/ca.key"}, fakeExecutor.calledWithCommandAndArgs[1])

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

					subject, shutdownFunc, err := New(kubeAPIClient, fakeExecutor, fakeTicker)
					r.NoError(err)
					r.NotNil(shutdownFunc)
					defer shutdownFunc()
					r.Equal(2, fakeExecutor.callCount)

					// Tick the timer and wait for another refresh loop to complete.
					fakeTicker <- time.Now()

					// Wait for there to be a log output and require that it matches our expectation.
					r.Eventually(func() bool { return len(logger.Transcript()) >= 1 }, 5*time.Second, 10*time.Millisecond)
					r.Contains(logger.Transcript()[0].Message, "could not create signer with API server secret: some exec error")
					r.Equal(logger.Transcript()[0].Level, "error")

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

			when("the exec commands succeed but return garbage", func() {
				it.Before(func() {
					fakeExecutor.resultsToReturn = []string{"not a cert", "not a private key"}
				})

				it("returns an error", func() {
					subject, shutdownFunc, err := New(kubeAPIClient, fakeExecutor, neverTicker)
					r.Nil(subject)
					r.Nil(shutdownFunc)
					r.EqualError(err, "could not load CA: tls: failed to find any PEM data in certificate input")
				})
			})

			when("the first exec command returns an error", func() {
				it.Before(func() {
					fakeExecutor.errorsToReturn = []error{fmt.Errorf("some error"), nil}
				})

				it("returns an error", func() {
					subject, shutdownFunc, err := New(kubeAPIClient, fakeExecutor, neverTicker)
					r.Nil(subject)
					r.Nil(shutdownFunc)
					r.EqualError(err, "some error")
				})
			})

			when("the second exec command returns an error", func() {
				it.Before(func() {
					fakeExecutor.errorsToReturn = []error{nil, fmt.Errorf("some error")}
				})

				it("returns an error", func() {
					subject, shutdownFunc, err := New(kubeAPIClient, fakeExecutor, neverTicker)
					r.Nil(subject)
					r.Nil(shutdownFunc)
					r.EqualError(err, "some error")
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
				_, shutdownFunc, err := New(kubeAPIClient, fakeExecutor, neverTicker)
				r.NoError(err)
				r.NotNil(shutdownFunc)
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
				_, shutdownFunc, err := New(kubeAPIClient, fakeExecutor, neverTicker)
				r.NoError(err)
				r.NotNil(shutdownFunc)
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
				subject, shutdownFunc, err := New(kubeAPIClient, fakeExecutor, neverTicker)
				r.Nil(subject)
				r.Nil(shutdownFunc)
				r.True(errors.Is(err, ErrNoKubeControllerManagerPod))
			})
		})
	}, spec.Report(report.Terminal{}))
}
