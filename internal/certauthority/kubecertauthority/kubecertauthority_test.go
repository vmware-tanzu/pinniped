/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package kubecertauthority

import (
	"crypto/x509/pkix"
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
)

type fakePodExecutor struct {
	resultsToReturn []string
	errorsToReturn  []error

	calledWithPodName        []string
	calledWithPodNamespace   []string
	calledWithCommandAndArgs [][]string

	callCount int
}

func (s *fakePodExecutor) exec(podNamespace string, podName string, commandAndArgs ...string) (string, error) {
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
		var fakePod *corev1.Pod
		var kubeAPIClient *kubernetesfake.Clientset
		var fakeExecutor *fakePodExecutor

		it.Before(func() {
			r = require.New(t)

			fakeCertPEMBytes, err := ioutil.ReadFile("../testdata/test.crt")
			require.NoError(t, err)
			fakeCertPEM = string(fakeCertPEMBytes)

			fakeKeyPEMBytes, err := ioutil.ReadFile("../testdata/test.key")
			require.NoError(t, err)
			fakeKeyPEM = string(fakeKeyPEMBytes)

			fakePod = &corev1.Pod{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-pod",
					Namespace: "kube-system",
					Labels:    map[string]string{"component": "kube-controller-manager"},
				},
				Spec: corev1.PodSpec{},
				Status: corev1.PodStatus{
					Phase: "Running",
				},
			}

			kubeAPIClient = kubernetesfake.NewSimpleClientset()

			fakeExecutor = &fakePodExecutor{
				resultsToReturn: []string{
					fakeCertPEM,
					fakeKeyPEM,
				},
			}
		})

		when("the kube-controller-manager pod is found", func() {
			it.Before(func() {
				err := kubeAPIClient.Tracker().Add(fakePod)
				r.NoError(err)
			})

			when("the exec commands return the API server's keypair", func() {
				it("finds the API server's signing key and uses it to issue certificates", func() {
					subject, shutdownFunc, err := New(kubeAPIClient, fakeExecutor)
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

					certPEM, keyPEM, err := subject.IssuePEM(
						pkix.Name{CommonName: "Test Server"},
						[]string{"example.com"},
						10*time.Minute,
					)
					r.NoError(err)
					r.NotEmpty(certPEM)
					r.NotEmpty(keyPEM)

					// TODO test that the keypair returned by fakeExecutor was used to issue these certs, maybe similar to certs_manager_test.go
					_ = certPEM
					_ = keyPEM

					// TODO pretend to wait a little while and then check that the API server's keypair was read again, causing
					//  subject.IssuePEM to use that new keypair when issuing certs
				})
			})

			// TODO add a test similar to the one above for when the pod's container's command line cert path flags
			//  were used to override the default paths

			when("the exec commands succeed but return garbage", func() {
				it.Before(func() {
					fakeExecutor.resultsToReturn = []string{"not a cert", "not a private key"}
				})

				it("returns an error", func() {
					subject, shutdownFunc, err := New(kubeAPIClient, fakeExecutor)
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
					subject, shutdownFunc, err := New(kubeAPIClient, fakeExecutor)
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
					subject, shutdownFunc, err := New(kubeAPIClient, fakeExecutor)
					r.Nil(subject)
					r.Nil(shutdownFunc)
					r.EqualError(err, "some error")
				})
			})
		})

		when("the kube-controller-manager pod is not found", func() {
			it("returns an error", func() {
				subject, shutdownFunc, err := New(kubeAPIClient, fakeExecutor)
				r.Nil(subject)
				r.Nil(shutdownFunc)
				r.EqualError(err, "could not find controller-manager pod: did not find matching pod")
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
