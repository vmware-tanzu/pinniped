/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package kubecertauthority implements a signer backed by the kubernetes controller-manager signing
// keys (accessed via the kubernetes exec API).
package kubecertauthority

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/deprecated/scheme"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/klog/v2"

	"github.com/suzerain-io/placeholder-name/internal/certauthority"
)

const k8sAPIServerCACertPEMDefaultPath = "/etc/kubernetes/ca/ca.pem"
const k8sAPIServerCAKeyPEMDefaultPath = "/etc/kubernetes/ca/ca.key"

type signer interface {
	IssuePEM(subject pkix.Name, dnsNames []string, ttl time.Duration) ([]byte, []byte, error)
}

type PodCommandExecutor interface {
	exec(podNamespace string, podName string, commandAndArgs ...string) (stdoutResult string, err error)
}

type kubeClientPodCommandExecutor struct {
	kubeConfig *restclient.Config
	kubeClient kubernetes.Interface
}

func NewPodCommandExecutor(kubeConfig *restclient.Config, kubeClient kubernetes.Interface) PodCommandExecutor {
	return &kubeClientPodCommandExecutor{kubeConfig: kubeConfig, kubeClient: kubeClient}
}

func (s *kubeClientPodCommandExecutor) exec(podNamespace string, podName string, commandAndArgs ...string) (string, error) {
	request := s.kubeClient.
		CoreV1().
		RESTClient().
		Post().
		Namespace(podNamespace).
		Resource("pods").
		Name(podName).
		SubResource("exec").
		VersionedParams(&v1.PodExecOptions{
			Stdin:   false,
			Stdout:  true,
			Stderr:  false,
			TTY:     false,
			Command: commandAndArgs,
		}, scheme.ParameterCodec)

	stdoutBuf := bytes.Buffer{}

	executor, err := remotecommand.NewSPDYExecutor(s.kubeConfig, "POST", request.URL())
	if err != nil {
		return "", err
	}

	err = executor.Stream(remotecommand.StreamOptions{Stdout: &stdoutBuf})
	result := string(stdoutBuf.Bytes())
	return result, nil
}

type CA struct {
	kubeClient         kubernetes.Interface
	podCommandExecutor PodCommandExecutor

	shutdown, done chan struct{}

	lock         sync.RWMutex
	activeSigner signer
}

type ShutdownFunc func()

// New creates a new instance of a CA which is has loaded the kube API server's private key
// and is ready to issue certs, or an error. When successful, it also starts a goroutine
// to periodically reload the kube API server's private key in case it changed, and returns
// a function that can be used to shut down that goroutine.
func New(kubeClient kubernetes.Interface, podCommandExecutor PodCommandExecutor) (*CA, ShutdownFunc, error) {
	signer, err := createSignerWithAPIServerSecret(kubeClient, podCommandExecutor)
	if err != nil {
		// The initial load failed, so give up
		return nil, nil, err
	}
	result := &CA{
		kubeClient:         kubeClient,
		podCommandExecutor: podCommandExecutor,
		activeSigner:       signer,
		shutdown:           make(chan struct{}),
		done:               make(chan struct{}),
	}
	go result.refreshLoop()
	return result, result.shutdownRefresh, nil
}

func createSignerWithAPIServerSecret(kubeClient kubernetes.Interface, podCommandExecutor PodCommandExecutor) (signer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pod, err := findControllerManagerPod(ctx, kubeClient)
	if err != nil {
		return nil, fmt.Errorf("could not find controller-manager pod: %v", err)
	}
	certPath, keyPath := getKeypairFilePaths(pod)

	certPEM, err := podCommandExecutor.exec(pod.Namespace, pod.Name, "cat", certPath)
	if err != nil {
		return nil, err
	}

	keyPEM, err := podCommandExecutor.exec(pod.Namespace, pod.Name, "cat", keyPath)
	if err != nil {
		return nil, err
	}

	return certauthority.Load(certPEM, keyPEM)
}

func (c *CA) refreshLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.shutdown:
			close(c.done)
			return
		case <-ticker.C:
			c.updateSigner()
		}
	}
}

func (c *CA) updateSigner() {
	newSigner, err := createSignerWithAPIServerSecret(c.kubeClient, c.podCommandExecutor)
	if err != nil {
		klog.Errorf("could not create signer with API server secret: %s", err)
		return
	}
	c.lock.Lock()
	c.activeSigner = newSigner
	c.lock.Unlock()
}

func (c *CA) shutdownRefresh() {
	close(c.shutdown)
	<-c.done
}

// IssuePEM issues a new server certificate for the given identity and duration, returning it as a pair of
//  PEM-formatted byte slices for the certificate and private key.
func (c *CA) IssuePEM(subject pkix.Name, dnsNames []string, ttl time.Duration) ([]byte, []byte, error) {
	c.lock.RLock()
	signer := c.activeSigner
	c.lock.RUnlock()

	return signer.IssuePEM(subject, dnsNames, ttl)
}

func findControllerManagerPod(ctx context.Context, kubeClient kubernetes.Interface) (*v1.Pod, error) {
	pods, err := kubeClient.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "component=kube-controller-manager",
		FieldSelector: "status.phase=Running",
	})
	if err != nil {
		return nil, err
	}
	for _, pod := range pods.Items {
		return &pod, nil
	}
	return nil, fmt.Errorf("did not find matching pod")
}

func getKeypairFilePaths(pod *v1.Pod) (string, string) {
	certPath := getContainerArgByName(pod, "cluster-signing-cert-file", k8sAPIServerCACertPEMDefaultPath)
	keyPath := getContainerArgByName(pod, "cluster-signing-key-file", k8sAPIServerCAKeyPEMDefaultPath)
	return certPath, keyPath
}

func getContainerArgByName(pod *v1.Pod, name string, defaultValue string) string {
	prefix := "--" + name + "="
	for _, container := range pod.Spec.Containers {
		for _, arg := range append(container.Command, container.Args...) {
			if strings.HasPrefix(arg, prefix) {
				return strings.TrimPrefix(arg, prefix)
			}
		}
	}
	return defaultValue
}
