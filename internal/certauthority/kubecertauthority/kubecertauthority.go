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
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/suzerain-io/placeholder-name/kubernetes/1.19/client-go/clientset/versioned/scheme"
)

type signer interface {
	IssuePEM(subject pkix.Name, dnsNames []string, ttl time.Duration) ([]byte, []byte, error)
}

type CA struct {
	k8s kubernetes.Interface

	shutdown, done chan struct{}

	lock         sync.RWMutex
	activeSigner signer
}

type ShutdownFunc func()

func New(k8s kubernetes.Interface) (*CA, ShutdownFunc, error) {
	signer, err := loadSecret(k8s)
	if err != nil {
		return nil, nil, err
	}
	result := &CA{
		k8s:          k8s,
		activeSigner: signer,
	}
	go result.refreshLoop()
	return result, result.shutdownRefresh, nil
}

func loadSecret(k8s kubernetes.Interface) (signer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pod, err := findControllerManagerPod(ctx, k8s)
	if err != nil {
		return nil, fmt.Errorf("could not find controller-manager pod: %v", err)
	}
	certPath, keyPath := getKeypairPath(pod)

	_ = certPath
	_ = keyPath

	return nil, nil
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
			c.refresh()
		}
	}
}

func (c *CA) refresh() {
	newSigner, err := loadSecret(c.k8s)
	if err != nil {
		//TODO: log the error
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
	defer c.lock.RUnlock()
	return c.activeSigner.IssuePEM(subject, dnsNames, ttl)
}

func findControllerManagerPod(ctx context.Context, k8s kubernetes.Interface) (*v1.Pod, error) {
	pods, err := k8s.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "component=kube-controller-manager",
		FieldSelector: "status.phase=Running",
	})
	if err != nil {
		return nil, err
	}
	for _, pod := range pods.Items {
		return &pod, nil
	}
	return nil, nil
}

func getKeypairPath(pod *v1.Pod) (string, string) {
	certPath := getArg(pod, "--cluster-signing-cert-file=")
	if certPath == "" {
		certPath = "/etc/kubernetes/ca/ca.pem"
	}
	keyPath := getArg(pod, "--cluster-signing-key-file=")
	if keyPath == "" {
		keyPath = "/etc/kubernetes/ca/ca.key"
	}
	return certPath, keyPath
}

func getArg(pod *v1.Pod, argPrefix string) string {
	for _, container := range pod.Spec.Containers {
		for _, arg := range append(container.Command, container.Args...) {
			if strings.HasPrefix(arg, argPrefix) {
				return strings.TrimPrefix(arg, argPrefix)
			}
		}
	}
	return ""
}

func exec(
	config *restclient.Config,
	client *kubernetes.Clientset,
	pod *v1.Pod,
	command string,
	args ...string,
) (stdout string, stderr string, err error) {
	// NOTE: exec needs role to create on pods/exec

	stdoutBuf := bytes.Buffer{}
	stderrBuf := bytes.Buffer{}
	comand := []string{command}
	comand = append(comand, args...)
	request := client.
		CoreV1().
		RESTClient().
		Post().
		Namespace(pod.Namespace).
		Resource("pods").
		Name(pod.Name).
		SubResource("exec").
		VersionedParams(&v1.PodExecOptions{
			Command: comand,
			Stdin:   false,
			Stdout:  true,
			Stderr:  true,
			TTY:     false,
		}, scheme.ParameterCodec)
	e, err := remotecommand.NewSPDYExecutor(config, "POST", request.URL())
	err = e.Stream(remotecommand.StreamOptions{
		Stdout: &stdoutBuf,
		Stderr: &stderrBuf,
	})
	return string(stdoutBuf.Bytes()), string(stderrBuf.Bytes()), err
}
