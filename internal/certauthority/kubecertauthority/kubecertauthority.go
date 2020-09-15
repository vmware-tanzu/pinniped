/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package kubecertauthority implements a signer backed by the kubernetes controller-manager signing
// keys (accessed via the kubernetes Exec API).
package kubecertauthority

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"fmt"
	"sync"
	"time"

	"github.com/spf13/pflag"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/deprecated/scheme"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/klog/v2"

	"github.com/suzerain-io/pinniped/internal/certauthority"
	"github.com/suzerain-io/pinniped/internal/constable"
)

// ErrNoKubeControllerManagerPod is returned when no kube-controller-manager pod is found on the cluster.
const ErrNoKubeControllerManagerPod = constable.Error("did not find kube-controller-manager pod")
const ErrIncapableOfIssuingCertificates = constable.Error("this cluster is not currently capable of issuing certificates")

const k8sAPIServerCACertPEMDefaultPath = "/etc/kubernetes/ca/ca.pem"
const k8sAPIServerCAKeyPEMDefaultPath = "/etc/kubernetes/ca/ca.key"

type signer interface {
	IssuePEM(subject pkix.Name, dnsNames []string, ttl time.Duration) ([]byte, []byte, error)
}

type PodCommandExecutor interface {
	Exec(podNamespace string, podName string, commandAndArgs ...string) (stdoutResult string, err error)
}

type kubeClientPodCommandExecutor struct {
	kubeConfig *restclient.Config
	kubeClient kubernetes.Interface
}

func NewPodCommandExecutor(kubeConfig *restclient.Config, kubeClient kubernetes.Interface) PodCommandExecutor {
	return &kubeClientPodCommandExecutor{kubeConfig: kubeConfig, kubeClient: kubeClient}
}

func (s *kubeClientPodCommandExecutor) Exec(podNamespace string, podName string, commandAndArgs ...string) (string, error) {
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

	executor, err := remotecommand.NewSPDYExecutor(s.kubeConfig, "POST", request.URL())
	if err != nil {
		return "", err
	}

	var stdoutBuf bytes.Buffer
	if err := executor.Stream(remotecommand.StreamOptions{Stdout: &stdoutBuf}); err != nil {
		return "", err
	}
	return stdoutBuf.String(), nil
}

type CA struct {
	kubeClient         kubernetes.Interface
	podCommandExecutor PodCommandExecutor

	shutdown, done chan struct{}

	onSuccessfulRefresh SuccessCallback
	onFailedRefresh     FailureCallback

	lock         sync.RWMutex
	activeSigner signer
}

type ShutdownFunc func()
type SuccessCallback func()
type FailureCallback func(error)

// New creates a new instance of a CA. It tries to load the kube API server's private key
// immediately. If that succeeds then it calls the success callback and it is ready to issue certs.
// When it fails to get the kube API server's private key, then it calls the failure callback and
// it will try again on the next tick. It starts a goroutine to periodically reload the kube
// API server's private key in case it failed previously or case the key has changed. It returns
// a function that can be used to shut down that goroutine. Future attempts made by that goroutine
// to get the key will also result in success or failure callbacks.
func New(
	kubeClient kubernetes.Interface,
	podCommandExecutor PodCommandExecutor,
	tick <-chan time.Time,
	onSuccessfulRefresh SuccessCallback,
	onFailedRefresh FailureCallback,
) (*CA, ShutdownFunc) {
	signer, err := createSignerWithAPIServerSecret(kubeClient, podCommandExecutor)
	if err != nil {
		klog.Errorf("could not initially fetch the API server's signing key: %s", err)
		signer = nil
		onFailedRefresh(err)
	} else {
		onSuccessfulRefresh()
	}
	result := &CA{
		kubeClient:          kubeClient,
		podCommandExecutor:  podCommandExecutor,
		shutdown:            make(chan struct{}),
		done:                make(chan struct{}),
		onSuccessfulRefresh: onSuccessfulRefresh,
		onFailedRefresh:     onFailedRefresh,
		activeSigner:        signer,
	}
	go result.refreshLoop(tick)
	return result, result.shutdownRefresh
}

func createSignerWithAPIServerSecret(kubeClient kubernetes.Interface, podCommandExecutor PodCommandExecutor) (signer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pod, err := findControllerManagerPod(ctx, kubeClient)
	if err != nil {
		return nil, err
	}
	certPath, keyPath := getKeypairFilePaths(pod)

	f := false
	newPod, err := kubeClient.CoreV1().Pods(pod.Namespace).Create(ctx, &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "pinniped-signer-",
			Namespace:    pod.Namespace,
		},
		Spec: v1.PodSpec{
			Volumes: pod.Spec.Volumes,
			Containers: []v1.Container{
				{
					Name:    "pinniped-signer",
					Image:   "busybox@sha256:d366a4665ab44f0648d7a00ae3fae139d55e32f9712c67accd604bb55df9d05a",
					Command: []string{"/bin/sleep", "60"},
					Resources: v1.ResourceRequirements{
						Limits: v1.ResourceList{
							v1.ResourceMemory: resource.MustParse("16Mi"),
							v1.ResourceCPU:    resource.MustParse("10m"),
						},
						Requests: v1.ResourceList{
							v1.ResourceMemory: resource.MustParse("16Mi"),
							v1.ResourceCPU:    resource.MustParse("10m"),
						},
					},
					VolumeMounts: pod.Spec.Containers[0].VolumeMounts,
				},
			},
			RestartPolicy:                v1.RestartPolicyNever,
			NodeSelector:                 pod.Spec.NodeSelector,
			AutomountServiceAccountToken: &f,
			NodeName:                     pod.Spec.NodeName,
			Tolerations:                  pod.Spec.Tolerations,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	defer func() {
		zero := int64(0)
		_ = kubeClient.CoreV1().Pods(newPod.Namespace).Delete(ctx, newPod.Name, metav1.DeleteOptions{GracePeriodSeconds: &zero})
	}()

	for {
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < 5*time.Second {
			return nil, fmt.Errorf("timed out while waiting for exec on temporary pod")
		}

		time.Sleep(1 * time.Second)
		certPEM, err := podCommandExecutor.Exec(newPod.Namespace, newPod.Name, "cat", certPath)
		if err != nil {
			continue
		}

		keyPEM, err := podCommandExecutor.Exec(newPod.Namespace, newPod.Name, "cat", keyPath)
		if err != nil {
			continue
		}

		return certauthority.Load(certPEM, keyPEM)
	}
}

func (c *CA) refreshLoop(tick <-chan time.Time) {
	for {
		select {
		case <-c.shutdown:
			close(c.done)
			return
		case <-tick:
			c.updateSigner()
		}
	}
}

func (c *CA) updateSigner() {
	newSigner, err := createSignerWithAPIServerSecret(c.kubeClient, c.podCommandExecutor)
	if err != nil {
		klog.Errorf("could not create signer with API server secret: %s", err)
		c.onFailedRefresh(err)
		return
	}
	c.lock.Lock()
	c.activeSigner = newSigner
	c.lock.Unlock()
	c.onSuccessfulRefresh()
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

	if signer == nil {
		return nil, nil, ErrIncapableOfIssuingCertificates
	}

	return signer.IssuePEM(subject, dnsNames, ttl)
}

func findControllerManagerPod(ctx context.Context, kubeClient kubernetes.Interface) (*v1.Pod, error) {
	pods, err := kubeClient.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "component=kube-controller-manager",
		FieldSelector: "status.phase=Running",
	})
	if err != nil {
		return nil, fmt.Errorf("could not check for kube-controller-manager pod: %w", err)
	}
	for _, pod := range pods.Items {
		return &pod, nil
	}
	return nil, ErrNoKubeControllerManagerPod
}

func getKeypairFilePaths(pod *v1.Pod) (string, string) {
	certPath := getContainerArgByName(pod, "cluster-signing-cert-file", k8sAPIServerCACertPEMDefaultPath)
	keyPath := getContainerArgByName(pod, "cluster-signing-key-file", k8sAPIServerCAKeyPEMDefaultPath)
	return certPath, keyPath
}

func getContainerArgByName(pod *v1.Pod, name string, defaultValue string) string {
	for _, container := range pod.Spec.Containers {
		flagset := pflag.NewFlagSet("", pflag.ContinueOnError)
		flagset.ParseErrorsWhitelist = pflag.ParseErrorsWhitelist{UnknownFlags: true}
		var val string
		flagset.StringVar(&val, name, "", "")
		_ = flagset.Parse(append(container.Command, container.Args...))
		if val != "" {
			return val
		}
	}
	return defaultValue
}
