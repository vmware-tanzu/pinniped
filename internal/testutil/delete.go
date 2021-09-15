// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	appsv1client "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

func NewDeleteOptionsRecorder(client kubernetes.Interface, opts *[]metav1.DeleteOptions) kubernetes.Interface {
	return &clientWrapper{
		Interface: client,
		opts:      opts,
	}
}

type clientWrapper struct {
	kubernetes.Interface
	opts *[]metav1.DeleteOptions
}

func (c *clientWrapper) CoreV1() corev1client.CoreV1Interface {
	return &coreWrapper{CoreV1Interface: c.Interface.CoreV1(), opts: c.opts}
}

func (c *clientWrapper) AppsV1() appsv1client.AppsV1Interface {
	return &appsWrapper{AppsV1Interface: c.Interface.AppsV1(), opts: c.opts}
}

type coreWrapper struct {
	corev1client.CoreV1Interface
	opts *[]metav1.DeleteOptions
}

func (c *coreWrapper) Pods(namespace string) corev1client.PodInterface {
	return &podsWrapper{PodInterface: c.CoreV1Interface.Pods(namespace), opts: c.opts}
}

func (c *coreWrapper) Secrets(namespace string) corev1client.SecretInterface {
	return &secretsWrapper{SecretInterface: c.CoreV1Interface.Secrets(namespace), opts: c.opts}
}

type appsWrapper struct {
	appsv1client.AppsV1Interface
	opts *[]metav1.DeleteOptions
}

func (c *appsWrapper) Deployments(namespace string) appsv1client.DeploymentInterface {
	return &deploymentsWrapper{DeploymentInterface: c.AppsV1Interface.Deployments(namespace), opts: c.opts}
}

type podsWrapper struct {
	corev1client.PodInterface
	opts *[]metav1.DeleteOptions
}

func (s *podsWrapper) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	*s.opts = append(*s.opts, opts)
	return s.PodInterface.Delete(ctx, name, opts)
}

type secretsWrapper struct {
	corev1client.SecretInterface
	opts *[]metav1.DeleteOptions
}

func (s *secretsWrapper) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	*s.opts = append(*s.opts, opts)
	return s.SecretInterface.Delete(ctx, name, opts)
}

type deploymentsWrapper struct {
	appsv1client.DeploymentInterface
	opts *[]metav1.DeleteOptions
}

func (s *deploymentsWrapper) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	*s.opts = append(*s.opts, opts)
	return s.DeploymentInterface.Delete(ctx, name, opts)
}

func NewPreconditions(uid types.UID, rv string) metav1.DeleteOptions {
	return metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{
			UID:             &uid,
			ResourceVersion: &rv,
		},
	}
}
