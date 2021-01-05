// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package deploymentref

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"go.pinniped.dev/internal/downward"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/ownerref"
)

func New(podInfo *downward.PodInfo) (kubeclient.Option, *appsv1.Deployment, error) {
	tempClient, err := kubeclient.New()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create temp client: %w", err)
	}

	deployment, err := getDeployment(tempClient.Kubernetes, podInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get deployment: %w", err)
	}

	ref := metav1.OwnerReference{
		Name: deployment.Name,
		UID:  deployment.UID,
	}
	ref.APIVersion, ref.Kind = appsv1.SchemeGroupVersion.WithKind("Deployment").ToAPIVersionAndKind()

	return kubeclient.WithMiddleware(ownerref.New(ref)), deployment, nil
}

func getDeployment(kubeClient kubernetes.Interface, podInfo *downward.PodInfo) (*appsv1.Deployment, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ns := podInfo.Namespace

	pod, err := kubeClient.CoreV1().Pods(ns).Get(ctx, podInfo.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not get pod: %w", err)
	}

	podOwner := metav1.GetControllerOf(pod)
	if podOwner == nil {
		return nil, fmt.Errorf("pod %s/%s is missing owner", ns, podInfo.Name)
	}

	rs, err := kubeClient.AppsV1().ReplicaSets(ns).Get(ctx, podOwner.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not get replicaset: %w", err)
	}

	rsOwner := metav1.GetControllerOf(rs)
	if rsOwner == nil {
		return nil, fmt.Errorf("replicaset %s/%s is missing owner", ns, podInfo.Name)
	}

	d, err := kubeClient.AppsV1().Deployments(ns).Get(ctx, rsOwner.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not get deployment: %w", err)
	}

	return d, nil
}
