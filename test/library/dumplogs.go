// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package library

import (
	"bufio"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DumpLogs is meant to be called in a `defer` to dump the logs of components in the cluster on a test failure.
func DumpLogs(t *testing.T, namespace string, labelSelector string) {
	// Only trigger on failed tests.
	if !t.Failed() {
		return
	}

	kubeClient := NewKubernetesClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pods, err := kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	require.NoError(t, err)

	for _, pod := range pods.Items {
		for _, container := range pod.Status.ContainerStatuses {
			if container.RestartCount > 0 {
				dumpContainerLogs(ctx, t, kubeClient, pod.Namespace, pod.Name, container.Name, true)
			}
			dumpContainerLogs(ctx, t, kubeClient, pod.Namespace, pod.Name, container.Name, false)
		}
	}
}

func dumpContainerLogs(ctx context.Context, t *testing.T, kubeClient kubernetes.Interface, namespace, pod, container string, prev bool) {
	logTailLines := int64(40)
	shortName := fmt.Sprintf("%s/%s/%s", namespace, pod, container)
	logReader, err := kubeClient.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{
		Container: container,
		TailLines: &logTailLines,
		Previous:  prev,
	}).Stream(ctx)
	if !assert.NoErrorf(t, err, "failed to stream logs for container %s", shortName) {
		return
	}
	scanner := bufio.NewScanner(logReader)
	for scanner.Scan() {
		prefix := shortName
		if prev {
			prefix += " (previous)"
		}
		t.Logf("%s > %s", prefix, scanner.Text())
	}
	assert.NoError(t, scanner.Err(), "failed to read logs from container %s", shortName)
}
