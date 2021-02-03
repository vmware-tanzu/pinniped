// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package library

import (
	"bufio"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	logTailLines := int64(40)
	pods, err := kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	require.NoError(t, err)

	for _, pod := range pods.Items {
		for _, container := range pod.Status.ContainerStatuses {
			t.Logf("pod %s/%s container %s restarted %d times:", pod.Namespace, pod.Name, container.Name, container.RestartCount)
			req := kubeClient.CoreV1().Pods(namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
				Container: container.Name,
				TailLines: &logTailLines,
			})
			logReader, err := req.Stream(ctx)
			require.NoError(t, err)

			scanner := bufio.NewScanner(logReader)
			for scanner.Scan() {
				t.Logf("%s/%s/%s > %s", pod.Namespace, pod.Name, container.Name, scanner.Text())
			}
			require.NoError(t, scanner.Err())
		}
	}
}
