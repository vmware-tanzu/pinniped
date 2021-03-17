// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package library

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// RequireEventuallyWithoutError is a wrapper around require.Eventually() that allows the caller to
// return an error from the condition function. If the condition function returns an error at any
// point, the assertion will immediately fail.
func RequireEventuallyWithoutError(
	t *testing.T,
	f func() (bool, error),
	waitFor time.Duration,
	tick time.Duration,
	msgAndArgs ...interface{},
) {
	t.Helper()
	require.NoError(t, wait.PollImmediate(tick, waitFor, f), msgAndArgs...)
}

// assertNoRestartsDuringTest allows a caller to assert that there were no restarts for a Pod in the
// provided namespace with the provided labelSelector during the lifetime of a test.
func assertNoRestartsDuringTest(t *testing.T, namespace, labelSelector string) {
	t.Helper()
	kubeClient := NewKubernetesClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	previousRestartCounts := getRestartCounts(ctx, t, kubeClient, namespace, labelSelector)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		currentRestartCounts := getRestartCounts(ctx, t, kubeClient, namespace, labelSelector)

		for key, previousRestartCount := range previousRestartCounts {
			currentRestartCount, ok := currentRestartCounts[key]

			// If the container no longer exists, that's a test failure.
			if !assert.Truef(
				t,
				ok,
				"container %s existed at beginning of the test, but not the end",
				key.String(),
			) {
				continue
			}

			// Expect the restart count to be the same as it was before the test.
			if !assert.Equal(
				t,
				previousRestartCount,
				currentRestartCount,
				"container %s has restarted %d times (original count was %d)",
				key.String(),
				currentRestartCount,
				previousRestartCount,
			) {
				// Attempt to dump the logs from the previous container that crashed.
				dumpContainerLogs(ctx, t, kubeClient, key.namespace, key.pod, key.container, true)
			}
		}
	})
}

type containerRestartKey struct {
	namespace string
	pod       string
	container string
}

func (k containerRestartKey) String() string {
	return fmt.Sprintf("%s/%s/%s", k.namespace, k.pod, k.container)
}

type containerRestartMap map[containerRestartKey]int32

func getRestartCounts(ctx context.Context, t *testing.T, kubeClient kubernetes.Interface, namespace, labelSelector string) containerRestartMap {
	t.Helper()

	pods, err := kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	require.NoError(t, err)

	restartCounts := make(containerRestartMap)
	for _, pod := range pods.Items {
		for _, container := range pod.Status.ContainerStatuses {
			key := containerRestartKey{
				namespace: pod.Namespace,
				pod:       pod.Name,
				container: container.Name,
			}
			restartCounts[key] = container.RestartCount
		}
	}

	return restartCounts
}
