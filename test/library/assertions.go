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

// NewRestartAssertion allows a caller to assert that there were no restarts for a Pod in the
// provided namespace with the provided labelSelector during the lifetime of a test.
func AssertNoRestartsDuringTest(t *testing.T, namespace, labelSelector string) {
	t.Helper()

	previousRestartCounts := getRestartCounts(t, namespace, labelSelector)

	t.Cleanup(func() {
		currentRestartCounts := getRestartCounts(t, namespace, labelSelector)

		for key, previousRestartCount := range previousRestartCounts {
			currentRestartCount, ok := currentRestartCounts[key]
			if assert.Truef(
				t,
				ok,
				"pod namespace/name/container %s existed at beginning of the test, but not the end",
				key,
			) {
				assert.Equal(
					t,
					previousRestartCount,
					currentRestartCount,
					"pod namespace/name/container %s has restarted %d times (original count was %d)",
					key,
					currentRestartCount,
					previousRestartCount,
				)
			}
		}
	})
}

func getRestartCounts(t *testing.T, namespace, labelSelector string) map[string]int32 {
	t.Helper()

	kubeClient := NewKubernetesClientset(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pods, err := kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	require.NoError(t, err)

	restartCounts := make(map[string]int32)
	for _, pod := range pods.Items {
		for _, container := range pod.Status.ContainerStatuses {
			key := fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)
			restartCounts[key] = container.RestartCount
		}
	}

	return restartCounts
}
