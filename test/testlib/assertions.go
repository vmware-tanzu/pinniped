// Copyright 2021-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testlib

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

	"go.pinniped.dev/internal/constable"
)

type (
	// loopTestingT records the failures observed during an iteration of the RequireEventually() loop.
	loopTestingT []assertionFailure

	// assertionFailure is a single error observed during an iteration of the RequireEventually() loop.
	assertionFailure struct {
		format string
		args   []any
	}
)

// loopTestingT implements require.TestingT.
var _ require.TestingT = (*loopTestingT)(nil)

// Errorf is called by the assert.Assertions methods to record an error.
func (e *loopTestingT) Errorf(format string, args ...any) {
	*e = append(*e, assertionFailure{format, args})
}

const errLoopFailNow = constable.Error("failing test now")

// FailNow is called by the require.Assertions methods to force the code to immediately halt. It panics with a
// sentinel value that is recovered by recoverLoopFailNow().
func (e *loopTestingT) FailNow() { panic(errLoopFailNow) }

// ignoreFailNowPanic catches the panic from FailNow() and ignores it (allowing the FailNow() call to halt the test
// but let the retry loop continue.
func recoverLoopFailNow() {
	switch p := recover(); p {
	case nil, errLoopFailNow:
		// Ignore nil (success) and our sentinel value.
		return
	default:
		// Re-panic on any other value.
		panic(p)
	}
}

func RequireEventuallyf(
	t *testing.T,
	f func(requireEventually *require.Assertions),
	waitFor time.Duration,
	tick time.Duration,
	msg string,
	args ...any,
) {
	t.Helper()
	RequireEventually(t, f, waitFor, tick, fmt.Sprintf(msg, args...))
}

// RequireEventually is similar to require.Eventually() except that it is thread safe and provides a richer way to
// write per-iteration assertions.
func RequireEventually(
	t *testing.T,
	f func(requireEventually *require.Assertions),
	waitFor time.Duration,
	tick time.Duration,
	msgAndArgs ...any,
) {
	t.Helper()

	// Set up some bookkeeping so we can fail with a nice message if necessary.
	var (
		startTime          = time.Now()
		attempts           int
		mostRecentFailures loopTestingT
	)

	// Run the check until it completes with no assertion failures.
	waitErr := wait.PollUntilContextTimeout(context.Background(), tick, waitFor, true, func(_ context.Context) (bool, error) {
		t.Helper()
		attempts++

		// Reset the recorded failures on each iteration.
		mostRecentFailures = nil

		// Ignore any panics caused by FailNow() -- they will cause the f() to return immediately but any errors
		// they've logged should be in mostRecentFailures.
		defer recoverLoopFailNow()

		// Run the per-iteration check, recording any failed assertions into mostRecentFailures.
		f(require.New(&mostRecentFailures))

		// We're only done iterating if no assertions have failed.
		return len(mostRecentFailures) == 0, nil
	})

	// If things eventually completed with no failures/timeouts, we're done.
	if waitErr == nil {
		return
	}

	// Re-assert the most recent set of failures with a nice error log.
	duration := time.Since(startTime).Round(100 * time.Millisecond)
	t.Errorf("failed to complete even after %s (%d attempts): %v", duration, attempts, waitErr)
	for _, failure := range mostRecentFailures {
		t.Errorf(failure.format, failure.args...)
	}

	// Fail the test now with the provided message.
	require.NoError(t, waitErr, msgAndArgs...)
}

// RequireEventuallyWithoutError is similar to require.Eventually() except that it also allows the caller to
// return an error from the condition function. If the condition function returns an error at any
// point, the assertion will immediately fail.
func RequireEventuallyWithoutError(
	t *testing.T,
	f func() (bool, error),
	waitFor time.Duration,
	tick time.Duration,
	msgAndArgs ...any,
) {
	t.Helper()
	// This previously used wait.PollImmediate (now deprecated), which did not take a ctx arg in the func.
	// Hide this detail from the callers for now to keep the old signature.
	fWithCtx := func(_ context.Context) (bool, error) { return f() }
	require.NoError(t, wait.PollUntilContextTimeout(context.Background(), tick, waitFor, true, fWithCtx), msgAndArgs...)
}

// RequireNeverWithoutError is similar to require.Never() except that it also allows the caller to
// return an error from the condition function. If the condition function returns an error at any
// point, the assertion will immediately fail.
func RequireNeverWithoutError(
	t *testing.T,
	f func() (bool, error),
	waitFor time.Duration,
	tick time.Duration,
	msgAndArgs ...any,
) {
	t.Helper()
	// This previously used wait.PollImmediate (now deprecated), which did not take a ctx arg in the func.
	// Hide this detail from the callers for now to keep the old signature.
	fWithCtx := func(_ context.Context) (bool, error) { return f() }
	err := wait.PollUntilContextTimeout(context.Background(), tick, waitFor, true, fWithCtx)
	if err != nil && !wait.Interrupted(err) {
		require.NoError(t, err, msgAndArgs...) // this will fail and throw the right error message
	}
	if err == nil {
		// This prints the same error message that require.Never would print in this case.
		require.Fail(t, "Condition satisfied", msgAndArgs...)
	}
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
			assert.Equal(
				t,
				previousRestartCount,
				currentRestartCount,
				"container %s has restarted %d times (original count was %d)",
				key.String(),
				currentRestartCount,
				previousRestartCount,
			)
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
		// Ignore pods that are already terminating at the start of the test. The app may have been redeployed
		// just before the tests were invoked, so it would be normal for some pods to still be terminating
		// in that situation. Note that terminating pods in this situation do not count as a "restart" anyway.
		if pod.DeletionTimestamp != nil {
			continue
		}

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
