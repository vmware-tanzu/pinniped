// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/test/testlib"
)

// TestPodShutdown_Disruptive is intended to test that the Supervisor and Concierge pods can
// perform a graceful shutdown. Most importantly, the leader pods should give up their leases
// before they die.
// Never run this test in parallel since deleting the pods is disruptive, see main_test.go.
func TestPodShutdown_Disruptive(t *testing.T) {
	env := testEnvForPodShutdownTests(t)

	shutdownAllPodsOfApp(t, env, env.ConciergeNamespace, env.ConciergeAppName, true)
	shutdownAllPodsOfApp(t, env, env.SupervisorNamespace, env.SupervisorAppName, false)
}

// testEnvForPodShutdownTests builds an env with the following description:
// Only run this test in CI on Kind clusters, because something about restarting the pods
// in this test breaks the "kubectl port-forward" commands that we are using in CI for
// AKS, EKS, and GKE clusters. The Go code that we wrote for graceful pod shutdown should
// not be sensitive to which distribution it runs on, so running this test only on Kind
// should give us sufficient coverage for what we are trying to test here.
func testEnvForPodShutdownTests(t *testing.T) *testlib.TestEnv {
	return testlib.IntegrationEnv(t, testlib.SkipPodRestartAssertions()).WithKubeDistribution(testlib.KindDistro)
}

func shutdownAllPodsOfApp(
	t *testing.T,
	env *testlib.TestEnv,
	namespace string,
	appName string,
	isConcierge bool,
) {
	t.Helper()

	ignorePodsWithNameSubstring := ""
	if isConcierge {
		ignorePodsWithNameSubstring = "-kube-cert-agent-"
	}

	// Precondition: the app should have some pods running initially.
	initialPods := getRunningPodsByNamePrefix(t, namespace, appName+"-", ignorePodsWithNameSubstring)
	require.Greater(t, len(initialPods), 0)

	// Precondition: the leader election lease should contain the name of one of the initial pods as the lease's holder.
	waitForLeaderElectionLeaseToHaveHolderIdentity(t, namespace, appName,
		func(holder string) bool { return holder != "" && slices.Contains(namesOfPods(initialPods), holder) }, 2*time.Minute)

	// Start tailing the logs of all the pods in background goroutines. This struct will keep track
	// of each background log tail.
	type podLog struct {
		pod        corev1.Pod    // which pod's logs are being tailed
		tailDoneCh chan struct{} // this channel will be closed when it is safe to read from logsBuf
		logsBuf    *bytes.Buffer // the text of the logs will be put in this buffer
	}
	podLogs := make([]*podLog, 0)
	// Skip tailing pod logs for test runs that are using alternate group suffixes. There seems to be a bug in our
	// kubeclient package which causes an "unable to find resp serialier" (sic) error for pod log API responses when
	// the middleware is active. Since we do not tail pod logs in production code (or anywhere else at this time),
	// we don't need to fix that bug right now just for this test.
	if env.APIGroupSuffix == "pinniped.dev" {
		// For each pod, start tailing its logs.
		for _, pod := range initialPods {
			tailDoneCh, logTailBuf := tailFollowPodLogs(t, pod)
			podLogs = append(podLogs, &podLog{
				pod:        pod,
				tailDoneCh: tailDoneCh,
				logsBuf:    logTailBuf,
			})
		}
	}

	// Scale down the deployment's number of replicas to 0, which will shut down all the pods.
	originalScale := updateDeploymentScale(t, namespace, appName, 0)

	// When the test is over, restore the deployment to the original scale.
	t.Cleanup(func() {
		updateDeploymentScale(t, namespace, appName, originalScale)

		// Wait for all the new pods to be running and ready.
		var newPods []corev1.Pod
		testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
			newPods = getRunningPodsByNamePrefix(t, namespace, appName+"-", ignorePodsWithNameSubstring)
			requireEventually.Equal(len(newPods), int(originalScale), "wanted pods to return to original scale")
			requireEventually.True(allPodsReady(newPods), "wanted all new pods to be ready")
		}, 2*time.Minute, 200*time.Millisecond)

		// After a short time, leader election should have finished and the lease should contain the name of
		// one of the new pods as the lease's holder.
		waitForLeaderElectionLeaseToHaveHolderIdentity(t, namespace, appName,
			func(holder string) bool { return holder != "" && slices.Contains(namesOfPods(newPods), holder) }, 1*time.Minute)

		t.Logf("new pod of Deployment %s/%s has acquired the leader election lease", namespace, appName)
	})

	// Double check: the deployment's previous scale should have equaled the actual number of running pods from
	// the start of the test (before we scaled down).
	require.Equal(t, len(initialPods), int(originalScale))

	// Now that we have adjusted the scale to 0, the pods should go away.
	// Our pods are intended to gracefully shut down within a few seconds, so fail unless it happens fairly quickly.
	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		pods := getRunningPodsByNamePrefix(t, namespace, appName+"-", ignorePodsWithNameSubstring)
		requireEventually.Len(pods, 0, "wanted no pods but found some")
	}, 20*time.Second, 200*time.Millisecond)

	// Look for some interesting log messages in each of the now-dead pod's logs, if we started tailing them above.
	for _, pl := range podLogs {
		// Wait for the logs of the now-dead pod to be finished collecting.
		t.Logf("waiting for tail of pod logs for pod %q", pl.pod.Name)
		<-pl.tailDoneCh
		// Assert that the Kubernetes generic apiserver library has started and finished a graceful
		// shutdown according to its log messages. This is to make sure that the whole graceful shutdown
		// process was performed successfully and without being blocked.
		require.Containsf(t, pl.logsBuf.String(), `"[graceful-termination] shutdown event","name":"ShutdownInitiated"`,
			"did not find expected message in pod log for pod %q", pl.pod.Name)
		require.Containsf(t, pl.logsBuf.String(), `[graceful-termination] apiserver is exiting`,
			"did not find expected message in pod log for pod %q", pl.pod.Name)

		if isConcierge {
			require.Containsf(t, pl.logsBuf.String(), `fetch-impersonation-proxy-tokens start hook's background goroutine has finished`,
				"did not find expected message in pod log for pod %q", pl.pod.Name)
		}

		t.Logf("found expected graceful-termination messages in the logs of pod %q", pl.pod.Name)
	}

	// The leader election lease should already contain the empty string as the holder, because the old leader
	// pod should have given up the lease during its graceful shutdown.
	waitForLeaderElectionLeaseToHaveHolderIdentity(t, namespace, appName,
		func(holder string) bool { return holder == "" }, 1*time.Minute)
}

// Given a list of pods, return a list of their names.
func namesOfPods(pods []corev1.Pod) []string {
	names := make([]string, len(pods))
	for i, pod := range pods {
		names[i] = pod.Name
	}
	return names
}

func getRunningPodsByNamePrefix(
	t *testing.T,
	namespace string,
	podNamePrefix string,
	podNameExcludeSubstring string,
) (foundPods []corev1.Pod) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	client := testlib.NewKubernetesClientset(t)

	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	require.NoError(t, err)

	for _, pod := range pods.Items {
		if !strings.HasPrefix(pod.Name, podNamePrefix) {
			continue
		}
		if podNameExcludeSubstring != "" && strings.Contains(pod.Name, podNameExcludeSubstring) {
			continue
		}
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		foundPods = append(foundPods, pod)
	}

	return foundPods
}

func allPodsReady(pods []corev1.Pod) bool {
	for _, pod := range pods {
		if !isPodReady(pod) {
			return false
		}
	}
	return true
}

func isPodReady(pod corev1.Pod) bool {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

func updateDeploymentScale(t *testing.T, namespace string, deploymentName string, newScale int32) int32 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	client := testlib.NewKubernetesClientset(t)

	initialScale, err := client.AppsV1().Deployments(namespace).GetScale(ctx, deploymentName, metav1.GetOptions{})
	require.NoError(t, err)

	desiredScale := initialScale.DeepCopy()
	desiredScale.Spec.Replicas = newScale
	updatedScale, err := client.AppsV1().Deployments(namespace).UpdateScale(ctx, deploymentName, desiredScale, metav1.UpdateOptions{})
	require.NoError(t, err)
	t.Logf("updated scale of Deployment %s/%s from %d to %d",
		namespace, deploymentName, initialScale.Spec.Replicas, updatedScale.Spec.Replicas)

	return initialScale.Spec.Replicas
}

func tailFollowPodLogs(t *testing.T, pod corev1.Pod) (chan struct{}, *bytes.Buffer) {
	t.Helper()
	done := make(chan struct{})
	var buf bytes.Buffer
	client := testlib.NewKubernetesClientset(t)

	go func() {
		// At the end of this block, signal that we are done writing to the returned buf,
		// so it is now safe to read the logs from the returned buf.
		defer close(done)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		req := client.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
			Follow: true, // keep streaming until completion
		})

		// This line should block until the pod dies or the context expires.
		body, err := req.Stream(ctx)
		require.NoError(t, err)

		_, err = io.Copy(&buf, body)
		require.NoError(t, err)

		require.NoError(t, body.Close())
	}()

	return done, &buf
}

func waitForLeaderElectionLeaseToHaveHolderIdentity(
	t *testing.T,
	namespace string,
	leaseName string,
	holderIdentityPredicate func(string) bool,
	waitDuration time.Duration,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitDuration*2)
	defer cancel()
	client := testlib.NewKubernetesClientset(t)

	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		lease, err := client.CoordinationV1().Leases(namespace).Get(ctx, leaseName, metav1.GetOptions{})
		requireEventually.NoError(err)
		requireEventually.Truef(holderIdentityPredicate(*lease.Spec.HolderIdentity),
			"leader election lease had holder %s", *lease.Spec.HolderIdentity)
	}, waitDuration, 200*time.Millisecond)
}
