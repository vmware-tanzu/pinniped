// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/pointer"

	"go.pinniped.dev/internal/downward"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/leaderelection"
	"go.pinniped.dev/test/testlib"
)

// safe to run in parallel with serial tests since it only interacts with a test local lease, see main_test.go.
func TestLeaderElection_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	t.Cleanup(cancel)

	leaseName := "leader-election-" + rand.String(5)

	namespace := testlib.CreateNamespace(ctx, t, leaseName)

	clients, cancels := leaderElectionClients(t, namespace, leaseName)

	// the tests below are order dependant to some degree and definitely cannot be run in parallel

	t.Run("sanity check write prevention", func(t *testing.T) {
		lease := checkOnlyLeaderCanWrite(ctx, t, namespace, leaseName, clients)
		logLease(t, lease)
	})

	t.Run("clients handle leader election transition correctly", func(t *testing.T) {
		lease := forceTransition(ctx, t, namespace, leaseName, clients)
		logLease(t, lease)
	})

	t.Run("sanity check write prevention after transition", func(t *testing.T) {
		lease := checkOnlyLeaderCanWrite(ctx, t, namespace, leaseName, clients)
		logLease(t, lease)
	})

	t.Run("clients handle leader election restart correctly", func(t *testing.T) {
		lease := forceRestart(ctx, t, namespace, leaseName, clients)
		logLease(t, lease)
	})

	t.Run("sanity check write prevention after restart", func(t *testing.T) {
		lease := checkOnlyLeaderCanWrite(ctx, t, namespace, leaseName, clients)
		logLease(t, lease)
	})

	t.Run("stop current leader", func(t *testing.T) {
		startLease := waitForIdentity(ctx, t, namespace, leaseName, clients)
		startTransitions := *startLease.Spec.LeaseTransitions
		startTime := *startLease.Spec.AcquireTime
		startLeaderIdentity := *startLease.Spec.HolderIdentity

		leaderClient := clients[startLeaderIdentity]

		err := runWriteRequest(ctx, leaderClient)
		require.NoError(t, err)

		// emulate stopping the leader process
		cancels[startLeaderIdentity]()
		delete(clients, startLeaderIdentity)

		testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
			err := runWriteRequest(ctx, leaderClient)
			requireEventually.ErrorIs(err, leaderelection.ErrNotLeader, "leader should no longer be able to write")
		}, time.Minute, time.Second)

		if len(clients) > 0 {
			finalLease := waitForIdentity(ctx, t, namespace, leaseName, clients)
			finalTransitions := *finalLease.Spec.LeaseTransitions
			finalTime := *finalLease.Spec.AcquireTime
			finalLeaderIdentity := *finalLease.Spec.HolderIdentity

			require.Greater(t, finalTransitions, startTransitions)
			require.Greater(t, finalTime.UnixNano(), startTime.UnixNano())
			require.NotEqual(t, startLeaderIdentity, finalLeaderIdentity, "should have elected new leader")

			logLease(t, finalLease)
		}
	})

	t.Run("sanity check write prevention after stopping leader", func(t *testing.T) {
		if len(clients) == 0 {
			t.Skip("no clients left to check")
		}

		lease := checkOnlyLeaderCanWrite(ctx, t, namespace, leaseName, clients)
		logLease(t, lease)
	})
}

func leaderElectionClient(t *testing.T, namespace *corev1.Namespace, leaseName, identity string) (*kubeclient.Client, context.CancelFunc) {
	t.Helper()

	podInfo := &downward.PodInfo{
		Namespace: namespace.Name,
		Name:      identity,
	}
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: leaseName}}

	client, leaderElector, err := leaderelection.New(podInfo, deployment, testlib.NewKubeclientOptions(t, testlib.NewClientConfig(t))...)
	require.NoError(t, err)

	controllerCtx, controllerCancel := context.WithCancel(context.Background())
	leaderCtx, leaderCancel := context.WithCancel(context.Background())

	t.Cleanup(func() {
		controllerCancel()

		select {
		case <-leaderCtx.Done():
			// leader election client stopped correctly

		case <-time.After(time.Minute):
			t.Errorf("leader election client in namespace %q with lease %q and identity %q failed to stop",
				namespace.Name, leaseName, identity)
		}
	})

	go func() {
		time.Sleep(time.Duration(rand.Int63nRange(1, 10)) * time.Second) // randomize start of client and controllers

		// this blocks
		leaderElector(controllerCtx, func(ctx context.Context) {
			<-ctx.Done()
			time.Sleep(time.Duration(rand.Int63nRange(1, 10)) * time.Second) // randomize stop of controllers
		})

		select {
		case <-controllerCtx.Done():
			// leaderElector correctly stopped but only after controllers stopped

		default:
			t.Errorf("leader election client in namespace %q with lease %q and identity %q stopped early",
				namespace.Name, leaseName, identity)
		}

		leaderCancel()
	}()

	return client, controllerCancel
}

func leaderElectionClients(t *testing.T, namespace *corev1.Namespace, leaseName string) (map[string]*kubeclient.Client, map[string]context.CancelFunc) {
	t.Helper()

	count := rand.IntnRange(1, 6)
	clients := make(map[string]*kubeclient.Client, count)
	cancels := make(map[string]context.CancelFunc, count)

	for i := 0; i < count; i++ {
		identity := "leader-election-client-" + rand.String(5)
		clients[identity], cancels[identity] = leaderElectionClient(t, namespace, leaseName, identity)
	}

	t.Logf("running leader election client tests with %d clients: %v", len(clients), sets.StringKeySet(clients).List())

	return clients, cancels
}

func pickRandomLeaderElectionClient(clients map[string]*kubeclient.Client) *kubeclient.Client {
	for _, client := range clients {
		client := client
		return client
	}
	panic("clients map was empty")
}

func waitForIdentity(ctx context.Context, t *testing.T, namespace *corev1.Namespace, leaseName string, clients map[string]*kubeclient.Client) *coordinationv1.Lease {
	t.Helper()

	identities := sets.StringKeySet(clients)
	var out *coordinationv1.Lease

	testlib.RequireEventuallyWithoutError(t, func() (bool, error) {
		lease, err := pickRandomLeaderElectionClient(clients).Kubernetes.CoordinationV1().Leases(namespace.Name).Get(ctx, leaseName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			t.Logf("lease %s/%s does not exist", namespace.Name, leaseName)
			return false, nil
		}
		if err != nil {
			return false, err
		}
		out = lease
		t.Logf("lease %s/%s - current leader identity: %s, valid leader identities: %s",
			namespace.Name, leaseName, pointer.StringDeref(lease.Spec.HolderIdentity, "<nil>"), identities.List())
		return lease.Spec.HolderIdentity != nil && identities.Has(*lease.Spec.HolderIdentity), nil
	}, 10*time.Minute, 10*time.Second)

	return out
}

func runWriteRequest(ctx context.Context, client *kubeclient.Client) error {
	_, err := client.Kubernetes.AuthenticationV1().TokenReviews().Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: "any-non-empty-value"},
	}, metav1.CreateOptions{})
	return err
}

func runWriteRequests(ctx context.Context, clients map[string]*kubeclient.Client) map[string]error {
	out := make(map[string]error, len(clients))

	for identity, client := range clients {
		identity, client := identity, client

		out[identity] = runWriteRequest(ctx, client)
	}

	return out
}

func pickCurrentLeaderClient(ctx context.Context, t *testing.T, namespace *corev1.Namespace, leaseName string, clients map[string]*kubeclient.Client) *kubeclient.Client {
	t.Helper()

	lease := waitForIdentity(ctx, t, namespace, leaseName, clients)
	return clients[*lease.Spec.HolderIdentity]
}

func checkOnlyLeaderCanWrite(ctx context.Context, t *testing.T, namespace *corev1.Namespace, leaseName string, clients map[string]*kubeclient.Client) *coordinationv1.Lease {
	t.Helper()

	lease := waitForIdentity(ctx, t, namespace, leaseName, clients)

	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		var leaders, nonLeaders int
		for identity, err := range runWriteRequests(ctx, clients) {
			identity, err := identity, err

			if identity == *lease.Spec.HolderIdentity {
				leaders++
				requireEventually.NoError(err, "leader client %q should have no error", identity)
			} else {
				nonLeaders++
				requireEventually.Error(err, "non leader client %q should have write error but it was nil", identity)
				requireEventually.ErrorIs(err, leaderelection.ErrNotLeader, "non leader client %q should have write error: %v", identity, err)
			}
		}
		requireEventually.Equal(1, leaders, "did not see leader")
		requireEventually.Equal(len(clients)-1, nonLeaders, "did not see non-leader")
	}, 3*time.Minute, 3*time.Second)

	return lease
}

func forceTransition(ctx context.Context, t *testing.T, namespace *corev1.Namespace, leaseName string, clients map[string]*kubeclient.Client) *coordinationv1.Lease {
	t.Helper()

	var startTransitions int32
	var startTime metav1.MicroTime

	errRetry := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		startLease := waitForIdentity(ctx, t, namespace, leaseName, clients)
		startTransitions = *startLease.Spec.LeaseTransitions
		startTime = *startLease.Spec.AcquireTime

		startLease = startLease.DeepCopy()
		startLease.Spec.HolderIdentity = pointer.String("some-other-client-" + rand.String(5))

		_, err := pickCurrentLeaderClient(ctx, t, namespace, leaseName, clients).
			Kubernetes.CoordinationV1().Leases(namespace.Name).Update(ctx, startLease, metav1.UpdateOptions{})
		return err
	})
	require.NoError(t, errRetry)

	finalLease := waitForIdentity(ctx, t, namespace, leaseName, clients)
	finalTransitions := *finalLease.Spec.LeaseTransitions
	finalTime := *finalLease.Spec.AcquireTime

	require.Greater(t, finalTransitions, startTransitions)
	require.Greater(t, finalTime.UnixNano(), startTime.UnixNano())

	return finalLease
}

func forceRestart(ctx context.Context, t *testing.T, namespace *corev1.Namespace, leaseName string, clients map[string]*kubeclient.Client) *coordinationv1.Lease {
	t.Helper()

	startLease := waitForIdentity(ctx, t, namespace, leaseName, clients)

	err := pickCurrentLeaderClient(ctx, t, namespace, leaseName, clients).
		Kubernetes.CoordinationV1().Leases(namespace.Name).Delete(ctx, leaseName, metav1.DeleteOptions{})
	require.NoError(t, err)

	newLease := waitForIdentity(ctx, t, namespace, leaseName, clients)
	require.Zero(t, *newLease.Spec.LeaseTransitions)
	require.Greater(t, newLease.Spec.AcquireTime.UnixNano(), startLease.Spec.AcquireTime.UnixNano())

	return newLease
}

func logLease(t *testing.T, lease *coordinationv1.Lease) {
	t.Helper()

	bytes, err := json.MarshalIndent(lease, "", "\t")
	require.NoError(t, err)

	t.Logf("current lease:\n%s", string(bytes))
}
