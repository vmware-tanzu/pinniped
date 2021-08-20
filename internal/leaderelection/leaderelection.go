// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package leaderelection

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/atomic"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/downward"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/plog"
)

const ErrNotLeader constable.Error = "write attempt rejected as client is not leader"

// New returns a client that has a leader election middleware injected into it.
// This middleware will prevent all non-read requests to the Kubernetes API when
// the current process does not hold the leader election lock.  Unlike normal
// leader election where the process blocks until it acquires the lock, this
// middleware approach lets the process run as normal for all read requests.
// Another difference is that if the process acquires the lock and then loses it
// (i.e. a failed renewal), it will not exit (i.e. restart).  Instead, it will
// simply attempt to acquire the lock again.
//
// The returned function is blocking and will run the leader election polling
// logic and will coordinate lease release with the input controller starter function.
func New(podInfo *downward.PodInfo, deployment *appsv1.Deployment, opts ...kubeclient.Option) (
	*kubeclient.Client,
	func(context.Context, func(context.Context)),
	error,
) {
	internalClient, err := kubeclient.New(opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create internal client for leader election: %w", err)
	}

	isLeader := atomic.NewBool(false)

	identity := podInfo.Name
	leaseName := deployment.Name

	leaderElectionConfig := leaderelection.LeaderElectionConfig{
		Lock: &resourcelock.LeaseLock{
			LeaseMeta: metav1.ObjectMeta{
				Namespace: podInfo.Namespace,
				Name:      leaseName,
			},
			Client: internalClient.Kubernetes.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{
				Identity: identity,
			},
		},
		ReleaseOnCancel: true, // semantics for correct release handled by controllersWithLeaderElector below
		LeaseDuration:   60 * time.Second,
		RenewDeadline:   15 * time.Second,
		RetryPeriod:     5 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(_ context.Context) {
				plog.Debug("leader gained", "identity", identity)
				isLeader.Store(true)
			},
			OnStoppedLeading: func() {
				plog.Debug("leader lost", "identity", identity)
				isLeader.Store(false)
			},
			OnNewLeader: func(newLeader string) {
				if newLeader == identity {
					return
				}
				plog.Debug("new leader elected", "newLeader", newLeader)
			},
		},
		Name: leaseName,
		// this must be set to nil because we do not want to associate /healthz with a failed
		// leader election renewal as we do not want to exit the process if the leader changes.
		WatchDog: nil,
	}

	// validate our config here before we rely on it being functioning below
	if _, err := leaderelection.NewLeaderElector(leaderElectionConfig); err != nil {
		return nil, nil, fmt.Errorf("invalid config - could not create leader elector: %w", err)
	}

	writeOnlyWhenLeader := kubeclient.MiddlewareFunc(func(_ context.Context, rt kubeclient.RoundTrip) {
		switch rt.Verb() {
		case kubeclient.VerbGet, kubeclient.VerbList, kubeclient.VerbWatch:
			// reads are always allowed.
			// note that while our pods/exec into the kube cert agent pod is a write request from the
			// perspective of the Kube API, it is semantically a read request since no mutation occurs.
			// we simply use it to fill a cache, and we need all pods to have a functioning cache.
			// however, we do not need to handle it here because remotecommand.NewSPDYExecutor uses a
			// kubeclient.Client.JSONConfig as input.  since our middleware logic is only injected into
			// the generated clientset code, this JSONConfig simply ignores this middleware all together.
			return
		}

		if isLeader.Load() { // only perform "expensive" test for writes
			return // we are currently the leader, all actions are permitted
		}

		rt.MutateRequest(func(_ kubeclient.Object) error {
			return ErrNotLeader // we are not the leader, fail the write request
		})
	})

	leaderElectionOpts := append(
		// all middleware are always executed so this being the first middleware is not relevant
		[]kubeclient.Option{kubeclient.WithMiddleware(writeOnlyWhenLeader)},
		opts..., // do not mutate input slice
	)

	client, err := kubeclient.New(leaderElectionOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create leader election client: %w", err)
	}

	controllersWithLeaderElector := func(ctx context.Context, controllers func(context.Context)) {
		leaderElectorCtx, leaderElectorCancel := context.WithCancel(context.Background()) // purposefully detached context

		go func() {
			controllers(ctx)      // run the controllers with the global context, this blocks until the context is canceled
			leaderElectorCancel() // once the controllers have all stopped, tell the leader elector to release the lock
		}()

		for { // run (and rerun on release) the leader elector with its own context (blocking)
			select {
			case <-leaderElectorCtx.Done():
				return // keep trying to run until process exit

			default:
				// blocks while trying to acquire lease, unblocks on release.
				// note that this creates a new leader elector on each loop to
				// prevent any bugs from reusing that struct across elections.
				// our config was validated above so this should never die.
				leaderelection.RunOrDie(leaderElectorCtx, leaderElectionConfig)
			}
		}
	}

	return client, controllersWithLeaderElector, nil
}
