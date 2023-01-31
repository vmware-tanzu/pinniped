// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package leaderelection

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/controllerinit"
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
	controllerinit.RunnerWrapper,
	error,
) {
	internalClient, err := kubeclient.New(opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create internal client for leader election: %w", err)
	}

	isLeader := &isLeaderTracker{tracker: &atomic.Bool{}}

	identity := podInfo.Name
	leaseName := deployment.Name

	leaderElectionConfig := newLeaderElectionConfig(podInfo.Namespace, leaseName, identity, internalClient.Kubernetes, isLeader)

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

		if isLeader.canWrite() { // only perform "expensive" test for writes
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

	controllersWithLeaderElector := func(ctx context.Context, controllers controllerinit.Runner) {
		plog.Debug("leader election loop start", "identity", identity)
		defer plog.Debug("leader election loop shutdown", "identity", identity)

		leaderElectorCtx, leaderElectorCancel := context.WithCancel(context.Background()) // purposefully detached context

		go func() {
			controllers(ctx) // run the controllers with the global context, this blocks until the context is canceled

			if isLeader.stop() { // remove our in-memory leader status before we release the lock
				plog.Debug("leader lost", "identity", identity, "reason", "controller stop")
			}
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

func newLeaderElectionConfig(namespace, leaseName, identity string, internalClient kubernetes.Interface, isLeader *isLeaderTracker) leaderelection.LeaderElectionConfig {
	return leaderelection.LeaderElectionConfig{
		Lock: &releaseLock{
			delegate: &resourcelock.LeaseLock{
				LeaseMeta: metav1.ObjectMeta{
					Namespace: namespace,
					Name:      leaseName,
				},
				Client: internalClient.CoordinationV1(),
				LockConfig: resourcelock.ResourceLockConfig{
					Identity: identity,
				},
			},
			isLeader: isLeader,
			identity: identity,
		},
		ReleaseOnCancel: true, // semantics for correct release handled by releaseLock.Update and controllersWithLeaderElector below

		// Copied from defaults used in OpenShift since we want the same semantics:
		// https://github.com/openshift/library-go/blob/e14e06ba8d476429b10cc6f6c0fcfe6ea4f2c591/pkg/config/leaderelection/leaderelection.go#L87-L109
		LeaseDuration: 137 * time.Second,
		RenewDeadline: 107 * time.Second,
		RetryPeriod:   26 * time.Second,

		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(_ context.Context) {
				plog.Debug("leader gained", "identity", identity)
				isLeader.start()
			},
			OnStoppedLeading: func() {
				if isLeader.stop() { // barring changes to client-go, this branch should only be taken on a panic
					plog.Debug("leader lost", "identity", identity, "reason", "on stop")
				}
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
}

type isLeaderTracker struct {
	tracker *atomic.Bool
}

func (t *isLeaderTracker) canWrite() bool {
	return t.tracker.Load()
}

func (t *isLeaderTracker) start() {
	t.tracker.Store(true)
}

func (t *isLeaderTracker) stop() (didStop bool) {
	return t.tracker.CompareAndSwap(true, false)
}

// note that resourcelock.Interface is an internal, unstable interface.
// so while it would be convenient to embed the implementation within
// this struct, we need to make sure our Update override is used and
// that no other methods are added that change the meaning of the
// interface.  thus we must have ~20 lines of boilerplate to have the
// compiler ensure that we keep up with this interface over time.
var _ resourcelock.Interface = &releaseLock{}

// releaseLock works around a limitation of the client-go leader election code:
// there is no "BeforeRelease" callback.  By the time the "OnStoppedLeading"
// callback runs (this callback is meant to always run at the very end since it
// normally terminates the process), we have already released the lock.  This
// creates a race condition in between the release call (the Update func) and the
// stop callback where a different client could acquire the lease while we still
// believe that we hold the lease in our in-memory leader status.
type releaseLock struct {
	delegate resourcelock.Interface // do not embed this, see comment above
	isLeader *isLeaderTracker
	identity string
}

func (r *releaseLock) Update(ctx context.Context, ler resourcelock.LeaderElectionRecord) error {
	// setting an empty HolderIdentity on update means that the client is releasing the lock.
	// thus we need to make sure to update our in-memory leader status before this occurs
	// since other clients could immediately acquire the lock.  note that even if the Update
	// call below fails, this client has already chosen to release the lock and thus we must
	// update the in-memory status regardless of it we succeed in making the Kube API call.
	// note that while resourcelock.Interface is an unstable interface, the meaning of an
	// empty HolderIdentity is encoded into the Kube API and thus we can safely rely on that
	// not changing (since changing that would break older clients).
	if len(ler.HolderIdentity) == 0 && r.isLeader.stop() {
		plog.Debug("leader lost", "identity", r.identity, "reason", "release")
	}

	return r.delegate.Update(ctx, ler)
}

// boilerplate passthrough methods below

func (r *releaseLock) Get(ctx context.Context) (*resourcelock.LeaderElectionRecord, []byte, error) {
	return r.delegate.Get(ctx)
}

func (r *releaseLock) Create(ctx context.Context, ler resourcelock.LeaderElectionRecord) error {
	return r.delegate.Create(ctx, ler)
}

func (r *releaseLock) RecordEvent(s string) {
	r.delegate.RecordEvent(s)
}

func (r *releaseLock) Identity() string {
	return r.delegate.Identity()
}

func (r *releaseLock) Describe() string {
	return r.delegate.Describe()
}
