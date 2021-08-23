// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package leaderelection

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/utils/pointer"
)

// see test/integration/leaderelection_test.go for the bulk of the testing related to this code

func Test_releaseLock_Update(t *testing.T) {
	tests := []struct {
		name string
		f    func(t *testing.T, internalClient *kubefake.Clientset, isLeader *isLeaderTracker, cancel context.CancelFunc)
	}{
		{
			name: "renewal fails on update",
			f: func(t *testing.T, internalClient *kubefake.Clientset, isLeader *isLeaderTracker, cancel context.CancelFunc) {
				internalClient.PrependReactor("update", "*", func(action kubetesting.Action) (handled bool, ret runtime.Object, err error) {
					lease := action.(kubetesting.UpdateAction).GetObject().(*coordinationv1.Lease)
					if len(pointer.StringDeref(lease.Spec.HolderIdentity, "")) == 0 {
						require.False(t, isLeader.canWrite(), "client must release in-memory leader status before Kube API call")
					}
					return true, nil, errors.New("cannot renew")
				})
			},
		},
		{
			name: "renewal fails due to context",
			f: func(t *testing.T, internalClient *kubefake.Clientset, isLeader *isLeaderTracker, cancel context.CancelFunc) {
				t.Cleanup(func() {
					require.False(t, isLeader.canWrite(), "client must release in-memory leader status when context is canceled")
				})
				start := time.Now()
				internalClient.PrependReactor("update", "*", func(action kubetesting.Action) (handled bool, ret runtime.Object, err error) {
					// keep going for a bit
					if time.Since(start) < 5*time.Second {
						return false, nil, nil
					}

					cancel()
					return false, nil, nil
				})
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			internalClient := kubefake.NewSimpleClientset()
			isLeader := &isLeaderTracker{tracker: atomic.NewBool(false)}

			leaderElectorCtx, cancel := context.WithCancel(context.Background())

			tt.f(t, internalClient, isLeader, cancel)

			leaderElectionConfig := newLeaderElectionConfig("ns-001", "lease-001", "foo-001", internalClient, isLeader)

			// make the tests run quicker
			leaderElectionConfig.LeaseDuration = 2 * time.Second
			leaderElectionConfig.RenewDeadline = 1 * time.Second
			leaderElectionConfig.RetryPeriod = 250 * time.Millisecond

			// note that this will block until it exits on its own or tt.f calls cancel()
			leaderelection.RunOrDie(leaderElectorCtx, leaderElectionConfig)
		})
	}
}
