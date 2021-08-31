// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"go.pinniped.dev/internal/controllerinit"
	"go.pinniped.dev/test/testlib"
)

// this just makes some slow read requests which are safe to run in parallel with serial tests, see main_test.go.
func TestControllerInitPrepare_Parallel(t *testing.T) {
	_ = testlib.IntegrationEnv(t)

	t.Run("with parent context that is never canceled", func(t *testing.T) {
		t.Parallel()

		// the nil params should never be used in this case
		buildControllers := controllerinit.Prepare(nil, nil, buildBrokenInformer(t))

		start := time.Now()
		runControllers, err := buildControllers(context.Background()) // we expect this to not block forever even with a context.Background()
		delta := time.Since(start)

		require.EqualError(t, err,
			"failed to sync informers of k8s.io/client-go/informers.sharedInformerFactory: "+
				"[k8s.io/api/core/v1.Namespace k8s.io/api/core/v1.Node]")
		require.Nil(t, runControllers)

		require.InDelta(t, time.Minute, delta, float64(30*time.Second))
	})

	t.Run("with parent context that is canceled early", func(t *testing.T) {
		t.Parallel()

		// the nil params should never be used in this case
		buildControllers := controllerinit.Prepare(nil, nil, buildBrokenInformer(t))

		// we expect this to exit sooner because the parent context is shorter
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)

		start := time.Now()
		runControllers, err := buildControllers(ctx)
		delta := time.Since(start)

		require.EqualError(t, err,
			"failed to sync informers of k8s.io/client-go/informers.sharedInformerFactory: "+
				"[k8s.io/api/core/v1.Namespace k8s.io/api/core/v1.Node]")
		require.Nil(t, runControllers)

		require.InDelta(t, 10*time.Second, delta, float64(15*time.Second))
	})
}

func buildBrokenInformer(t *testing.T) kubeinformers.SharedInformerFactory {
	t.Helper()

	config := testlib.NewClientConfig(t)
	config = rest.CopyConfig(config)
	config.Impersonate.UserName = "user-with-no-rbac" // so we can test that we correctly detect a cache sync failure

	client := kubernetes.NewForConfigOrDie(config)

	informers := kubeinformers.NewSharedInformerFactoryWithOptions(client, 0)

	// make sure some informers gets lazily loaded
	_ = informers.Core().V1().Nodes().Informer()
	_ = informers.Core().V1().Namespaces().Informer()

	return informers
}
