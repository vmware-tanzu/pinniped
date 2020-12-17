// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/cache"
)

func TestCacheMutationDetectorEnabled(t *testing.T) {
	// this is a bit of simplistic test to check if we have a real cache mutation detector.
	// if we actually start mutating an informer cache in this test, the test will almost
	// always fail because the go race detector will see the mutation.
	// the cache mutation detector will certainly make certain races more common and thus
	// easily detected by the race detector, but its real use is against a compiled binary
	// such as pinniped-server running in a pod - that binary has no race detector at runtime.

	c := cache.NewCacheMutationDetector("test pinniped")

	type realCacheMutationDetector interface {
		CompareObjects() // this is brittle, but this function name has never changed...
	}
	require.Implementsf(t, (*realCacheMutationDetector)(nil), c, "%T is not a real cache mutation detector", c)
}
