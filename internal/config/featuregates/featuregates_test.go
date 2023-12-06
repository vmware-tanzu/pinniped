// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package featuregates

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
)

func TestEnableKubeFeatureGate(t *testing.T) {
	f := features.UnauthenticatedHTTP2DOSMitigation

	// This feature gate is currently disabled by default in the Kubernetes library.
	// Assert this as a precondition so if that ever changes during a dependency bump
	// we will be forced to take note and decide if any code deserves to change.
	require.False(t, feature.DefaultFeatureGate.Enabled(f))

	defer featuregatetesting.SetFeatureGateDuringTest(t, feature.DefaultFeatureGate, f, false)()

	require.False(t, feature.DefaultFeatureGate.Enabled(f))
	EnableKubeFeatureGate(f)
	require.True(t, feature.DefaultFeatureGate.Enabled(f))
}
