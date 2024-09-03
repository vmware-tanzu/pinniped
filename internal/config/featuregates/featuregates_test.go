// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package featuregates

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
)

func TestEnableAndDisableKubeFeatureGate(t *testing.T) {
	f := features.UnauthenticatedHTTP2DOSMitigation

	// This feature gate is currently enabled by default in the Kubernetes library.
	// Assert this as a precondition.
	require.True(t, feature.DefaultFeatureGate.Enabled(f))

	// Set it back to its default value of true at the end of this test.
	featuregatetesting.SetFeatureGateDuringTest(t, feature.DefaultFeatureGate, f, true)

	EnableKubeFeatureGate(f)
	require.True(t, feature.DefaultFeatureGate.Enabled(f))

	DisableKubeFeatureGate(f)
	require.False(t, feature.DefaultFeatureGate.Enabled(f))

	DisableKubeFeatureGate(f)
	require.False(t, feature.DefaultFeatureGate.Enabled(f))

	EnableKubeFeatureGate(f)
	require.True(t, feature.DefaultFeatureGate.Enabled(f))
}
