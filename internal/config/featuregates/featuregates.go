// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package featuregates

import (
	"k8s.io/apiserver/pkg/util/feature"
	"k8s.io/component-base/featuregate"

	"go.pinniped.dev/internal/plog"
)

func EnableKubeFeatureGate(f featuregate.Feature) {
	initialValue := feature.DefaultFeatureGate.Enabled(f)

	if err := feature.DefaultMutableFeatureGate.SetFromMap(map[string]bool{string(f): true}); err != nil {
		panic(err) // this should never happen as long as a feature gate still exists
	}

	plog.Always("feature gate status",
		"name", f,
		"initialEnabledValue", initialValue,
		"updatedEnabledValue", feature.DefaultFeatureGate.Enabled(f),
	)
}
