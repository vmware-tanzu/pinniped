// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
)

// Deprecated: This is meant for old tests only.
func SetGlobalKlogLevel(t *testing.T, l klog.Level) {
	t.Helper()
	_, err := logs.GlogSetter(strconv.Itoa(int(l)))
	require.NoError(t, err)
}

func GetGlobalKlogLevel() klog.Level {
	// hack around klog not exposing a Get method
	for i := klog.Level(0); i < 256; i++ {
		if klog.V(i).Enabled() {
			continue
		}
		return i - 1
	}

	return -1
}
