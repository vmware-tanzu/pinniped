// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"mime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func RequireTimeInDelta(t *testing.T, t1 time.Time, t2 time.Time, delta time.Duration) {
	require.InDeltaf(t,
		float64(t1.UnixNano()),
		float64(t2.UnixNano()),
		float64(delta.Nanoseconds()),
		"expected %s and %s to be < %s apart, but they are %s apart",
		t1.Format(time.RFC3339Nano),
		t2.Format(time.RFC3339Nano),
		delta.String(),
		t1.Sub(t2).String(),
	)
}

func RequireEqualContentType(t *testing.T, actual string, expected string) {
	t.Helper()

	if expected == "" {
		require.Empty(t, actual)
		return
	}

	actualContentType, actualContentTypeParams, err := mime.ParseMediaType(expected)
	require.NoError(t, err)
	expectedContentType, expectedContentTypeParams, err := mime.ParseMediaType(expected)
	require.NoError(t, err)
	require.Equal(t, actualContentType, expectedContentType)
	require.Equal(t, actualContentTypeParams, expectedContentTypeParams)
}
