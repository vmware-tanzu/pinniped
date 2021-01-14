// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package library

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/wait"
)

// RequireEventuallyWithoutError is a wrapper around require.Eventually() that allows the caller to
// return an error from the condition function. If the condition function returns an error at any
// point, the assertion will immediately fail.
func RequireEventuallyWithoutError(
	t *testing.T,
	f func() (bool, error),
	waitFor time.Duration,
	tick time.Duration,
	msgAndArgs ...interface{},
) {
	t.Helper()
	require.NoError(t, wait.PollImmediate(tick, waitFor, f), msgAndArgs...)
}
