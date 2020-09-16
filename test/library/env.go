// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package library

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// GetEnv gets the environment variable with key and asserts that it is not
// empty. It returns the value of the environment variable.
func GetEnv(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	require.NotEmptyf(t, value, "must specify %s env var for integration tests", key)
	return value
}
