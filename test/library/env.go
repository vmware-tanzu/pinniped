/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package library

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// Getenv gets the environment variable with key and asserts that it is not
// empty. It returns the value of the environment variable.
func Getenv(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	require.NotEmptyf(t, value, "must specify %s env var for integration tests", key)
	return value
}
