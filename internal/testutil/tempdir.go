// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"io/ioutil" //nolint:staticcheck // ioutil is deprecated, but this file is for go1.14
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TempDir(t *testing.T) string {
	t.Helper()
	dir, err := ioutil.TempDir("", "test-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, os.RemoveAll(dir))
	})
	return dir
}
