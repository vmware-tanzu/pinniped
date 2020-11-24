// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// +build !go1.14

package testutil

import (
	"testing"
)

func TempDir(t *testing.T) string {
	return t.TempDir()
}
