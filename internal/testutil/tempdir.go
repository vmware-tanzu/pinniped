// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"testing"
)

func TempDir(t *testing.T) string {
	return t.TempDir()
}
