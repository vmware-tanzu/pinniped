// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !go1.14
// +build !go1.14

package testutil

import (
	"testing"
)

func TempDir(t *testing.T) string {
	return t.TempDir()
}
