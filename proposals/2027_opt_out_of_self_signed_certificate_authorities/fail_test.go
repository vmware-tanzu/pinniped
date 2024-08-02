// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package fail_test

// TODO: remove this file before merging.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	require.Fail(t, "fail this test so that unit tests fail and integration tests do not run in CI")
}
