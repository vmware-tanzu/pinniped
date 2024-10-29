// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func RequireLogLines(t *testing.T, wantLogs []string, log *bytes.Buffer) {
	t.Helper()

	expectedLogs := ""
	if len(wantLogs) > 0 {
		expectedLogs = strings.Join(wantLogs, "\n") + "\n"
	}
	require.Equal(t, expectedLogs, log.String())
}
