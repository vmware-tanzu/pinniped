// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tlsassertions

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetTLSErrorPrefix(t *testing.T) {
	expected := "tls: failed to verify certificate: "

	if strings.Contains(runtime.Version(), "1.19") {
		expected = ""
	}

	require.Equal(t, expected, GetTLSErrorPrefix())
}
