// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestState(t *testing.T) {
	s, err := Generate()
	require.NoError(t, err)
	require.Len(t, s, 32)
	require.Len(t, s.String(), 32)
	require.True(t, s.Valid(string(s)))
	require.False(t, s.Valid(string(s)+"x"))

	var empty bytes.Buffer
	s, err = generate(&empty)
	require.EqualError(t, err, "could not generate random state: EOF")
	require.Empty(t, s)
}
