// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestState(t *testing.T) {
	s, err := Generate()
	require.NoError(t, err)
	require.Len(t, s, 32)
	require.Len(t, s.String(), 32)
	require.NoError(t, s.Validate(string(s)))
	err = s.Validate(string(s) + "x")
	require.Error(t, err)
	require.True(t, errors.As(err, &InvalidStateError{}))
	require.Contains(t, err.Error(), string(s)+"x")

	var empty bytes.Buffer
	s, err = generate(&empty)
	require.EqualError(t, err, "could not generate random state: EOF")
	require.Empty(t, s)
}
