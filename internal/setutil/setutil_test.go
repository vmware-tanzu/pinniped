// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package setutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCaseInsensitiveSet(t *testing.T) {
	var nilSet *CaseInsensitiveSet
	require.True(t, nilSet.Empty())
	require.False(t, nilSet.HasAnyIgnoringCase([]string{"a", "b"}))
	require.False(t, nilSet.HasAnyIgnoringCase(nil))
	require.False(t, nilSet.ContainsIgnoringCase("a"))
	require.False(t, nilSet.ContainsIgnoringCase("a"))

	emptySet := NewCaseInsensitiveSet()
	require.True(t, emptySet.Empty())
	require.False(t, emptySet.HasAnyIgnoringCase([]string{"a", "b"}))
	require.False(t, emptySet.HasAnyIgnoringCase(nil))
	require.False(t, emptySet.ContainsIgnoringCase("a"))
	require.False(t, emptySet.ContainsIgnoringCase("a"))

	set := NewCaseInsensitiveSet("A", "B", "c")
	require.False(t, set.Empty())
	require.False(t, set.HasAnyIgnoringCase([]string{"x", "y"}))
	require.True(t, set.HasAnyIgnoringCase([]string{"a", "x"}))
	require.False(t, set.HasAnyIgnoringCase(nil))
	require.False(t, set.ContainsIgnoringCase("x"))
	require.True(t, set.ContainsIgnoringCase("a"))
}
