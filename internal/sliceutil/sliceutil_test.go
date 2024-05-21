// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sliceutil

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMap(t *testing.T) {
	type testCase[I any, O any] struct {
		name          string
		in            []I
		transformFunc func(I) O
		want          []O
	}

	stringStringTests := []testCase[string, string]{
		{
			name:          "downcase func",
			in:            []string{"Aa", "bB", "CC"},
			transformFunc: strings.ToLower,
			want:          []string{"aa", "bb", "cc"},
		},
		{
			name:          "upcase func",
			in:            []string{"Aa", "bB", "CC"},
			transformFunc: strings.ToUpper,
			want:          []string{"AA", "BB", "CC"},
		},
		{
			name:          "when in is nil, then out is an empty slice",
			in:            nil,
			transformFunc: strings.ToUpper,
			want:          []string{},
		},
	}
	for _, tt := range stringStringTests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			actual := Map(tt.in, tt.transformFunc)
			require.Equal(t, tt.want, actual)
		})
	}

	stringIntTests := []testCase[string, int]{
		{
			name: "len func",
			in:   []string{"Aa", "bBb", "CCcC"},
			transformFunc: func(s string) int {
				return len(s)
			},
			want: []int{2, 3, 4},
		},
		{
			name: "index func",
			in:   []string{"Aab", "bB", "CC"},
			transformFunc: func(s string) int {
				return strings.Index(s, "b")
			},
			want: []int{2, 0, -1},
		},
	}
	for _, tt := range stringIntTests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			actual := Map(tt.in, tt.transformFunc)
			require.Equal(t, tt.want, actual)
		})
	}
}
