// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package backoff

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInfiniteBackoff(t *testing.T) {
	tests := []struct {
		name             string
		stepper          Stepper
		expectedSequence []time.Duration
	}{
		{
			name:    "zero initialization results in 0ns steps",
			stepper: &InfiniteBackoff{},
			expectedSequence: func() []time.Duration {
				results := make([]time.Duration, 1000)
				for i := 0; i < 1000; i++ {
					results[i] = time.Duration(0)
				}
				return results
			}(),
		},
		{
			name: "double 5 ns forever",
			stepper: &InfiniteBackoff{
				Duration: 5 * time.Nanosecond,
				Factor:   2,
			},
			expectedSequence: func() []time.Duration {
				// limit to 60 to prevent int64 overflow
				results := make([]time.Duration, 60)
				results[0] = 5 * time.Nanosecond
				for i := 1; i < 60; i++ {
					results[i] = 2 * results[i-1]
				}
				return results
			}(),
		},
		{
			name: "grows slowly until limit",
			stepper: &InfiniteBackoff{
				Duration:    20 * time.Nanosecond,
				Factor:      1.1,
				MaxDuration: 40 * time.Nanosecond,
			},
			expectedSequence: func() []time.Duration {
				results := make([]time.Duration, 1000)
				results[0] = 20 * time.Nanosecond
				for i := 1; i < 1000; i++ {
					nanoseconds := 1.1 * float64(results[i-1])
					results[i] = time.Duration(math.Min(nanoseconds, 40))
				}
				return results
			}(),
		},
		{
			name: "factor less than 1.0 is replaced with 1.0",
			stepper: &InfiniteBackoff{
				Duration: 20 * time.Nanosecond,
				Factor:   0.9,
			},
			expectedSequence: func() []time.Duration {
				results := make([]time.Duration, 1000)
				for i := 0; i < 1000; i++ {
					results[i] = 20 * time.Nanosecond
				}
				return results
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotEmpty(t, tt.expectedSequence)
			for i, expected := range tt.expectedSequence {
				actual := tt.stepper.Step()
				require.Equalf(t, expected, actual, "incorrect result on step #%d, previous steps are %v", i, tt.expectedSequence[:i])
			}

			backoff, ok := tt.stepper.(*InfiniteBackoff)
			require.True(t, ok)
			require.NotNil(t, backoff)
			require.GreaterOrEqual(t, backoff.Factor, 1.0)
		})
	}
}
