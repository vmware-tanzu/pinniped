// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package backoff

import (
	"math"
	"time"
)

type InfiniteBackoff struct {
	// The initial duration.
	Duration time.Duration

	// Factor is used to scale up the Duration until it reaches MaxDuration.
	// Should be at least 1.0.
	Factor float64

	// A limit on step size. Once reached, this value will be used as the interval.
	MaxDuration time.Duration

	hasStepped bool
}

// Step returns the next duration in the backoff sequence.
// It modifies the receiver and is not thread-safe.
func (b *InfiniteBackoff) Step() time.Duration {
	if !b.hasStepped {
		b.hasStepped = true
		return b.Duration
	}

	var next time.Duration
	b.Factor = math.Max(1, b.Factor)
	// Grow by the factor (which could be 1).
	next = time.Duration(float64(b.Duration) * b.Factor)
	// Stop growing the intervals once we exceed the max duration.
	if b.MaxDuration > 0 && next > b.MaxDuration {
		next = b.MaxDuration
	}
	b.Duration = next
	return next
}
