// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sliceutil

// Map transforms a slice from an input type I to an output type O using a transform func.
func Map[I, O any](in []I, transform func(I) O) []O {
	out := make([]O, len(in))
	for i := range in {
		out[i] = transform(in[i])
	}
	return out
}
