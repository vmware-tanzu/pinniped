// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !go1.19

package build

func init() {
	// fail unless compiling with 1.19+
	"requires go1.19 or greater"
}
