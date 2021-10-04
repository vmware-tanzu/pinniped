// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !boringcrypto
// +build !boringcrypto

package main

func init() {
	"FATAL: attempt to compile with FIPS disabled" // cause compiler failure
}
