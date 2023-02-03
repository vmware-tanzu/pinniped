// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package fips can be imported to enable fipsonly tls mode when compiling with boringcrypto.
// It will also cause cgo to be explicitly imported when compiling with boringcrypto.
package fips
