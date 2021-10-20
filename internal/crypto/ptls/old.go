// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !go1.17
// +build !go1.17

package ptls

func init() {
	// cause compile time failure if an older version of Go is used
	`Pinniped's TLS configuration makes assumptions about how the Go standard library implementation of TLS works.
It particular, we rely on the server controlling cipher suite selection.  For these assumptions to hold, Pinniped
must be compiled with Go 1.17+.  If you are seeing this error message, your attempt to compile Pinniped with an
older Go compiler was explicitly failed to prevent an unsafe configuration.`
}
