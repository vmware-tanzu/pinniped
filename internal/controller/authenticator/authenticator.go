// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package authenticator contains helper code for dealing with *Authenticator CRDs.
package authenticator

// Closer is a type that can be closed idempotently.
//
// This type is slightly different from io.Closer, because io.Closer can return an error and is not
// necessarily idempotent.
type Closer interface {
	Close()
}
