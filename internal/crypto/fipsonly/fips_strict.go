// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build boringcrypto

package fipsonly

import (
	"C"                     // explicitly import cgo so that runtime/cgo gets linked into the kube-cert-agent
	_ "crypto/tls/fipsonly" // restricts all TLS configuration to FIPS-approved settings.
)
