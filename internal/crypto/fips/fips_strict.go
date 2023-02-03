// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build boringcrypto
// +build boringcrypto

package fips

import (
	"C"                     // explicitly import cgo so that runtime/cgo gets linked into the kube-cert-agent
	_ "crypto/tls/fipsonly" // restricts all TLS configuration to FIPS-approved settings.
)
