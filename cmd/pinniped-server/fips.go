// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build boringcrypto
// +build boringcrypto

package main

import (
	_ "crypto/tls/fipsonly" // restricts all TLS configuration to FIPS-approved settings.
	"log"
)

func init() {
	log.Println("using boringcrypto in fipsonly mode")
}
