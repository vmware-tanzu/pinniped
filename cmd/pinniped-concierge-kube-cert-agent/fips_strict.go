//go:build fips_strict
// +build fips_strict

package main

import (
	_ "crypto/tls/fipsonly" // restricts all TLS configuration to FIPS-approved settings.
)
