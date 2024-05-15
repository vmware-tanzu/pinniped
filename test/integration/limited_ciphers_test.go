// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !fips_strict

package integration

import (
	"crypto/tls"
	"testing"
)

// TestLimitedCiphersNotFIPS_Disruptive will confirm that the Pinniped Supervisor exposes only those ciphers listed in
// configuration.
// This does not test the Concierge (which has the same feature) since the Concierge does not have exposed API
// endpoints with the Default profile.
// This does not test the CLI, since it does not have a feature to limit cipher suites.
func TestLimitedCiphersNotFIPS_Disruptive(t *testing.T) {
	performLimitedCiphersTest(t,
		[]string{
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		},
		[]uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		})
}
