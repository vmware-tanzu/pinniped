// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !fips_strict

package integration

import (
	"crypto/tls"
	"testing"
)

// TestLimitedCiphersNotFIPS_Disruptive will confirm that the Pinniped Supervisor and Concierge expose only those
// ciphers listed in configuration, when compiled in non-FIPS mode.
// This does not test the CLI, since it does not have a feature to limit cipher suites.
func TestLimitedCiphersNotFIPS_Disruptive(t *testing.T) {
	performLimitedCiphersTest(t,
		// The user-configured ciphers for both the Supervisor and Concierge.
		// This is a subset of the hardcoded ciphers from profiles.go.
		[]string{
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		},
		// Expected server configuration for the Supervisor's OIDC endpoints.
		&tls.Config{
			MinVersion: tls.VersionTLS12, // Supervisor OIDC always allows TLS 1.2 clients to connect
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				// Supervisor OIDC endpoints configured with EC certs use only EC ciphers.
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
		},
		// Expected server configuration for the Supervisor and Concierge aggregated API endpoints.
		&tls.Config{
			MinVersion:   tls.VersionTLS13, // do not allow TLS 1.2 clients to connect
			MaxVersion:   tls.VersionTLS13,
			CipherSuites: nil, // TLS 1.3 ciphers are not configurable
		},
	)
}
