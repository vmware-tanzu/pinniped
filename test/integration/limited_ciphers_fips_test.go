// Copyright 2024-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build fips_strict

package integration

import (
	"crypto/tls"
	"testing"
)

// TestLimitedCiphersFIPS_Disruptive will confirm that the Pinniped Supervisor and Concierge expose only those
// ciphers listed in configuration, when compiled in FIPS mode.
// This does not test the CLI, since it does not have a feature to limit cipher suites.
func TestLimitedCiphersFIPS_Disruptive(t *testing.T) {
	performLimitedCiphersTest(t,
		// The user-configured ciphers for both the Supervisor and Concierge.
		// This is a subset of the hardcoded ciphers from profiles_fips_strict.go.
		[]string{
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
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
			MinVersion: tls.VersionTLS12, // always allow TLS 1.2 in fips mode
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
		},
	)
}
