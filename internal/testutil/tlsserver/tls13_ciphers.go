// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !fips_strict

package tlsserver

import "crypto/tls"

// GetExpectedTLS13Ciphers returns the expected TLS 1.3 cipher for a non-FIPS build.
func GetExpectedTLS13Ciphers() []uint16 {
	// TLS 1.3 ciphers are not configurable, so we can hard-code them here.
	return []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}
}

// GetExpectedTLS13CipherNMapKeyExchangeInfoValue returns the expected key exchange info value
// which is shown by nmap in parenthesis next to the cipher name for a non-FIPS build.
func GetExpectedTLS13CipherNMapKeyExchangeInfoValue(cipher uint16) string {
	switch cipher {
	case tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256:
		return "ecdh_x25519"
	default:
		return "unknown key exchange value"
	}
}
