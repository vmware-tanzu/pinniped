// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !fips_strict

package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
)

// cipherSuitesForDefault are the ciphers that Pinniped allows.
// It will be a strict subset of tls.CipherSuites.
func cipherSuitesForDefault() []*tls.CipherSuite {
	// the order does not matter in go 1.17+ https://go.dev/blog/tls-cipher-suites
	// we match crypto/tls.cipherSuitesPreferenceOrder because it makes unit tests easier to write
	// this list is ignored when TLS 1.3 is used
	//
	// as of 2021-10-19, Mozilla Guideline v5.6, Go 1.17.2, intermediate configuration, supports:
	// - Firefox 27
	// - Android 4.4.2
	// - Chrome 31
	// - Edge
	// - IE 11 on Windows 7
	// - Java 8u31
	// - OpenSSL 1.0.1
	// - Opera 20
	// - Safari 9
	// https://ssl-config.mozilla.org/#server=go&version=1.17.2&config=intermediate&guideline=5.6
	//
	// The Kubernetes API server must use approved cipher suites.
	// https://stigviewer.com/stig/kubernetes/2021-06-17/finding/V-242418

	// These are all AEADs with ECDHE, some use ChaCha20Poly1305 while others use AES-GCM,
	// which provides forward secrecy, confidentiality and authenticity of data.
	cipherSuiteIDsForDefault := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	return translateIDIntoSecureCipherSuites(cipherSuiteIDsForDefault)
}

// cipherSuitesForDefaultLDAP are some additional ciphers that Pinniped allows only for LDAP.
// It will be a strict subset of tls.CipherSuites.
func cipherSuitesForDefaultLDAP() []*tls.CipherSuite {
	// Add less secure ciphers to support the default AWS Active Directory config
	//
	// CBC with ECDHE
	// this provides forward secrecy and confidentiality of data but not authenticity
	// MAC-then-Encrypt CBC ciphers are susceptible to padding oracle attacks
	// See https://crypto.stackexchange.com/a/205 and https://crypto.stackexchange.com/a/224
	cipherSuiteIDsForDefaultLDAP := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	}
	result := cipherSuitesForDefault()
	result = append(result, translateIDIntoSecureCipherSuites(cipherSuiteIDsForDefaultLDAP)...)
	return result
}

// validateAllowedCiphers will take in the user-configured allowed cipher names and validate them against Pinniped's configured list of ciphers.
// If any allowed cipher names are not configured, return a descriptive error.
// An empty list of allowed cipher names is perfectly valid.
// Returns the tls.CipherSuite representation when all allowedCipherNames are accepted.
func validateAllowedCiphers(allowedCipherNames []string) ([]*tls.CipherSuite, error) {
	if len(allowedCipherNames) < 1 {
		return nil, nil
	}

	// Use cipherSuitesForDefaultLDAP since it is a superset of cipherSuitesForDefault
	configuredCiphers := cipherSuitesForDefaultLDAP()
	configuredCipherNames := make([]string, len(configuredCiphers))
	for i, cipher := range configuredCiphers {
		configuredCipherNames[i] = cipher.Name
	}

	// Allow some loosening of the names for legacy reasons.
	for i := range allowedCipherNames {
		switch allowedCipherNames[i] {
		case "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":
			allowedCipherNames[i] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
		case "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":
			allowedCipherNames[i] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
		}
	}

	// Make sure that all allowedCipherNames are actually configured within Pinniped
	var invalidCipherNames []string
	for _, allowedCipherName := range allowedCipherNames {
		if !slices.Contains(configuredCipherNames, allowedCipherName) {
			invalidCipherNames = append(invalidCipherNames, allowedCipherName)
		}
	}

	if len(invalidCipherNames) > 0 {
		return nil, fmt.Errorf("unrecognized ciphers [%s], ciphers must be from list [%s]",
			strings.Join(invalidCipherNames, ", "),
			strings.Join(configuredCipherNames, ", "))
	}

	// Now translate the allowedCipherNames into their *tls.CipherSuite representation
	var validCiphers []*tls.CipherSuite
	for _, cipher := range cipherSuitesForDefaultLDAP() {
		if slices.Contains(allowedCipherNames, cipher.Name) {
			validCiphers = append(validCiphers, cipher)
		}
	}

	return validCiphers, nil
}

// Default returns a tls.Config with a minimum of TLS1.2+ and a few ciphers that can be further constrained by configuration.
func Default(rootCAs *x509.CertPool) *tls.Config {
	return buildTLSConfig(rootCAs, cipherSuitesForDefault(), getAllowedCiphersForTLSOneDotTwo())
}

// DefaultLDAP returns a tls.Config with a minimum of TLS1.2+ and a few ciphers that can be further constrained by configuration.
// It allows a few more ciphers than Default to support specific known LDAP providers.
func DefaultLDAP(rootCAs *x509.CertPool) *tls.Config {
	return buildTLSConfig(rootCAs, cipherSuitesForDefaultLDAP(), getAllowedCiphersForTLSOneDotTwo())
}
