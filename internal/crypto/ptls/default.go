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
	"sync/atomic"
)

//nolint:gochecknoglobals // These need to be global because they are set when reading config
var (
	// allowedCiphersForTLSOneDotTwo will only contain ciphers that meet the following criteria:
	// 1. They are secure
	// 2. They are returned by tls.CipherSuites
	// 3. They are within list cipherSuiteIDsForDefault or additionalCipherSuiteIDsForDefaultLDAP
	// This is atomic so that it can not be set and read at the same time.
	allowedCiphersForTLSOneDotTwo atomic.Value
	cipherSuiteIDsForDefault      = []uint16{
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
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
	cipherSuiteIDsForDefaultLDAP = func() []uint16 {
		result := cipherSuiteIDsForDefault

		// Add less secure ciphers to support the default AWS Active Directory config
		//
		// CBC with ECDHE
		// this provides forward secrecy and confidentiality of data but not authenticity
		// MAC-then-Encrypt CBC ciphers are susceptible to padding oracle attacks
		// See https://crypto.stackexchange.com/a/205 and https://crypto.stackexchange.com/a/224
		result = append(result,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		)
		return result
	}()
)

func translateIDIntoSecureCipherSuites(ids []uint16) []*tls.CipherSuite {
	golangSecureCipherSuites := tls.CipherSuites()
	result := make([]*tls.CipherSuite, len(ids))

	for _, golangSecureCipherSuite := range golangSecureCipherSuites {
		// As of golang 1.22.2, all cipher suites from tls.CipherSuites are secure, so this is just future-proofing.
		if golangSecureCipherSuite.Insecure { // untested
			continue
		}

		if !slices.Contains(golangSecureCipherSuite.SupportedVersions, tls.VersionTLS12) {
			continue
		}

		i := slices.Index(ids, golangSecureCipherSuite.ID)
		if i >= 0 {
			result[i] = golangSecureCipherSuite
		}
	}
	return result
}

// cipherSuitesForDefault are the ciphers that Pinniped allows.
// It will be a strict subset of tls.CipherSuites.
func cipherSuitesForDefault() []*tls.CipherSuite {
	return translateIDIntoSecureCipherSuites(cipherSuiteIDsForDefault)
}

// additionalCipherSuitesForDefaultLDAP are some additional ciphers that Pinniped allows only for LDAP.
// It will be a strict subset of tls.CipherSuites.
func cipherSuitesForDefaultLDAP() []*tls.CipherSuite {
	return translateIDIntoSecureCipherSuites(cipherSuiteIDsForDefaultLDAP)
}

// SetAllowedCiphersForTLSOneDotTwo allows configuration/setup components to constrain the allowed TLS ciphers for TLS1.2.
// Not tested in unit tests for pollution reasons.
func SetAllowedCiphersForTLSOneDotTwo(allowedCipherNames []string) error {
	temp, err := validateAllowedCiphers(allowedCipherNames)
	if err != nil {
		allowedCiphersForTLSOneDotTwo.Store(temp)
	}
	return err
}

// validateAllowedCiphers will take in the user-configured allowed cipher names and validate them against Pinniped's configured list of ciphers.
// If any allowed cipher names are not configured, return a descriptive error.
// An empty list of allowed cipher names is perfectly valid.
// Returns the tls.CipherSuite representation when all allowedCipherNames are accepted.
func validateAllowedCiphers(allowedCipherNames []string) ([]*tls.CipherSuite, error) {
	if len(allowedCipherNames) < 1 {
		return nil, nil
	}

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

// buildTLSConfig will return a tls.Config with CipherSuites from the intersection of configuredCipherSuites and allowedCipherSuites.
func buildTLSConfig(
	rootCAs *x509.CertPool,
	configuredCipherSuites []*tls.CipherSuite,
	allowedCipherSuites []*tls.CipherSuite,
) *tls.Config {
	return &tls.Config{
		// Can't use SSLv3 because of POODLE and BEAST
		// Can't use TLSv1.0 because of POODLE and BEAST using CBC cipher
		// Can't use TLSv1.1 because of RC4 cipher usage
		//
		// The Kubernetes API Server must use TLS 1.2, at a minimum,
		// to protect the confidentiality of sensitive data during electronic dissemination.
		// https://stigviewer.com/stig/kubernetes/2021-06-17/finding/V-242378
		MinVersion: tls.VersionTLS12,

		CipherSuites: buildCipherSuites(configuredCipherSuites, allowedCipherSuites),

		// enable HTTP2 for go's 1.7 HTTP Server
		// setting this explicitly is only required in very specific circumstances
		// it is simpler to just set it here than to try and determine if we need to
		NextProtos: []string{"h2", "http/1.1"},

		// optional root CAs, nil means use the host's root CA set
		RootCAs: rootCAs,
	}
}

// buildCipherSuites returns the intersection of its parameters, as a list of cipher suite IDs.
// If allowedCipherSuites is empty, it will return all the configuredCipherSuites.
func buildCipherSuites(
	configuredCipherSuites []*tls.CipherSuite,
	allowedCipherSuites []*tls.CipherSuite,
) []uint16 {
	allowedCipherSuiteIDs := make([]uint16, 0)

	for _, allowedCipherSuite := range allowedCipherSuites {
		for _, secureCipher := range configuredCipherSuites {
			if secureCipher.ID == allowedCipherSuite.ID {
				allowedCipherSuiteIDs = append(allowedCipherSuiteIDs, secureCipher.ID)
			}
		}
	}

	configuredCipherSuiteIDs := make([]uint16, len(configuredCipherSuites))
	for i := range configuredCipherSuites {
		configuredCipherSuiteIDs[i] = configuredCipherSuites[i].ID
	}

	// If the user did not provide any valid allowed cipher suites, use the configured allowed cipher suites.
	// Note that the allowed cipher suites are validated elsewhere, so this should only happen when the user chose not to specify any allowed cipher suites.
	if len(allowedCipherSuiteIDs) == 0 {
		allowedCipherSuiteIDs = configuredCipherSuiteIDs
	}
	// Preserve the order as shown in configuredCipherSuites
	slices.SortFunc(allowedCipherSuiteIDs, func(a, b uint16) int {
		return slices.Index(configuredCipherSuiteIDs, a) - slices.Index(configuredCipherSuiteIDs, b)
	})

	return allowedCipherSuiteIDs
}

// Default or Secure should be the only way to create a tls.Config within any component of Pinniped.
func Default(rootCAs *x509.CertPool) *tls.Config {
	return buildTLSConfig(rootCAs, cipherSuitesForDefault(), getAllowedCiphersForTLSOneDotTwo())
}

// DefaultLDAP or Secure should be the only ways to create a tls.Config for LDAP within any component of Pinniped.
func DefaultLDAP(rootCAs *x509.CertPool) *tls.Config {
	return buildTLSConfig(rootCAs, cipherSuitesForDefaultLDAP(), getAllowedCiphersForTLSOneDotTwo())
}

func getAllowedCiphersForTLSOneDotTwo() []*tls.CipherSuite {
	temp, ok := (allowedCiphersForTLSOneDotTwo.Load()).([]*tls.CipherSuite)
	if ok { // untested within unit tests
		return temp
	}
	return nil
}
