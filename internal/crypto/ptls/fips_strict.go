// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// The configurations here override the usual configs when Pinniped is built in fips-only mode.
//go:build fips_strict

package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"k8s.io/apiserver/pkg/server/options"

	// Cause fipsonly tls mode with this side effect import.
	_ "go.pinniped.dev/internal/crypto/fips"
	"go.pinniped.dev/internal/plog"
)

// SecureTLSConfigMinTLSVersion is TLS 1.2 Until goboring supports TLS 1.3.
const SecureTLSConfigMinTLSVersion = tls.VersionTLS12

func init() {
	switch filepath.Base(os.Args[0]) {
	case "pinniped-server", "pinniped-supervisor", "pinniped-concierge", "pinniped-concierge-kube-cert-agent":
	default:
		return // do not print FIPS logs if we cannot confirm that we are running a server binary
	}

	// this init runs before we have parsed our config to determine our log level
	// thus we must use a log statement that will always print instead of conditionally print
	plog.Always("using boring crypto in fips only mode", "go version", runtime.Version())
}

func cipherSuitesForFIPS() []*tls.CipherSuite {
	// This is all the fips-approved TLS 1.2 ciphers.
	// The list is hard-coded for convenience of testing.
	// If this list does not match the boring crypto compiler's list then the TestFIPSCipherSuites integration
	// test should fail, which indicates that this list needs to be updated.
	secureCipherSuiteIDsForFIPS := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}

	insecureCipherSuiteIDsForFIPS := []uint16{
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	}

	result := translateIDIntoSecureCipherSuites(secureCipherSuiteIDsForFIPS)

	for _, golangInsecureCipherSuite := range tls.InsecureCipherSuites() {
		if !slices.Contains(golangInsecureCipherSuite.SupportedVersions, tls.VersionTLS12) {
			continue
		}

		i := slices.Index(insecureCipherSuiteIDsForFIPS, golangInsecureCipherSuite.ID)
		if i >= 0 {
			result = append(result, golangInsecureCipherSuite)
		}
	}
	return result
}

func Default(rootCAs *x509.CertPool) *tls.Config {
	config := buildTLSConfig(rootCAs, cipherSuitesForFIPS(), getAllowedCiphersForTLSOneDotTwo())

	// Until goboring supports TLS 1.3, make the max version 1.2.
	config.MaxVersion = tls.VersionTLS12
	return config
}

// Secure will be exactly the same as Default until goboring supports TLS 1.3.
func Secure(rootCAs *x509.CertPool) *tls.Config {
	return Default(rootCAs)
}

// DefaultLDAP is exactly the same as Default.
func DefaultLDAP(rootCAs *x509.CertPool) *tls.Config {
	return Default(rootCAs)
}

// Until goboring supports TLS 1.3, make secureServing use the same as the defaultServing profile in FIPS mode.
func secureServing(opts *options.SecureServingOptionsWithLoopback) {
	defaultServing(opts)
}

// validateAllowedCiphers will take in the user-configured allowed cipher names and validate them against Pinniped's configured list of ciphers.
// If any allowed cipher names are not configured, return a descriptive error.
// An empty list of allowed cipher names is perfectly valid.
// Returns the tls.CipherSuite representation when all allowedCipherNames are accepted.
func validateAllowedCiphers(allowedCipherNames []string) ([]*tls.CipherSuite, error) {
	if len(allowedCipherNames) < 1 {
		return nil, nil
	}

	configuredCiphers := cipherSuitesForFIPS()
	configuredCipherNames := make([]string, len(configuredCiphers))
	for i, cipher := range configuredCiphers {
		configuredCipherNames[i] = cipher.Name
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
	for _, cipher := range cipherSuitesForFIPS() {
		if slices.Contains(allowedCipherNames, cipher.Name) {
			validCiphers = append(validCiphers, cipher)
		}
	}

	return validCiphers, nil
}
