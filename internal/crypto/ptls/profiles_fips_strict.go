// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// The configurations here override the usual configs when Pinniped is built in fips-only mode.
//go:build fips_strict

package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"k8s.io/apiserver/pkg/server/options"

	// Cause fipsonly tls mode with this side effect import.
	_ "go.pinniped.dev/internal/crypto/fips"
	"go.pinniped.dev/internal/plog"
)

// init: see comment in profiles.go.
func init() {
	switch filepath.Base(os.Args[0]) {
	case "pinniped-server", "pinniped-supervisor", "pinniped-concierge", "pinniped-concierge-kube-cert-agent":
	default:
		return // do not print FIPS logs if we cannot confirm that we are running a server binary
	}

	// this init runs before we have parsed our config to determine our log level
	// thus we must use a log statement that will always print instead of conditionally print
	plog.Always("this server was compiled to use boring crypto in FIPS-only mode",
		"go version", runtime.Version())
}

// SecureTLSConfigMinTLSVersion: see comment in profiles.go.
// Until goboring supports TLS 1.3, use TLS 1.2.
const SecureTLSConfigMinTLSVersion = tls.VersionTLS12

// Default: see comment in profiles.go.
// This chooses different cipher suites and/or TLS versions compared to non-FIPS mode.
func Default(rootCAs *x509.CertPool) *tls.Config {
	config := buildTLSConfig(rootCAs, hardcodedCipherSuites(), getUserConfiguredCiphersAllowList())
	// Until goboring supports TLS 1.3, make the max version 1.2.
	config.MaxVersion = tls.VersionTLS12
	return config
}

// DefaultLDAP: see comment in profiles.go.
// This chooses different cipher suites and/or TLS versions compared to non-FIPS mode.
func DefaultLDAP(rootCAs *x509.CertPool) *tls.Config {
	return Default(rootCAs)
}

// Secure: see comment in profiles.go.
// This chooses different cipher suites and/or TLS versions compared to non-FIPS mode.
// Until goboring supports TLS 1.3, make the Secure profile the same as the Default profile in FIPS mode.
func Secure(rootCAs *x509.CertPool) *tls.Config {
	return Default(rootCAs)
}

// SecureServing: see comment in profiles.go.
// This chooses different cipher suites and/or TLS versions compared to non-FIPS mode.
// Until goboring supports TLS 1.3, make SecureServing use the same as the defaultServing profile in FIPS mode.
func SecureServing(opts *options.SecureServingOptionsWithLoopback) {
	defaultServing(opts)
}

func hardcodedCipherSuites() []*tls.CipherSuite {
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

		if slices.Contains(insecureCipherSuiteIDsForFIPS, golangInsecureCipherSuite.ID) {
			result = append(result, golangInsecureCipherSuite)
		}
	}
	return result
}
