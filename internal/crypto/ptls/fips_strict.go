// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// The configurations here override the usual ptls.Default and ptls.DefaultLDAP
// configs when Pinniped is built in fips-only mode.
//go:build fips_strict

package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"

	// Cause fipsonly tls mode with this side effect import.
	_ "go.pinniped.dev/internal/crypto/fips"
	"go.pinniped.dev/internal/plog"
)

// goboring now also supports TLS 1.3 starting in Golang 1.21.6
// (see https://github.com/golang/go/issues/64717),
// so we can use TLS 1.3 as the minimum TLS version for our "secure" configuration
// profile in both FIPS and non-FIPS compiled binaries.
// Hence, we no longer redefine the Secure() function in this file.

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

func Default(rootCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// goboring now also supports TLS 1.3 (see https://github.com/golang/go/issues/64717)
		// so this default configuration can allow either 1.2 or 1.3
		MaxVersion: SecureTLSConfigMinTLSVersion,

		// This is all the fips-approved TLS 1.2 ciphers.
		// The list is hard-coded for convenience of testing.
		// If this list does not match the boring crypto compiler's list then the TestFIPSCipherSuites integration
		// test should fail, which indicates that this list needs to be updated.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},

		// enable HTTP2 for go's 1.7 HTTP Server
		// setting this explicitly is only required in very specific circumstances
		// it is simpler to just set it here than to try and determine if we need to
		NextProtos: []string{"h2", "http/1.1"},

		// optional root CAs, nil means use the host's root CA set
		RootCAs: rootCAs,
	}
}

func DefaultLDAP(rootCAs *x509.CertPool) *tls.Config {
	return Default(rootCAs)
}
