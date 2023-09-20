// Copyright 2022-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build boringcrypto

package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"

	"go.pinniped.dev/internal/plog"
)

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
		// goboring requires TLS 1.2 and only TLS 1.2
		MinVersion: SecureTLSConfigMinTLSVersion,
		MaxVersion: SecureTLSConfigMinTLSVersion,

		// enable HTTP2 for go's 1.7 HTTP Server
		// setting this explicitly is only required in very specific circumstances
		// it is simpler to just set it here than to try and determine if we need to
		NextProtos: []string{"h2", "http/1.1"},

		// optional root CAs, nil means use the host's root CA set
		RootCAs: rootCAs,

		// This is all the fips-approved ciphers.
		// The list is hard-coded for convenience of testing.
		// This is kept in sync with the boring crypto compiler via TestFIPSCipherSuites.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
}

func DefaultLDAP(rootCAs *x509.CertPool) *tls.Config {
	return Default(rootCAs)
}
