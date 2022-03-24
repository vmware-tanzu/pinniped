// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// The configurations here override the usual ptls.Secure, ptls.Default, and ptls.DefaultLDAP
// configs when Pinniped is built in fips-only mode.
// All of these are the same because FIPs is already so limited.
//go:build fips_strict
// +build fips_strict

package ptls

import (
	"crypto/tls"
	_ "crypto/tls/fipsonly" // restricts all TLS configuration to FIPS-approved settings.
	"crypto/x509"
	"log"
	"time"
)

// Always use TLS 1.2 for FIPs
const secureServingOptionsMinTLSVersion = "VersionTLS12"
const SecureTLSConfigMinTLSVersion = tls.VersionTLS12

func init() {
	go func() {
		time.Sleep(5 * time.Second)
		log.Println("using boringcrypto in fips only mode.")
	}()
}

func Default(rootCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		// goboring requires TLS 1.2 and only TLS 1.2
		MinVersion: SecureTLSConfigMinTLSVersion,

		// enable HTTP2 for go's 1.7 HTTP Server
		// setting this explicitly is only required in very specific circumstances
		// it is simpler to just set it here than to try and determine if we need to
		NextProtos: []string{"h2", "http/1.1"},

		// optional root CAs, nil means use the host's root CA set
		RootCAs: rootCAs,

		// Don't set CipherSuites, which means it will default to the FIPS-compatible ones.
	}
}

func Secure(rootCAs *x509.CertPool) *tls.Config {
	return Default(rootCAs)
}

func DefaultLDAP(rootCAs *x509.CertPool) *tls.Config {
	return Default(rootCAs)
}
