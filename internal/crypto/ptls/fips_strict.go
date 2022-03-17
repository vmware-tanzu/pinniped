// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

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
const secureMinTLSVersion = "VersionTLS12"

func init() {
	go func() {
		time.Sleep(5 * time.Second)
		log.Println("using boringcrypto in fips only mode.")
	}()
}

// FIPS does not support TLS 1.3.
// Therefore, we cannot use Pinniped's usual secure configuration,
// which requires TLS 1.3.
// Secure is just a wrapper for Default in this case.
func Secure(rootCAs *x509.CertPool) *tls.Config {
	return Default(rootCAs)
}

func Default(rootCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		// Can't use SSLv3 because of POODLE and BEAST
		// Can't use TLSv1.0 because of POODLE and BEAST using CBC cipher
		// Can't use TLSv1.1 because of RC4 cipher usage
		//
		// The Kubernetes API Server must use TLS 1.2, at a minimum,
		// to protect the confidentiality of sensitive data during electronic dissemination.
		// https://stigviewer.com/stig/kubernetes/2021-06-17/finding/V-242378
		MinVersion: tls.VersionTLS12,

		// enable HTTP2 for go's 1.7 HTTP Server
		// setting this explicitly is only required in very specific circumstances
		// it is simpler to just set it here than to try and determine if we need to
		NextProtos: []string{"h2", "http/1.1"},

		// optional root CAs, nil means use the host's root CA set
		RootCAs: rootCAs,
	}
}
