// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !boringcrypto

package ptls

import (
	"crypto/tls"
	"crypto/x509"

	"k8s.io/apiserver/pkg/server/options"
)

// secureServingOptionsMinTLSVersion is the minimum tls version in the format
// expected by SecureServingOptions.MinTLSVersion from
// k8s.io/apiserver/pkg/server/options.
const secureServingOptionsMinTLSVersion = "VersionTLS13"

// SecureTLSConfigMinTLSVersion is the minimum tls version in the format expected
// by tls.Config.
const SecureTLSConfigMinTLSVersion = tls.VersionTLS13

func Secure(rootCAs *x509.CertPool) *tls.Config {
	// as of 2021-10-19, Mozilla Guideline v5.6, Go 1.17.2, modern configuration, supports:
	// - Firefox 63
	// - Android 10.0
	// - Chrome 70
	// - Edge 75
	// - Java 11
	// - OpenSSL 1.1.1
	// - Opera 57
	// - Safari 12.1
	// https://ssl-config.mozilla.org/#server=go&version=1.17.2&config=modern&guideline=5.6
	c := Default(rootCAs)
	c.MinVersion = SecureTLSConfigMinTLSVersion // max out the security
	c.CipherSuites = []uint16{
		// TLS 1.3 ciphers are not configurable, but we need to explicitly set them here to make our client hello behave correctly
		// See https://github.com/golang/go/pull/49293
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}
	return c
}

func secureServing(opts *options.SecureServingOptionsWithLoopback) {
	opts.MinTLSVersion = secureServingOptionsMinTLSVersion
	opts.CipherSuites = nil
}
