// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !boringcrypto

package ptls

import (
	"crypto/tls"
	"crypto/x509"
)

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
		CipherSuites: []uint16{
			// these are all AEADs with ECDHE, some use ChaCha20Poly1305 while others use AES-GCM
			// this provides forward secrecy, confidentiality and authenticity of data
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
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
	c := Default(rootCAs)
	// add less secure ciphers to support the default AWS Active Directory config
	c.CipherSuites = append(c.CipherSuites,
		// CBC with ECDHE
		// this provides forward secrecy and confidentiality of data but not authenticity
		// MAC-then-Encrypt CBC ciphers are susceptible to padding oracle attacks
		// See https://crypto.stackexchange.com/a/205 and https://crypto.stackexchange.com/a/224
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	)
	return c
}
