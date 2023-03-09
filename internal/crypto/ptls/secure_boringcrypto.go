// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build boringcrypto

package ptls

import (
	"crypto/tls"
	"crypto/x509"

	"k8s.io/apiserver/pkg/server/options"
)

// secureServingOptionsMinTLSVersion is the minimum tls version in the format
// expected by SecureServingOptions.MinTLSVersion from
// k8s.io/apiserver/pkg/server/options.
//
// Always use TLS 1.2 for FIPs.
const secureServingOptionsMinTLSVersion = "VersionTLS12"

// SecureTLSConfigMinTLSVersion is the minimum tls version in the format expected
// by tls.Config.
const SecureTLSConfigMinTLSVersion = tls.VersionTLS12

func Secure(rootCAs *x509.CertPool) *tls.Config {
	return Default(rootCAs)
}

func secureServing(opts *options.SecureServingOptionsWithLoopback) {
	defaultServing(opts)
}
