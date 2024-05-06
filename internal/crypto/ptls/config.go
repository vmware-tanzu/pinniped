// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"slices"
	"sync/atomic"

	"k8s.io/apimachinery/pkg/util/sets"
)

// allowedCiphersForTLSOneDotTwo will only contain ciphers that meet the following criteria:
// 1. They are secure
// 2. They are returned by tls.CipherSuites
// 3. They are returned by cipherSuitesForDefault or cipherSuitesForDefaultLDAP
// This is atomic so that it can not be set and read at the same time.
//
//nolint:gochecknoglobals // This needs to be global because it will be set at application startup from configuration values
var allowedCiphersForTLSOneDotTwo atomic.Value

type SetAllowedCiphers func([]string) error

// SetAllowedCiphersForTLSOneDotTwo allows configuration/setup components to constrain the allowed TLS ciphers for TLS1.2.
// Not tested in unit tests for pollution reasons.
func SetAllowedCiphersForTLSOneDotTwo(allowedCipherNames []string) error {
	temp, err := validateAllowedCiphers(allowedCipherNames)
	if err != nil {
		allowedCiphersForTLSOneDotTwo.Store(temp)
	}
	return err
}

// getAllowedCiphersForTLSOneDotTwo returns the user-configured list of allowed ciphers for TLS1.2.
// It is not exported so that it is only available to this package.
func getAllowedCiphersForTLSOneDotTwo() []*tls.CipherSuite {
	temp, ok := (allowedCiphersForTLSOneDotTwo.Load()).([]*tls.CipherSuite)
	if ok {
		return temp
	}
	return nil
}

// buildCipherSuites returns the intersection of its parameters, as a list of cipher suite IDs.
// If allowedCipherSuites is empty, it will return all the configuredCipherSuites.
func buildCipherSuites(
	configuredCipherSuites []*tls.CipherSuite,
	allowedCipherSuites []*tls.CipherSuite,
) []uint16 {
	allowedCipherSuiteIDs := sets.New[uint16]()
	for _, allowedCipherSuite := range allowedCipherSuites {
		allowedCipherSuiteIDs.Insert(allowedCipherSuite.ID)
	}

	configuredCipherSuiteIDs := sets.New[uint16]()
	for _, configuredCipherSuite := range configuredCipherSuites {
		configuredCipherSuiteIDs.Insert(configuredCipherSuite.ID)
	}

	intersection := configuredCipherSuiteIDs.Intersection(allowedCipherSuiteIDs)

	// If the user did not provide any valid allowed cipher suites, use the configured allowed cipher suites.
	// Note that the allowed cipher suites are validated elsewhere, so this should only happen when the user chose not to specify any allowed cipher suites.
	if len(intersection) == 0 {
		intersection = configuredCipherSuiteIDs
	}

	result := intersection.UnsortedList()
	// Preserve the order as shown in configuredCipherSuites
	slices.SortFunc(result, func(a, b uint16) int {
		return slices.IndexFunc(configuredCipherSuites, func(cipher *tls.CipherSuite) bool { return cipher.ID == a }) -
			slices.IndexFunc(configuredCipherSuites, func(cipher *tls.CipherSuite) bool { return cipher.ID == b })
	})

	return result
}

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
