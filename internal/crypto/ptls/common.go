// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ptls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"

	"k8s.io/apimachinery/pkg/util/sets"

	"go.pinniped.dev/internal/plog"
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

// SetUserConfiguredCiphersForTLSOneDotTwo allows configuration/setup components to constrain the allowed TLS ciphers
// for TLS1.2.
func SetUserConfiguredCiphersForTLSOneDotTwo(userConfiguredCiphersForTLSOneDotTwo []string) error {
	plog.Info("setting user-configured allowed ciphers for TLS 1.2", "userConfiguredAllowedCipherSuites", userConfiguredCiphersForTLSOneDotTwo)

	validatedUserConfiguredAllowedCipherSuites, err := validateAllowedCiphers(allHardcodedAllowedCipherSuites(), userConfiguredCiphersForTLSOneDotTwo)
	if err != nil {
		return err
	}
	allowedCiphersForTLSOneDotTwo.Store(validatedUserConfiguredAllowedCipherSuites)
	return nil
}

// getUserConfiguredCiphersAllowList returns the user-configured list of allowed ciphers for TLS1.2.
// It is not exported so that it is only available to this package.
func getUserConfiguredCiphersAllowList() []*tls.CipherSuite {
	userConfiguredCiphersAllowList, ok := (allowedCiphersForTLSOneDotTwo.Load()).([]*tls.CipherSuite)
	if ok {
		return userConfiguredCiphersAllowList
	}
	return nil
}

// constrainCipherSuites returns the intersection of its parameters, as a list of cipher suite IDs.
// If userConfiguredCiphersAllowList is empty, it will return all the hardcodedCipherSuites.
func constrainCipherSuites(
	hardcodedCipherSuites []*tls.CipherSuite,
	userConfiguredAllowedCipherSuites []*tls.CipherSuite,
) []uint16 {
	allowedCipherSuiteIDs := sets.New[uint16]()
	for _, allowedCipherSuite := range userConfiguredAllowedCipherSuites {
		allowedCipherSuiteIDs.Insert(allowedCipherSuite.ID)
	}

	configuredCipherSuiteIDs := sets.New[uint16]()
	for _, configuredCipherSuite := range hardcodedCipherSuites {
		configuredCipherSuiteIDs.Insert(configuredCipherSuite.ID)
	}

	intersection := configuredCipherSuiteIDs.Intersection(allowedCipherSuiteIDs)

	// If the user did not provide any valid allowed cipher suites, use configuredCipherSuiteIDs.
	// Note that the user-configured allowed cipher suites are validated elsewhere, so this should only happen when the
	// user chose not to specify any allowed cipher suites.
	if len(intersection) == 0 {
		intersection = configuredCipherSuiteIDs
	}

	result := intersection.UnsortedList()
	// Preserve the order as shown in configuredCipherSuites
	slices.SortFunc(result, func(a, b uint16) int {
		return slices.IndexFunc(hardcodedCipherSuites, func(cipher *tls.CipherSuite) bool { return cipher.ID == a }) -
			slices.IndexFunc(hardcodedCipherSuites, func(cipher *tls.CipherSuite) bool { return cipher.ID == b })
	})

	return result
}

func translateIDIntoSecureCipherSuites(ids []uint16) []*tls.CipherSuite {
	golangSecureCipherSuites := tls.CipherSuites()
	result := make([]*tls.CipherSuite, 0)

	for _, golangSecureCipherSuite := range golangSecureCipherSuites {
		// As of golang 1.22.2, all cipher suites from tls.CipherSuites are secure, so this is just future-proofing.
		if golangSecureCipherSuite.Insecure { // untested
			continue
		}

		if !slices.Contains(golangSecureCipherSuite.SupportedVersions, tls.VersionTLS12) {
			continue
		}

		if slices.Contains(ids, golangSecureCipherSuite.ID) {
			result = append(result, golangSecureCipherSuite)
		}
	}

	// Preserve the order as shown in ids
	slices.SortFunc(result, func(a, b *tls.CipherSuite) int {
		return slices.Index(ids, a.ID) - slices.Index(ids, b.ID)
	})

	return result
}

// buildTLSConfig will return a tls.Config with CipherSuites from the intersection of configuredCipherSuites and allowedCipherSuites.
func buildTLSConfig(
	rootCAs *x509.CertPool,
	hardcodedCipherSuites []*tls.CipherSuite,
	userConfiguredCiphersAllowList []*tls.CipherSuite,
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

		CipherSuites: constrainCipherSuites(hardcodedCipherSuites, userConfiguredCiphersAllowList),

		// enable HTTP2 for go's 1.7 HTTP Server
		// setting this explicitly is only required in very specific circumstances
		// it is simpler to just set it here than to try and determine if we need to
		NextProtos: []string{"h2", "http/1.1"},

		// optional root CAs, nil means use the host's root CA set
		RootCAs: rootCAs,
	}
}

// validateAllowedCiphers will take in the user-configured allowed cipher names and validate them against Pinniped's configured list of ciphers.
// If any allowed cipher names are not configured, return a descriptive error.
// An empty list of allowed cipher names is perfectly valid.
// Returns the tls.CipherSuite representation when all allowedCipherNames are accepted.
func validateAllowedCiphers(
	hardcodedCipherSuites []*tls.CipherSuite,
	userConfiguredCiphersAllowList []string,
) ([]*tls.CipherSuite, error) {
	if len(userConfiguredCiphersAllowList) < 1 {
		return nil, nil
	}

	hardcodedCipherSuiteNames := make([]string, len(hardcodedCipherSuites))
	for i, cipher := range hardcodedCipherSuites {
		hardcodedCipherSuiteNames[i] = cipher.Name
	}

	// Allow some loosening of the names for legacy reasons.
	for i := range userConfiguredCiphersAllowList {
		switch userConfiguredCiphersAllowList[i] {
		case "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":
			userConfiguredCiphersAllowList[i] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
		case "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":
			userConfiguredCiphersAllowList[i] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
		}
	}

	// Make sure that all allowedCipherNames are actually configured within Pinniped
	var invalidCipherNames []string
	for _, allowedCipherName := range userConfiguredCiphersAllowList {
		if !slices.Contains(hardcodedCipherSuiteNames, allowedCipherName) {
			invalidCipherNames = append(invalidCipherNames, allowedCipherName)
		}
	}

	if len(invalidCipherNames) > 0 {
		return nil, fmt.Errorf("unrecognized ciphers [%s], ciphers must be from list [%s]",
			strings.Join(invalidCipherNames, ", "),
			strings.Join(hardcodedCipherSuiteNames, ", "))
	}

	// Now translate the allowedCipherNames into their *tls.CipherSuite representation
	var validCiphers []*tls.CipherSuite
	for _, cipher := range hardcodedCipherSuites {
		if slices.Contains(userConfiguredCiphersAllowList, cipher.Name) {
			validCiphers = append(validCiphers, cipher)
		}
	}

	return validCiphers, nil
}

// allHardcodedAllowedCipherSuites returns the full list of all hardcoded ciphers that are allowed for any profile.
// Note that it will return different values depending on if the code was compiled in FIPS or non-FIPS mode.
func allHardcodedAllowedCipherSuites() []*tls.CipherSuite {
	// First append all secure and LDAP cipher suites.
	result := translateIDIntoSecureCipherSuites(append(secureCipherSuiteIDs, additionalSecureCipherSuiteIDsOnlyForLDAPClients...))

	// Then append any insecure cipher suites that might be allowed.
	// insecureCipherSuiteIDs is empty except when compiled in FIPS mode.
	for _, golangInsecureCipherSuite := range tls.InsecureCipherSuites() {
		if !slices.Contains(golangInsecureCipherSuite.SupportedVersions, tls.VersionTLS12) {
			continue
		}

		if slices.Contains(insecureCipherSuiteIDs, golangInsecureCipherSuite.ID) {
			result = append(result, golangInsecureCipherSuite)
		}
	}
	return result
}
