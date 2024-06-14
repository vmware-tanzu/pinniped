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

// validatedUserConfiguredAllowedCipherSuitesForTLSOneDotTwo is the validated configuration of allowed cipher suites
// provided by the user, as set by SetUserConfiguredAllowedCipherSuitesForTLSOneDotTwo().
// This global variable is atomic so that it can not be set and read at the same time.
//
//nolint:gochecknoglobals // this needs to be global because it will be set at application startup from configuration values
var validatedUserConfiguredAllowedCipherSuitesForTLSOneDotTwo atomic.Value

type SetAllowedCiphersFunc func([]string) error

// SetUserConfiguredAllowedCipherSuitesForTLSOneDotTwo allows configuration/setup components to constrain the
// allowed TLS ciphers for TLS1.2. It implements SetAllowedCiphersFunc.
func SetUserConfiguredAllowedCipherSuitesForTLSOneDotTwo(userConfiguredAllowedCipherSuitesForTLSOneDotTwo []string) error {
	plog.Info("setting user-configured allowed ciphers for TLS 1.2", "userConfiguredAllowedCipherSuites", userConfiguredAllowedCipherSuitesForTLSOneDotTwo)

	validatedSuites, err := validateAllowedCiphers(
		allHardcodedAllowedCipherSuites(),
		userConfiguredAllowedCipherSuitesForTLSOneDotTwo,
	)
	if err != nil {
		return err
	}

	validatedUserConfiguredAllowedCipherSuitesForTLSOneDotTwo.Store(validatedSuites)
	return nil
}

// getUserConfiguredAllowedCipherSuitesForTLSOneDotTwo returns the user-configured list of allowed ciphers for TLS1.2.
// It is not exported so that it is only available to this package.
func getUserConfiguredAllowedCipherSuitesForTLSOneDotTwo() []*tls.CipherSuite {
	userConfiguredAllowedCipherSuites, ok := (validatedUserConfiguredAllowedCipherSuitesForTLSOneDotTwo.Load()).([]*tls.CipherSuite)
	if ok {
		return userConfiguredAllowedCipherSuites
	}
	return nil
}

// constrainCipherSuites returns the intersection of its parameters, as a list of cipher suite IDs.
// If userConfiguredAllowedCipherSuites is empty, it will return the list from cipherSuites as IDs.
func constrainCipherSuites(
	cipherSuites []*tls.CipherSuite,
	userConfiguredAllowedCipherSuites []*tls.CipherSuite,
) []uint16 {
	// If the user did not configure any allowed ciphers suites, then return the IDs
	// for the ciphers in cipherSuites in the same sort order as quickly as possible.
	if len(userConfiguredAllowedCipherSuites) == 0 {
		cipherSuiteIDs := make([]uint16, len(cipherSuites))
		for i := range cipherSuites {
			cipherSuiteIDs[i] = cipherSuites[i].ID
		}
		return cipherSuiteIDs
	}

	// Make two sets so we can intersect them below.
	cipherSuiteIDsSet := sets.New[uint16]()
	for _, s := range cipherSuites {
		cipherSuiteIDsSet.Insert(s.ID)
	}
	userConfiguredAllowedCipherSuiteIDsSet := sets.New[uint16]()
	for _, s := range userConfiguredAllowedCipherSuites {
		userConfiguredAllowedCipherSuiteIDsSet.Insert(s.ID)
	}

	// Calculate the intersection of sets.
	intersection := cipherSuiteIDsSet.Intersection(userConfiguredAllowedCipherSuiteIDsSet)

	// If the user did not provide any valid allowed cipher suites, use cipherSuiteIDsSet.
	// Note that the user-configured allowed cipher suites are validated elsewhere, so
	// this should only happen when the user chose not to specify any allowed cipher suites.
	if len(intersection) == 0 {
		intersection = cipherSuiteIDsSet
	}

	result := intersection.UnsortedList()
	// Preserve the original order as shown in the cipherSuites parameter.
	slices.SortFunc(result, func(a, b uint16) int {
		return slices.IndexFunc(cipherSuites, func(cipher *tls.CipherSuite) bool { return cipher.ID == a }) -
			slices.IndexFunc(cipherSuites, func(cipher *tls.CipherSuite) bool { return cipher.ID == b })
	})

	return result
}

func translateIDIntoSecureCipherSuites(ids []uint16) []*tls.CipherSuite {
	golangSecureCipherSuites := tls.CipherSuites()
	result := make([]*tls.CipherSuite, 0)

	for _, golangSecureCipherSuite := range golangSecureCipherSuites {
		// As of golang 1.22, all cipher suites from tls.CipherSuites are secure, so this is just future-proofing.
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

// buildTLSConfig will return a tls.Config with CipherSuites from the intersection of cipherSuites and userConfiguredAllowedCipherSuites.
func buildTLSConfig(
	rootCAs *x509.CertPool,
	cipherSuites []*tls.CipherSuite,
	userConfiguredAllowedCipherSuites []*tls.CipherSuite,
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

		CipherSuites: constrainCipherSuites(cipherSuites, userConfiguredAllowedCipherSuites),

		// enable HTTP2 for go's 1.7 HTTP Server
		// setting this explicitly is only required in very specific circumstances
		// it is simpler to just set it here than to try and determine if we need to
		NextProtos: []string{"h2", "http/1.1"},

		// optional root CAs, nil means use the host's root CA set
		RootCAs: rootCAs,
	}
}

// validateAllowedCiphers will take in the user-configured allowed cipher names and validate them against a list of
// ciphers. If any userConfiguredAllowedCipherSuites names are not in the cipherSuites, return a descriptive error.
// An empty list of userConfiguredAllowedCipherSuites means that the user wants the all default ciphers from cipherSuites.
// Returns the tls.CipherSuite representation when all userConfiguredAllowedCipherSuites are valid.
func validateAllowedCiphers(
	cipherSuites []*tls.CipherSuite,
	userConfiguredAllowedCipherSuites []string,
) ([]*tls.CipherSuite, error) {
	if len(userConfiguredAllowedCipherSuites) < 1 {
		return nil, nil
	}

	cipherSuiteNames := make([]string, len(cipherSuites))
	for i, cipher := range cipherSuites {
		cipherSuiteNames[i] = cipher.Name
	}

	// Allow some loosening of the names for legacy reasons.
	for i := range userConfiguredAllowedCipherSuites {
		switch userConfiguredAllowedCipherSuites[i] {
		case "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":
			userConfiguredAllowedCipherSuites[i] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
		case "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":
			userConfiguredAllowedCipherSuites[i] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
		}
	}

	// Make sure that all allowedCipherNames are actually configured within Pinniped.
	var invalidCipherNames []string
	for _, allowedCipherName := range userConfiguredAllowedCipherSuites {
		if !slices.Contains(cipherSuiteNames, allowedCipherName) {
			invalidCipherNames = append(invalidCipherNames, allowedCipherName)
		}
	}

	if len(invalidCipherNames) > 0 {
		return nil, fmt.Errorf("unrecognized ciphers [%s], ciphers must be from list [%s]",
			strings.Join(invalidCipherNames, ", "),
			strings.Join(cipherSuiteNames, ", "))
	}

	// Now translate the allowedCipherNames into their *tls.CipherSuite representation.
	var validCiphers []*tls.CipherSuite
	for _, cipher := range cipherSuites {
		if slices.Contains(userConfiguredAllowedCipherSuites, cipher.Name) {
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
