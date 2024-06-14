// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ptls

import (
	"crypto/tls"

	"go.pinniped.dev/internal/plog"
)

func cipherSuiteNamesForCipherSuites(ciphers []uint16) []string {
	names := make([]string, len(ciphers))
	for i, suite := range ciphers {
		names[i] = tls.CipherSuiteName(suite)
	}
	return names
}

func tlsVersionName(tlsVersion uint16) string {
	if tlsVersion == 0 {
		return "NONE"
	}
	return tls.VersionName(tlsVersion)
}

func logProfile(name string, log plog.Logger, profile *tls.Config) {
	log.Info("tls configuration",
		"profile name", name,
		"MinVersion", tlsVersionName(profile.MinVersion),
		"MaxVersion", tlsVersionName(profile.MaxVersion),
		"CipherSuites", cipherSuiteNamesForCipherSuites(profile.CipherSuites),
		"NextProtos", profile.NextProtos,
	)
}

func LogAllProfiles(log plog.Logger) {
	logProfile("Default", log, Default(nil))
	logProfile("DefaultLDAP", log, DefaultLDAP(nil))
	logProfile("Secure", log, Secure(nil))
}
