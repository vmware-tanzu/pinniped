// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ptls_test

import (
	"testing"

	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
)

func TestLogAllProfiles(t *testing.T) {
	logger, log := plog.TestLogger(t)

	ptls.LogAllProfiles(logger)

	expectedLines := []string{
		`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"ptls/log_profiles.go:<line>$ptls.logProfile","message":"tls configuration","profile name":"Default","MinVersion":"TLS 1.2","MaxVersion":"NONE","CipherSuites":["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"],"NextProtos":["h2","http/1.1"]}`,
		`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"ptls/log_profiles.go:<line>$ptls.logProfile","message":"tls configuration","profile name":"DefaultLDAP","MinVersion":"TLS 1.2","MaxVersion":"NONE","CipherSuites":["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"],"NextProtos":["h2","http/1.1"]}`,
		`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"ptls/log_profiles.go:<line>$ptls.logProfile","message":"tls configuration","profile name":"Secure","MinVersion":"TLS 1.3","MaxVersion":"NONE","CipherSuites":[],"NextProtos":["h2","http/1.1"]}`,
	}
	testutil.RequireLogLines(t, expectedLines, log)
}
