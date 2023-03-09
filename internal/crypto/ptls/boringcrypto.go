// Copyright 2022-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build boringcrypto

package ptls

import (
	"C"                     // explicitly import cgo
	_ "crypto/tls/fipsonly" // restricts all TLS configuration to FIPS-approved settings.
	"os"
	"path/filepath"
	"runtime"

	"go.pinniped.dev/internal/plog"
)

func init() {
	switch filepath.Base(os.Args[0]) {
	case "pinniped-server", "pinniped-supervisor", "pinniped-concierge", "pinniped-concierge-kube-cert-agent":
	default:
		return // do not print FIPS logs if we cannot confirm that we are running a server binary
	}

	// this init runs before we have parsed our config to determine our log level
	// thus we must use a log statement that will always print instead of conditionally print
	plog.Always("using boring crypto in fips only mode", "go version", runtime.Version())
}
