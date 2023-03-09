// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/pkg/browser"

	"go.pinniped.dev/cmd/pinniped/cmd"
	// this side effect import ensures that we use fipsonly crypto in boringcrypto mode.
	_ "go.pinniped.dev/internal/crypto/ptls"

	// This side effect ensures building with at least go1.19.
	_ "go.pinniped.dev/internal/build"
)

//nolint:gochecknoinits
func init() {
	// browsers like chrome like to write to our std out which breaks our JSON ExecCredential output
	// thus we redirect the browser's std out to our std err
	browser.Stdout = os.Stderr
}

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
