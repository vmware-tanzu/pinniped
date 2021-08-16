// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/pkg/browser"

	"go.pinniped.dev/cmd/pinniped/cmd"
)

//nolint: gochecknoinits
func init() {
	// browsers like chrome like to write to our std out which breaks our JSON ExecCredential output
	// thus we redirect the browser's std out to our std err
	browser.Stdout = os.Stderr
}

func main() {
	cmd.Execute()
}
