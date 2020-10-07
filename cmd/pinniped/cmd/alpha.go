// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

//nolint: gochecknoglobals
var alphaCmd = &cobra.Command{
	Use:          "alpha",
	Short:        "alpha",
	Long:         "alpha subcommands (syntax or flags are still subject to change)",
	SilenceUsage: true, // do not print usage message when commands fail
	Hidden:       true,
}

//nolint: gochecknoinits
func init() {
	rootCmd.AddCommand(alphaCmd)
}
