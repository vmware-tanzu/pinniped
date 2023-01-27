// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

//nolint:gochecknoglobals
var getCmd = &cobra.Command{
	Use:          "get",
	Short:        "Gets one of [kubeconfig]",
	SilenceUsage: true, // Do not print usage message when commands fail.
}

//nolint:gochecknoinits
func init() {
	rootCmd.AddCommand(getCmd)
}
