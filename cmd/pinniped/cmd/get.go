// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

//nolint: gochecknoglobals
var getCmd = &cobra.Command{Use: "get", Short: "get"}

//nolint: gochecknoinits
func init() {
	rootCmd.AddCommand(getCmd)
}
