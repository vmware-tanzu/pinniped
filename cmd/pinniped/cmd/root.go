/*
Copyright 2020 the Pinniped contributors. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

//nolint: gochecknoglobals
var rootCmd = &cobra.Command{
	Use:          "pinniped",
	Short:        "pinniped",
	Long:         "pinniped is the client-side binary for use with Pinniped-enabled Kubernetes clusters.",
	SilenceUsage: true, // do not print usage message when commands fail
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
