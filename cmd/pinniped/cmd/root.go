// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"

	"github.com/spf13/cobra"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/plog"
)

//nolint:gochecknoglobals
var rootCmd = &cobra.Command{
	Use: "pinniped",
	Long: here.Doc(
		`The Pinniped CLI is the client-side binary for use with Pinniped-enabled Kubernetes clusters

		 Find more information at: https://pinniped.dev`,
	),
	SilenceUsage: true, // do not print usage message when commands fail
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	defer plog.Setup()()
	// the context does not matter here because it is unused when CLI formatting is provided
	if err := plog.ValidateAndSetLogLevelAndFormatGlobally(context.Background(), plog.LogSpec{Format: plog.FormatCLI}); err != nil {
		return err
	}
	return rootCmd.Execute()
}
