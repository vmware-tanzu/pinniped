// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/component-base/version"
)

//nolint: gochecknoinits
func init() {
	rootCmd.AddCommand(newVersionCommand())
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "%#v\n", version.Get())
			return nil
		},
		Args:  cobra.NoArgs, // do not accept positional arguments for this command
		Use:   "version",
		Short: "Print the version of this Pinniped CLI",
	}
}
