// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import "github.com/spf13/cobra"

// mustMarkRequired marks the given flags as required on the provided cobra.Command. If any of the names are wrong, it panics.
func mustMarkRequired(cmd *cobra.Command, flags ...string) {
	for _, flag := range flags {
		if err := cmd.MarkFlagRequired(flag); err != nil {
			panic(err)
		}
	}
}

// mustMarkHidden marks the given flags as hidden on the provided cobra.Command. If any of the names are wrong, it panics.
func mustMarkHidden(cmd *cobra.Command, flags ...string) {
	for _, flag := range flags {
		if err := cmd.Flags().MarkHidden(flag); err != nil {
			panic(err)
		}
	}
}

func mustMarkDeprecated(cmd *cobra.Command, flag, usageMessage string) {
	if err := cmd.Flags().MarkDeprecated(flag, usageMessage); err != nil {
		panic(err)
	}
}
