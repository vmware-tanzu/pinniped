// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"go.pinniped.dev/internal/pversion"
)

//nolint:gochecknoinits
func init() {
	rootCmd.AddCommand(newVersionCommand())
}

//nolint:gochecknoglobals
var (
	output = new(string)
	// getBuildInfo can be overwritten by tests.
	getBuildInfo = pversion.Get
)

func newVersionCommand() *cobra.Command {
	c := &cobra.Command{
		RunE:  runner,
		Args:  cobra.NoArgs, // do not accept positional arguments for this command
		Use:   "version",
		Short: "Print the version of this Pinniped CLI",
	}
	c.Flags().StringVarP(output, "output", "o", "", "one of 'yaml' or 'json'")
	return c
}

func runner(cmd *cobra.Command, _ []string) error {
	buildVersion := getBuildInfo()

	switch {
	case output == nil || *output == "":
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", buildVersion.GitVersion)
	case *output == "json":
		bytes, err := json.MarshalIndent(buildVersion, "", "  ")
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", bytes)
	case *output == "yaml":
		bytes, err := yaml.Marshal(buildVersion)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprint(cmd.OutOrStdout(), string(bytes))
	default:
		return fmt.Errorf("'%s' is not a valid option for output", *output)
	}
	return nil
}
