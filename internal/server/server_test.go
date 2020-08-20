/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package server

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

const knownGoodUsage = `
pinniped-server provides a generic API for mapping an external
credential from somewhere to an internal credential to be used for
authenticating to the Kubernetes API.

Usage:
  pinniped-server [flags]

Flags:
  -c, --config string                                path to configuration file (default "pinniped.yaml")
      --downward-api-path string                     path to Downward API volume mount (default "/etc/podinfo")
  -h, --help                                         help for pinniped-server
      --log-flush-frequency duration                 Maximum number of seconds between log flushes (default 5s)
      --serving-cert-rotation-threshold percentage   real number between 0 and 1 indicating percentage of lifetime before rotation of serving cert (default 70.00%)
`

func TestCommand(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantErr    string
		wantStdout string
	}{
		{
			name: "NoArgsSucceeds",
			args: []string{},
		},
		{
			name:       "Usage",
			args:       []string{"-h"},
			wantStdout: knownGoodUsage,
		},
		{
			name:    "OneArgFails",
			args:    []string{"tuna"},
			wantErr: `unknown command "tuna" for "pinniped-server"`,
		},
		{
			name: "ShortConfigFlagSucceeds",
			args: []string{"-c", "some/path/to/config.yaml"},
		},
		{
			name: "LongConfigFlagSucceeds",
			args: []string{"--config", "some/path/to/config.yaml"},
		},
		{
			name: "OneArgWithConfigFlagFails",
			args: []string{
				"--config", "some/path/to/config.yaml",
				"tuna",
			},
			wantErr: `unknown command "tuna" for "pinniped-server"`,
		},
		{
			name: "PercentageIsNotRealNumber",
			args: []string{
				"--config", "some/path/to/config.yaml",
				"--serving-cert-rotation-threshold", "tuna",
			},
			wantErr: `invalid argument "tuna" for "--serving-cert-rotation-threshold" flag: must pass real number between 0 and 1`,
		},
		{
			name: "PercentageIsTooSmall",
			args: []string{
				"--config", "some/path/to/config.yaml",
				"--serving-cert-rotation-threshold", "-1",
			},
			wantErr: `invalid argument "-1" for "--serving-cert-rotation-threshold" flag: must pass real number between 0 and 1`,
		},
		{
			name: "PercentageIsTooLarge",
			args: []string{
				"--config", "some/path/to/config.yaml",
				"--serving-cert-rotation-threshold", "75",
			},
			wantErr: `invalid argument "75" for "--serving-cert-rotation-threshold" flag: must pass real number between 0 and 1`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			stdout := bytes.NewBuffer([]byte{})
			stderr := bytes.NewBuffer([]byte{})

			a := New(context.Background(), test.args, stdout, stderr)
			a.cmd.RunE = func(cmd *cobra.Command, args []string) error {
				return nil
			}
			err := a.Run()
			if test.wantErr != "" {
				require.EqualError(t, err, test.wantErr)
			} else {
				require.NoError(t, err)
			}
			if test.wantStdout != "" {
				require.Equal(t, strings.TrimSpace(test.wantStdout), strings.TrimSpace(stdout.String()), cmp.Diff(test.wantStdout, stdout.String()))
			}
		})
	}
}
