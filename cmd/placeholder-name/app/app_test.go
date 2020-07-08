/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package app

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

const knownGoodUsage = `Usage:
  placeholder-name [flags]

Flags:
  -c, --config string   path to configuration file (default "placeholder-name.yaml")
  -h, --help            help for placeholder-name
`

func TestCommand(t *testing.T) {
	tests := []struct {
		name string
		args []string

		wantConfigPath string
	}{
		{
			name:           "NoArgsSucceeds",
			args:           []string{},
			wantConfigPath: "placeholder-name.yaml",
		},
		{
			name: "OneArgFails",
			args: []string{"tuna"},
		},
		{
			name:           "ShortConfigFlagSucceeds",
			args:           []string{"-c", "some/path/to/config.yaml"},
			wantConfigPath: "some/path/to/config.yaml",
		},
		{
			name:           "LongConfigFlagSucceeds",
			args:           []string{"--config", "some/path/to/config.yaml"},
			wantConfigPath: "some/path/to/config.yaml",
		},
		{
			name: "OneArgWithConfigFlagFails",
			args: []string{
				"--config", "some/path/to/config.yaml",
				"tuna",
			},
		},
	}
	for _, theTest := range tests {
		test := theTest // please the linter :'(
		t.Run(test.name, func(t *testing.T) {
			expect := assert.New(t)

			stdout := bytes.NewBuffer([]byte{})
			stderr := bytes.NewBuffer([]byte{})

			configPaths := make([]string, 0, 1)
			runFunc := func(configPath string) {
				configPaths = append(configPaths, configPath)
			}

			a := New(test.args, stdout, stderr)
			a.runFunc = runFunc
			err := a.Run()

			if test.wantConfigPath != "" {
				if expect.Equal(1, len(configPaths)) {
					expect.Equal(test.wantConfigPath, configPaths[0])
				}
			} else {
				expect.Error(err)
				expect.Contains(stdout.String(), knownGoodUsage)
			}
		})
	}
}
