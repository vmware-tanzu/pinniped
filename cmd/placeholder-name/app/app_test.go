/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package app

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			expect := require.New(t)

			stdout := bytes.NewBuffer([]byte{})
			stderr := bytes.NewBuffer([]byte{})

			configPaths := make([]string, 0, 1)
			runFunc := func(ctx context.Context, configPath string) error {
				configPaths = append(configPaths, configPath)
				return nil
			}

			a := New(test.args, stdout, stderr)
			a.runFunc = runFunc
			err := a.Run()

			if test.wantConfigPath != "" {
				expect.Equal(1, len(configPaths))
				expect.Equal(test.wantConfigPath, configPaths[0])
			} else {
				expect.Error(err)
				expect.Contains(stdout.String(), knownGoodUsage)
			}
		})
	}
}

func TestServeApp(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		cancel()

		a := App{
			healthAddr: "127.0.0.1:0",
			mainAddr:   "127.0.0.1:8443",
		}
		err := a.serve(ctx, "testdata/valid-config.yaml")
		require.NoError(t, err)
	})

	t.Run("failure", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		a := App{
			healthAddr: "127.0.0.1:8081",
			mainAddr:   "127.0.0.1:8081",
		}
		err := a.serve(ctx, "testdata/valid-config.yaml")
		require.EqualError(t, err, "listen tcp 127.0.0.1:8081: bind: address already in use")
	})
}
