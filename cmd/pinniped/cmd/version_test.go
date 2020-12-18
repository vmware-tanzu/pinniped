// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
)

var (
	knownGoodUsageRegexpForVersion = here.Doc(`
		Usage:
		  version \[flags\]

		Flags:
		  -h, --help   help for version

		`)

	knownGoodHelpRegexpForVersion = here.Doc(`
		Print the version of this Pinniped CLI

		Usage:
		  version \[flags\]

		Flags:
		  -h, --help   help for version
		`)

	emptyVersionRegexp = `version.Info{Major:"", Minor:"", GitVersion:".*", GitCommit:".*", GitTreeState:"", BuildDate:".*", GoVersion:".*", Compiler:".*", Platform:".*/.*"}`
)

func TestNewVersionCmd(t *testing.T) {
	tests := []struct {
		name             string
		args             []string
		wantError        bool
		wantStdoutRegexp string
		wantStderrRegexp string
	}{
		{
			name:             "no flags",
			args:             []string{},
			wantStdoutRegexp: emptyVersionRegexp + "\n",
		},
		{
			name:             "help flag passed",
			args:             []string{"--help"},
			wantStdoutRegexp: knownGoodHelpRegexpForVersion,
		},
		{
			name:             "arg passed",
			args:             []string{"tuna"},
			wantError:        true,
			wantStderrRegexp: `Error: unknown command "tuna" for "version"`,
			wantStdoutRegexp: knownGoodUsageRegexpForVersion,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			cmd := newVersionCommand()
			require.NotNil(t, cmd)

			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Regexp(t, tt.wantStdoutRegexp, stdout.String(), "unexpected stdout")
			assert.Regexp(t, tt.wantStderrRegexp, stderr.String(), "unexpected stderr")
		})
	}
}
