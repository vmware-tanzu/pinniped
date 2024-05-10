// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apimachineryversion "k8s.io/apimachinery/pkg/version"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/pversion"
)

var (
	knownGoodUsageRegexpForVersion = here.Doc(`
		Usage:
		  version \[flags\]

		Flags:
		  -h, --help            help for version
		  -o, --output string   one of 'yaml' or 'json'
		`)

	knownGoodHelpRegexpForVersion = here.Doc(`
		Print the version of this Pinniped CLI

		Usage:
		  version \[flags\]

		Flags:
		  -h, --help            help for version
		  -o, --output string   one of 'yaml' or 'json'
		`)

	jsonRegexp = here.Doc(`{
  "major": "\d*",
  "minor": "\d*",
  "gitVersion": "i am a version for json output",
  "gitCommit": ".*",
  "gitTreeState": ".*",
  "buildDate": ".*",
  "goVersion": ".*",
  "compiler": ".*",
  "platform": ".*/.*"
}`)

	yamlRegexp = here.Doc(`buildDate: ".*"
compiler: .*
gitCommit: .*
gitTreeState: .*
gitVersion: i am a version for yaml output
goVersion: .*
major: "\d*"
minor: "\d*"
platform: .*/.*
`)
)

func TestNewVersionCmd(t *testing.T) {
	t.Cleanup(func() {
		getBuildInfo = pversion.Get
	})

	tests := []struct {
		name             string
		args             []string
		vars             string
		getBuildInfo     func() apimachineryversion.Info
		wantError        bool
		wantStdoutRegexp string
		wantStderrRegexp string
	}{
		{
			name: "no flags",
			args: []string{},
			getBuildInfo: func() apimachineryversion.Info {
				return apimachineryversion.Info{GitVersion: "v55.66.44"}
			},
			wantStdoutRegexp: "v55.66.44\n",
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
		{
			name: "json output",
			args: []string{"--output", "json"},
			getBuildInfo: func() apimachineryversion.Info {
				return apimachineryversion.Info{
					GitVersion: "i am a version for json output",
					Platform:   "a/b",
				}
			},
			wantStdoutRegexp: jsonRegexp,
		},
		{
			name: "yaml output",
			args: []string{"--output", "yaml"},
			getBuildInfo: func() apimachineryversion.Info {
				return apimachineryversion.Info{
					GitVersion: "i am a version for yaml output",
					Platform:   "c/d",
				}
			},
			wantStdoutRegexp: yamlRegexp,
		},
		{
			name:             "incorrect output",
			args:             []string{"--output", "foo"},
			wantError:        true,
			wantStderrRegexp: `Error: 'foo' is not a valid option for output`,
			wantStdoutRegexp: knownGoodUsageRegexpForVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.getBuildInfo != nil {
				getBuildInfo = tt.getBuildInfo
			}

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
