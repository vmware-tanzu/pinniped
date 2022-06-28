// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEntrypoint(t *testing.T) {
	for _, tt := range []struct {
		name       string
		args       []string
		wantOutput string
		wantFail   bool
		wantArgs   []string
	}{
		{
			name:       "missing args",
			args:       []string{},
			wantOutput: "missing os.Args\n",
			wantFail:   true,
		},
		{
			name:       "invalid subcommand",
			args:       []string{"/path/to/invalid", "some", "args"},
			wantOutput: "must be invoked as one of [another-test-binary valid-test-binary], not \"invalid\"\n",
			wantFail:   true,
		},
		{
			name:     "valid",
			args:     []string{"/path/to/valid-test-binary", "foo", "bar"},
			wantArgs: []string{"/path/to/valid-test-binary", "foo", "bar"},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			testLog := log.New(&logBuf, "", 0)
			exited := "exiting via fatal"
			fail = func(err error, keysAndValues ...interface{}) {
				testLog.Print(err)
				if len(keysAndValues) > 0 {
					testLog.Print(keysAndValues...)
				}
				panic(exited)
			}

			// Make a test command that records os.Args when it's invoked.
			var gotArgs []string
			subcommands = map[string]func(){
				"valid-test-binary":   func() { gotArgs = os.Args },
				"another-test-binary": func() {},
			}

			os.Args = tt.args
			if tt.wantFail {
				require.PanicsWithValue(t, exited, main)
			} else {
				require.NotPanics(t, main)
			}
			if tt.wantArgs != nil {
				require.Equal(t, tt.wantArgs, gotArgs)
			}
			if tt.wantOutput != "" {
				require.Equal(t, tt.wantOutput, logBuf.String())
			}
		})
	}
}
