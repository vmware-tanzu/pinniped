/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFromConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		wantSuccess bool
	}{
		{
			name: "Happy",
			config: Config{
				URL:          "https://tuna.com/marlin",
				CABundlePath: "testdata/happy.pem",
			},
			wantSuccess: true,
		},
		{
			name: "SadURL",
			config: Config{
				URL:          "this://is-a-bad \n url",
				CABundlePath: "testdata/happy.pem",
			},
		},
		{
			name: "SadHTTPURL",
			config: Config{
				URL:          "http://tuna.com/marlin",
				CABundlePath: "testdata/happy.pem",
			},
		},
		{
			name: "SadCABundlePath",
			config: Config{
				URL:          "http://tuna.com/marlin",
				CABundlePath: "testdata/does-not-exist.txt",
			},
		},
		{
			name: "SadCABundle",
			config: Config{
				URL:          "http://tuna.com/marlin",
				CABundlePath: "testdata/sad.txt",
			},
		},
	}
	for _, theTest := range tests {
		test := theTest
		t.Run(test.name, func(t *testing.T) {
			expect := assert.New(t)

			w, err := FromConfig(&test.config)
			t.Logf("%+v", w)
			if test.wantSuccess {
				expect.NoError(err)
			} else {
				expect.Error(err)
			}
		})
	}
}
