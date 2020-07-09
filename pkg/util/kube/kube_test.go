/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package kube

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnonymousClientset(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		caBundlePath string
		wantErr      bool
	}{
		{
			name:         "Happy",
			url:          "https://some-kube-api.com",
			caBundlePath: "testdata/happy.pem",
		},
		{
			name:         "SadURL",
			url:          "this://is-a-bad \n url",
			caBundlePath: "testdata/happy.pem",
			wantErr:      true,
		},
		{
			name:         "SadCABundlePath",
			url:          "https://some-kube-api.com",
			caBundlePath: "testdata/does-not-exist.txt",
			wantErr:      true,
		},
		{
			name:         "SadCABundle",
			url:          "https://some-kube-api.com",
			caBundlePath: "testdata/sad.txt",
			wantErr:      true,
		},
	}
	for _, theTest := range tests {
		test := theTest
		t.Run(test.name, func(t *testing.T) {
			// Just make sure this function succeeds.
			// Not sure we can do much more on a unit test level.
			_, err := AnonymousClientset(test.url, test.caBundlePath)
			if test.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
