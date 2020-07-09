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
		name     string
		url      string
		caBundle string
		wantErr  bool
	}{
		{
			name:     "Happy",
			url:      "https://some-kube-api.com",
			caBundle: "testdata/happy.pem",
		},
		{
			name:     "SadURL",
			url:      "this://is-a-bad \n url",
			caBundle: "testdata/happy.pem",
			wantErr:  true,
		},
		{
			name:     "SadCABundlePath",
			url:      "https://some-kube-api.com",
			caBundle: "testdata/does-not-exist.txt",
			wantErr:  true,
		},
		{
			name:     "SadCABundle",
			url:      "https://some-kube-api.com",
			caBundle: "testdata/sad.txt",
			wantErr:  true,
		},
	}
	for _, theTest := range tests {
		test := theTest
		t.Run(test.name, func(t *testing.T) {
			// Just make sure this function succeeds.
			// Not sure we can do much more on a unit test level.
			_, err := AnonymousClientset(test.url, test.caBundle)
			if test.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
