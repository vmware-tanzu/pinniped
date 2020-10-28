// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
)

func TestFromPath(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		wantConfig *Config
		wantError  string
	}{
		{
			name: "Happy",
			yaml: here.Doc(`
				---
				labels:
				  myLabelKey1: myLabelValue1
				  myLabelKey2: myLabelValue2
				names:
				  defaultTLSCertificateSecret: my-secret-name
			`),
			wantConfig: &Config{
				Labels: map[string]string{
					"myLabelKey1": "myLabelValue1",
					"myLabelKey2": "myLabelValue2",
				},
				NamesConfig: NamesConfigSpec{
					DefaultTLSCertificateSecret: "my-secret-name",
				},
			},
		},
		{
			name: "When only the required fields are present, causes other fields to be defaulted",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
			`),
			wantConfig: &Config{
				Labels: map[string]string{},
				NamesConfig: NamesConfigSpec{
					DefaultTLSCertificateSecret: "my-secret-name",
				},
			},
		},
		{
			name: "Missing defaultTLSCertificateSecret name",
			yaml: here.Doc(`
				---
			`),
			wantError: "validate names: missing required names: defaultTLSCertificateSecret",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Write yaml to temp file
			f, err := ioutil.TempFile("", "pinniped-test-config-yaml-*")
			require.NoError(t, err)
			defer func() {
				err := os.Remove(f.Name())
				require.NoError(t, err)
			}()
			_, err = f.WriteString(test.yaml)
			require.NoError(t, err)
			err = f.Close()
			require.NoError(t, err)

			// Test FromPath()
			config, err := FromPath(f.Name())

			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.wantConfig, config)
			}
		})
	}
}
