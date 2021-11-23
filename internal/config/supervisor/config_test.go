// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"io/ioutil"
	"os"
	"testing"

	"k8s.io/utils/pointer"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
)

func TestFromPath(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		wantConfig *Config
		wantError  string

		wantSupervisorHTTPListenerNetwork  string
		wantSupervisorHTTPListenerAddress  string
		wantSupervisorHTTPSListenerNetwork string
		wantSupervisorHTTPSListenerAddress string
	}{
		{
			name: "Happy",
			yaml: here.Doc(`
				---
				apiGroupSuffix: some.suffix.com
				labels:
				  myLabelKey1: myLabelValue1
				  myLabelKey2: myLabelValue2
				names:
				  defaultTLSCertificateSecret: my-secret-name
				supervisorHTTPListener: "tcp,:8080"
				supervisorHTTPSListener: "tcp,:8443"
			`),
			wantConfig: &Config{
				APIGroupSuffix: pointer.StringPtr("some.suffix.com"),
				Labels: map[string]string{
					"myLabelKey1": "myLabelValue1",
					"myLabelKey2": "myLabelValue2",
				},
				NamesConfig: NamesConfigSpec{
					DefaultTLSCertificateSecret: "my-secret-name",
				},
				SupervisorHTTPListener:  "tcp,:8080",
				SupervisorHTTPSListener: "tcp,:8443",
			},
			wantSupervisorHTTPListenerNetwork:  "tcp",
			wantSupervisorHTTPListenerAddress:  ":8080",
			wantSupervisorHTTPSListenerNetwork: "tcp",
			wantSupervisorHTTPSListenerAddress: ":8443",
		},
		{
			name: "When only the required fields are present, causes other fields to be defaulted",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
				supervisorHTTPSListener: "tcp,:8443"
			`),
			wantConfig: &Config{
				APIGroupSuffix: pointer.StringPtr("pinniped.dev"),
				Labels:         map[string]string{},
				NamesConfig: NamesConfigSpec{
					DefaultTLSCertificateSecret: "my-secret-name",
				},
				SupervisorHTTPSListener: "tcp,:8443",
			},
			wantSupervisorHTTPListenerNetwork:  "",
			wantSupervisorHTTPListenerAddress:  "",
			wantSupervisorHTTPSListenerNetwork: "tcp",
			wantSupervisorHTTPSListenerAddress: ":8443",
		},
		{
			name: "Missing supervisorHTTPSListener",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
			`),
			wantError: "validate supervisorHTTPSListener: must have format 'network,address'",
		},
		{
			name: "Blank supervisorHTTPSListener",
			yaml: here.Doc(`
				---
				supervisorHTTPSListener: "   "
				names:
				  defaultTLSCertificateSecret: my-secret-name
			`),
			wantError: "validate supervisorHTTPSListener: must have format 'network,address'",
		},
		{
			name: "No comma supervisorHTTPListener",
			yaml: here.Doc(`
				---
				supervisorHTTPListener: "foo"
				supervisorHTTPSListener: "tcp,:8443"
				names:
				  defaultTLSCertificateSecret: my-secret-name
			`),
			wantError: "validate supervisorHTTPListener: must have format 'network,address'",
		},
		{
			name: "No comma supervisorHTTPSListener",
			yaml: here.Doc(`
				---
				supervisorHTTPSListener: "foo"
				names:
				  defaultTLSCertificateSecret: my-secret-name
			`),
			wantError: "validate supervisorHTTPSListener: must have format 'network,address'",
		},
		{
			name: "Empty network type supervisorHTTPSListener",
			yaml: here.Doc(`
				---
				supervisorHTTPSListener: ",42"
				names:
				  defaultTLSCertificateSecret: my-secret-name
			`),
			wantError: "validate supervisorHTTPSListener: must have format 'network,address'",
		},
		{
			name: "Empty network type supervisorHTTPListener",
			yaml: here.Doc(`
				---
				supervisorHTTPListener: ",42"
				supervisorHTTPSListener: "tcp,:8443"
				names:
				  defaultTLSCertificateSecret: my-secret-name
			`),
			wantError: "validate supervisorHTTPListener: must have format 'network,address'",
		},
		{
			name: "Empty address supervisorHTTPSListener",
			yaml: here.Doc(`
				---
				supervisorHTTPSListener: "tcp,"
				names:
				  defaultTLSCertificateSecret: my-secret-name
			`),
			wantError: "validate supervisorHTTPSListener: must have format 'network,address'",
		},
		{
			name: "Empty address supervisorHTTPListener",
			yaml: here.Doc(`
				---
				supervisorHTTPListener: "tcp,"
				supervisorHTTPSListener: "tcp,:8443"
				names:
				  defaultTLSCertificateSecret: my-secret-name
			`),
			wantError: "validate supervisorHTTPListener: must have format 'network,address'",
		},
		{
			name: "Invalid network type supervisorHTTPSListener",
			yaml: here.Doc(`
				---
				supervisorHTTPSListener: "foo,42"
				names:
				  defaultTLSCertificateSecret: my-secret-name
			`),
			wantError: "validate supervisorHTTPSListener: invalid network type",
		},
		{
			name: "Invalid network type supervisorHTTPListener",
			yaml: here.Doc(`
				---
				supervisorHTTPListener: "foo,42"
				supervisorHTTPSListener: "tcp,:8443"
				names:
				  defaultTLSCertificateSecret: my-secret-name
			`),
			wantError: "validate supervisorHTTPListener: invalid network type",
		},
		{
			name: "Missing defaultTLSCertificateSecret name",
			yaml: here.Doc(`
				---
				supervisorHTTPSListener: "tcp,:8443"
			`),
			wantError: "validate names: missing required names: defaultTLSCertificateSecret",
		},
		{
			name: "apiGroupSuffix is prefixed with '.'",
			yaml: here.Doc(`
				---
				apiGroupSuffix: .starts.with.dot
				names:
				  defaultTLSCertificateSecret: my-secret-name
			`),
			wantError: "validate apiGroupSuffix: a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')",
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

				require.Equal(t, test.wantSupervisorHTTPListenerNetwork, config.SupervisorHTTPListenerNetwork())
				require.Equal(t, test.wantSupervisorHTTPListenerAddress, config.SupervisorHTTPListenerAddress())
				require.Equal(t, test.wantSupervisorHTTPSListenerNetwork, config.SupervisorHTTPSListenerNetwork())
				require.Equal(t, test.wantSupervisorHTTPSListenerAddress, config.SupervisorHTTPSListenerAddress())
			}
		})
	}
}
