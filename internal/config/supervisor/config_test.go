// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/plog"
)

func TestFromPath(t *testing.T) {
	tests := []struct {
		name                string
		yaml                string
		allowedCiphersError error
		wantConfig          *Config
		wantError           string
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
				endpoints:
				  https:
				    network: unix
				    address: :1234
				  http:
				    network: tcp
				    address: 127.0.0.1:1234
				insecureAcceptExternalUnencryptedHttpRequests: false
				log:
				  level: info
				  format: json
				aggregatedAPIServerPort: 12345
				aggregatedAPIServerDisableAdmissionPlugins:
				  - NamespaceLifecycle
				  - MutatingAdmissionWebhook
				  - ValidatingAdmissionPolicy
				  - ValidatingAdmissionWebhook
				tls:
				  onedottwo:
				    allowedCiphers:
				    - foo
				    - bar
				    - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
				audit:
				  logUsernamesAndGroups: enabled
				  logInternalPaths: enabled
			`),
			wantConfig: &Config{
				APIGroupSuffix: ptr.To("some.suffix.com"),
				Labels: map[string]string{
					"myLabelKey1": "myLabelValue1",
					"myLabelKey2": "myLabelValue2",
				},
				NamesConfig: NamesConfigSpec{
					DefaultTLSCertificateSecret: "my-secret-name",
				},
				Endpoints: &Endpoints{
					HTTPS: &Endpoint{
						Network: "unix",
						Address: ":1234",
					},
					HTTP: &Endpoint{
						Network: "tcp",
						Address: "127.0.0.1:1234",
					},
				},
				Log: plog.LogSpec{
					Level:  plog.LevelInfo,
					Format: plog.FormatJSON,
				},
				AggregatedAPIServerPort: ptr.To[int64](12345),
				AggregatedAPIServerDisableAdmissionPlugins: []string{
					"NamespaceLifecycle",
					"MutatingAdmissionWebhook",
					"ValidatingAdmissionPolicy",
					"ValidatingAdmissionWebhook",
				},
				TLS: TLSSpec{
					OneDotTwo: TLSProtocolSpec{
						AllowedCiphers: []string{
							"foo",
							"bar",
							"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
						},
					},
				},
				Audit: AuditSpec{
					LogUsernamesAndGroups: "enabled",
					LogInternalPaths:      "enabled",
				},
			},
		},
		{
			name: "cli is a bad log format when configured by the user",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
				log:
				  level: info
				  format: cli
			`),
			wantError: "decode yaml: error unmarshaling JSON: while decoding JSON: invalid log format, valid choices are the empty string or 'json'",
		},
		{
			name: "When only the required fields are present, causes other fields to be defaulted",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
			`),
			wantConfig: &Config{
				APIGroupSuffix: ptr.To("pinniped.dev"),
				Labels:         map[string]string{},
				NamesConfig: NamesConfigSpec{
					DefaultTLSCertificateSecret: "my-secret-name",
				},
				Endpoints: &Endpoints{
					HTTPS: &Endpoint{
						Network: "tcp",
						Address: ":8443",
					},
					HTTP: &Endpoint{
						Network: "disabled",
					},
				},
				AggregatedAPIServerPort: ptr.To[int64](10250),
				Audit: AuditSpec{
					LogInternalPaths:      "",
					LogUsernamesAndGroups: "",
				},
				AggregatedAPIServerDisableAdmissionPlugins: nil,
				TLS: TLSSpec{},
				Log: plog.LogSpec{},
			},
		},
		{
			name: "audit settings can be disabled explicitly",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
				audit:
				  logInternalPaths: disabled
				  logUsernamesAndGroups: disabled
			`),
			wantConfig: &Config{
				APIGroupSuffix: ptr.To("pinniped.dev"),
				Labels:         map[string]string{},
				NamesConfig: NamesConfigSpec{
					DefaultTLSCertificateSecret: "my-secret-name",
				},
				Endpoints: &Endpoints{
					HTTPS: &Endpoint{
						Network: "tcp",
						Address: ":8443",
					},
					HTTP: &Endpoint{
						Network: "disabled",
					},
				},
				AggregatedAPIServerPort: ptr.To[int64](10250),
				Audit: AuditSpec{
					LogInternalPaths:      "disabled",
					LogUsernamesAndGroups: "disabled",
				},
			},
		},
		{
			name: "all endpoints disabled",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
				endpoints:
				  https:
				    network: disabled
				  http:
				    network: disabled
			`),
			wantError: "validate endpoints: all endpoints are disabled",
		},
		{
			name: "invalid https endpoint",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
				endpoints:
				  https:
				    network: foo
				  http:
				    network: disabled
			`),
			wantError: `validate https endpoint: unknown network "foo"`,
		},
		{
			name: "invalid http endpoint",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
				endpoints:
				  https:
				    network: disabled
				  http:
				    network: bar
			`),
			wantError: `validate http endpoint: unknown network "bar"`,
		},
		{
			name: "http endpoint uses tcp but binds to more than only loopback interfaces with insecureAcceptExternalUnencryptedHttpRequests missing",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
				endpoints:
				  https:
				    network: disabled
				  http:
				    network: tcp
					address: :8080
			`),
			wantError: `validate http endpoint: http listener address ":8080" for "tcp" network may only bind to loopback interfaces`,
		},
		{
			name: "http endpoint uses tcp but binds to more than only loopback interfaces",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
				endpoints:
				  https:
				    network: disabled
				  http:
				    network: tcp
					address: :8080
			`),
			wantError: `validate http endpoint: http listener address ":8080" for "tcp" network may only bind to loopback interfaces`,
		},
		{
			name: "endpoint disabled with non-empty address",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
				endpoints:
				  https:
				    network: disabled
				    address: wee
			`),
			wantError: `validate https endpoint: address set to "wee" when disabled, should be empty`,
		},
		{
			name: "endpoint tcp with empty address",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
				endpoints:
				  http:
				    network: tcp
			`),
			wantError: `validate http endpoint: address must be set with "tcp" network`,
		},
		{
			name: "endpoint unix with empty address",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
				endpoints:
				  https:
				    network: unix
			`),
			wantError: `validate https endpoint: address must be set with "unix" network`,
		},
		{
			name: "Missing defaultTLSCertificateSecret name",
			yaml: here.Doc(`
				---
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
		{
			name: "AggregatedAPIServerPortDefault too small",
			yaml: here.Doc(`
				---
				aggregatedAPIServerPort: 1023
			`),
			wantError: "validate aggregatedAPIServerPort: must be within range 1024 to 65535",
		},
		{
			name: "AggregatedAPIServerPortDefault too large",
			yaml: here.Doc(`
				---
				aggregatedAPIServerPort: 65536
			`),
			wantError: "validate aggregatedAPIServerPort: must be within range 1024 to 65535",
		},
		{
			name: "invalid audit.logUsernamesAndGroups format",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
				audit:
				  logUsernamesAndGroups: this-is-not-a-valid-value
			`),
			wantError: "validate audit: invalid logUsernamesAndGroups format, valid choices are 'enabled', 'disabled', or empty string (equivalent to 'disabled')",
		},
		{
			name: "invalid audit.logInternalPaths format",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
				audit:
				  logInternalPaths: this-is-not-a-valid-value
			`),
			wantError: "validate audit: invalid logInternalPaths format, valid choices are 'enabled', 'disabled', or empty string (equivalent to 'disabled')",
		},
		{
			name: "returns setAllowedCiphers errors",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
				tls:
				  onedottwo:
				    allowedCiphers:
				    - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
			`),
			allowedCiphersError: fmt.Errorf("some error from setAllowedCiphers"),
			wantError:           "validate tls: some error from setAllowedCiphers",
		},
		{
			name: "invalid aggregatedAPIServerDisableAdmissionPlugins",
			yaml: here.Doc(`
				---
				names:
				  defaultTLSCertificateSecret: my-secret-name
				aggregatedAPIServerDisableAdmissionPlugins: [foobar, ValidatingAdmissionWebhook, foobaz]
			`),
			wantError: "validate aggregatedAPIServerDisableAdmissionPlugins: admission plugin names not recognized: [foobar foobaz] (each must be one of [NamespaceLifecycle MutatingAdmissionPolicy MutatingAdmissionWebhook ValidatingAdmissionPolicy ValidatingAdmissionWebhook])",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// this is a serial test because it sets the global logger

			// Write yaml to temp file
			f, err := os.CreateTemp("", "pinniped-test-config-yaml-*")
			require.NoError(t, err)
			t.Cleanup(func() {
				err := os.Remove(f.Name())
				require.NoError(t, err)
			})
			_, err = f.WriteString(test.yaml)
			require.NoError(t, err)
			err = f.Close()
			require.NoError(t, err)

			// Test FromPath()
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			var actualCiphers []string
			setAllowedCiphers := func(ciphers []string) error {
				actualCiphers = ciphers
				return test.allowedCiphersError
			}

			config, err := FromPath(ctx, f.Name(), setAllowedCiphers)

			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.wantConfig, config)
			require.Equal(t, test.wantConfig.TLS.OneDotTwo.AllowedCiphers, actualCiphers)
		})
	}
}

func TestAddrIsOnlyOnLoopback(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{addr: "localhost:", want: true},
		{addr: "localhost:0", want: true},
		{addr: "localhost:80", want: true},
		{addr: "localhost:http", want: true},
		{addr: "ip6-localhost:", want: true},
		{addr: "ip6-localhost:0", want: true},
		{addr: "ip6-localhost:80", want: true},
		{addr: "ip6-localhost:http", want: true},
		{addr: "ip6-loopback:", want: true},
		{addr: "ip6-loopback:0", want: true},
		{addr: "ip6-loopback:80", want: true},
		{addr: "ip6-loopback:http", want: true},
		{addr: "127.0.0.1:", want: true},
		{addr: "127.0.0.1:0", want: true},
		{addr: "127.0.0.1:80", want: true},
		{addr: "127.0.0.1:http", want: true},
		{addr: "[::1]:", want: true},
		{addr: "[::1]:0", want: true},
		{addr: "[::1]:80", want: true},
		{addr: "[::1]:http", want: true},
		{addr: "[0:0:0:0:0:0:0:1]:", want: true},
		{addr: "[0:0:0:0:0:0:0:1]:0", want: true},
		{addr: "[0:0:0:0:0:0:0:1]:80", want: true},
		{addr: "[0:0:0:0:0:0:0:1]:http", want: true},
		{addr: "", want: false},               // illegal input, can't be empty
		{addr: "host", want: false},           // illegal input, need colon
		{addr: "localhost", want: false},      // illegal input, need colon
		{addr: "127.0.0.1", want: false},      // illegal input, need colon
		{addr: ":", want: false},              // illegal input, need either host or port
		{addr: "2001:db8::1:80", want: false}, // illegal input, forgot square brackets
		{addr: ":0", want: false},
		{addr: ":80", want: false},
		{addr: ":http", want: false},
		{addr: "notlocalhost:", want: false},
		{addr: "notlocalhost:0", want: false},
		{addr: "notlocalhost:80", want: false},
		{addr: "notlocalhost:http", want: false},
		{addr: "0.0.0.0:", want: false},
		{addr: "0.0.0.0:0", want: false},
		{addr: "0.0.0.0:80", want: false},
		{addr: "0.0.0.0:http", want: false},
		{addr: "[::]:", want: false},
		{addr: "[::]:0", want: false},
		{addr: "[::]:80", want: false},
		{addr: "[::]:http", want: false},
		{addr: "42.42.42.42:", want: false},
		{addr: "42.42.42.42:0", want: false},
		{addr: "42.42.42.42:80", want: false},
		{addr: "42.42.42.42:http", want: false},
		{addr: "[2001:db8::1]:", want: false},
		{addr: "[2001:db8::1]:0", want: false},
		{addr: "[2001:db8::1]:80", want: false},
		{addr: "[2001:db8::1]:http", want: false},
		{addr: "[fe80::1%zone]:", want: false},
		{addr: "[fe80::1%zone]:0", want: false},
		{addr: "[fe80::1%zone]:80", want: false},
		{addr: "[fe80::1%zone]:http", want: false},
	}
	for _, test := range tests {
		tt := test
		t.Run(fmt.Sprintf("address %s should be %t", tt.addr, tt.want), func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.want, addrIsOnlyOnLoopback(tt.addr))
		})
	}
}
