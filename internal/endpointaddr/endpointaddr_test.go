// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package endpointaddr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name           string
		input          string
		defaultPort    uint16
		expectErr      string
		expect         HostPort
		expectEndpoint string
	}{
		{
			name:           "plain IPv4",
			input:          "127.0.0.1",
			defaultPort:    443,
			expect:         HostPort{Host: "127.0.0.1", Port: 443},
			expectEndpoint: "127.0.0.1:443",
		},
		{
			name:           "IPv4 with port",
			input:          "127.0.0.1:8443",
			defaultPort:    443,
			expect:         HostPort{Host: "127.0.0.1", Port: 8443},
			expectEndpoint: "127.0.0.1:8443",
		},
		{
			name:           "IPv4 in brackets with port",
			input:          "[127.0.0.1]:8443",
			defaultPort:    443,
			expect:         HostPort{Host: "127.0.0.1", Port: 8443},
			expectEndpoint: "127.0.0.1:8443",
		},
		{
			name:           "IPv4 as IPv6 in brackets with port",
			input:          "[::127.0.0.1]:8443",
			defaultPort:    443,
			expect:         HostPort{Host: "::127.0.0.1", Port: 8443},
			expectEndpoint: "[::127.0.0.1]:8443",
		},
		{
			name:           "IPv4 as IPv6 without port",
			input:          "::127.0.0.1",
			defaultPort:    443,
			expect:         HostPort{Host: "::127.0.0.1", Port: 443},
			expectEndpoint: "[::127.0.0.1]:443",
		},
		{
			name:           "plain IPv6 without port",
			input:          "2001:db8::ffff",
			defaultPort:    443,
			expect:         HostPort{Host: "2001:db8::ffff", Port: 443},
			expectEndpoint: "[2001:db8::ffff]:443",
		},
		{
			name:           "IPv6 with port",
			input:          "[2001:db8::ffff]:8443",
			defaultPort:    443,
			expect:         HostPort{Host: "2001:db8::ffff", Port: 8443},
			expectEndpoint: "[2001:db8::ffff]:8443",
		},
		{
			name:           "plain hostname",
			input:          "host.example.com",
			defaultPort:    443,
			expect:         HostPort{Host: "host.example.com", Port: 443},
			expectEndpoint: "host.example.com:443",
		},
		{
			name:           "plain hostname with dash",
			input:          "host-dev.example.com",
			defaultPort:    443,
			expect:         HostPort{Host: "host-dev.example.com", Port: 443},
			expectEndpoint: "host-dev.example.com:443",
		},
		{
			name:           "hostname with port",
			input:          "host.example.com:8443",
			defaultPort:    443,
			expect:         HostPort{Host: "host.example.com", Port: 8443},
			expectEndpoint: "host.example.com:8443",
		},
		{
			name:           "hostname in brackets with port",
			input:          "[host.example.com]:8443",
			defaultPort:    443,
			expect:         HostPort{Host: "host.example.com", Port: 8443},
			expectEndpoint: "host.example.com:8443",
		},
		{
			name:           "hostname without dots",
			input:          "localhost",
			defaultPort:    443,
			expect:         HostPort{Host: "localhost", Port: 443},
			expectEndpoint: "localhost:443",
		},
		{
			name:           "hostname and port without dots",
			input:          "localhost:8443",
			defaultPort:    443,
			expect:         HostPort{Host: "localhost", Port: 8443},
			expectEndpoint: "localhost:8443",
		},
		{
			name:        "invalid empty string",
			input:       "",
			defaultPort: 443,
			expectErr:   `host "" is not a valid hostname or IP address`,
		},
		{
			// IPv6 zone index specifiers are not yet supported.
			name:        "IPv6 with port and zone index",
			input:       "[2001:db8::ffff%lo0]:8443",
			defaultPort: 443,
			expectErr:   `host "2001:db8::ffff%lo0" is not a valid hostname or IP address`,
		},
		{
			name:        "IPv6 in brackets without port",
			input:       "[2001:db8::ffff]",
			defaultPort: 443,
			expectErr:   `address [[2001:db8::ffff]]:443: missing port in address`,
		},
		{
			name:        "invalid HTTPS URL",
			input:       "https://host.example.com",
			defaultPort: 443,
			expectErr:   `invalid port "//host.example.com"`,
		},
		{
			name:        "invalid host with URL path",
			input:       "host.example.com/some/path",
			defaultPort: 443,
			expectErr:   `host "host.example.com/some/path" is not a valid hostname or IP address`,
		},
		{
			name:        "invalid host with mismatched brackets",
			input:       "[host.example.com",
			defaultPort: 443,
			expectErr:   "address [host.example.com:443: missing ']' in address",
		},
		{
			name:        "invalid host with underscores",
			input:       "___.example.com:1234",
			defaultPort: 443,
			expectErr:   `host "___.example.com" is not a valid hostname or IP address`,
		},
		{
			name:        "invalid host with uppercase",
			input:       "HOST.EXAMPLE.COM",
			defaultPort: 443,
			expectErr:   `host "HOST.EXAMPLE.COM" is not a valid hostname or IP address`,
		},
		{
			name:        "invalid host with extra port",
			input:       "host.example.com:port1:port2",
			defaultPort: 443,
			expectErr:   `host "host.example.com:port1:port2" is not a valid hostname or IP address`,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.input, tt.defaultPort)
			if tt.expectErr == "" {
				assert.NoError(t, err)
				assert.Equal(t, tt.expect, got)
				assert.Equal(t, tt.expectEndpoint, got.Endpoint())
			} else {
				assert.EqualError(t, err, tt.expectErr)
				assert.Equal(t, HostPort{}, got)
			}
		})
	}
}
