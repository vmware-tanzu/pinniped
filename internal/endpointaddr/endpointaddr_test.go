// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package endpointaddr

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			name:        "invalid IPv4",
			input:       "1.1.1.",
			defaultPort: 443,
			expectErr:   `host "1.1.1." is not a valid hostname or IP address`,
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
			name:        "invalid host with extra port",
			input:       "host.example.com:port1:port2",
			defaultPort: 443,
			expectErr:   `host "host.example.com:port1:port2" is not a valid hostname or IP address`,
		},
		{
			name:           "hostname with upper case letters should be valid",
			input:          "HoSt.EXamplE.cOM",
			defaultPort:    443,
			expect:         HostPort{Host: "HoSt.EXamplE.cOM", Port: 443},
			expectEndpoint: "HoSt.EXamplE.cOM:443",
		},
		{
			name:        "unicode chars are disallowed in host names",
			input:       "Hello.世界🙂.com",
			defaultPort: 443,
			expectErr:   `host "Hello.世界🙂.com" is not a valid hostname or IP address`,
		},
	} {
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

func TestParseFromURL(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name        string
		input       string
		defaultPort uint16
		expectErr   string
		expect      HostPort
		// HostPort.Endpoint() returns a properly constructed endpoint.  The normalization provided by ParseFromURL()
		// expects that the resulting HostPort.Endpoint() will be called to normalize several special cases, especially
		// for IPv6.
		expectEndpoint string
	}{
		// First set of valid passthrough tests to Parse()
		// Matches the above test table, minus any test that would not url.Parse(input) properly
		{
			name:           "plain IPv4",
			input:          "http://127.0.0.1",
			defaultPort:    443,
			expect:         HostPort{Host: "127.0.0.1", Port: 443},
			expectEndpoint: "127.0.0.1:443",
		},
		{
			name:           "IPv4 with port",
			input:          "http://127.0.0.1:8443",
			defaultPort:    443,
			expect:         HostPort{Host: "127.0.0.1", Port: 8443},
			expectEndpoint: "127.0.0.1:8443",
		},
		{
			name:           "IPv4 in brackets with port",
			input:          "http://[127.0.0.1]:8443",
			defaultPort:    443,
			expect:         HostPort{Host: "127.0.0.1", Port: 8443},
			expectEndpoint: "127.0.0.1:8443",
		},
		{
			name:           "IPv4 as IPv6 in brackets with port",
			input:          "http://[::127.0.0.1]:8443",
			defaultPort:    443,
			expect:         HostPort{Host: "::127.0.0.1", Port: 8443},
			expectEndpoint: "[::127.0.0.1]:8443",
		},
		{
			name:           "IPv6 with port",
			input:          "http://[2001:db8::ffff]:8443",
			defaultPort:    443,
			expect:         HostPort{Host: "2001:db8::ffff", Port: 8443},
			expectEndpoint: "[2001:db8::ffff]:8443",
		},
		{
			name:           "plain hostname",
			input:          "http://host.example.com",
			defaultPort:    443,
			expect:         HostPort{Host: "host.example.com", Port: 443},
			expectEndpoint: "host.example.com:443",
		},
		{
			name:           "plain hostname with dash",
			input:          "http://host-dev.example.com",
			defaultPort:    443,
			expect:         HostPort{Host: "host-dev.example.com", Port: 443},
			expectEndpoint: "host-dev.example.com:443",
		},
		{
			name:           "hostname with port",
			input:          "http://host.example.com:8443",
			defaultPort:    443,
			expect:         HostPort{Host: "host.example.com", Port: 8443},
			expectEndpoint: "host.example.com:8443",
		},
		{
			name:           "hostname in brackets with port",
			input:          "http://[host.example.com]:8443",
			defaultPort:    443,
			expect:         HostPort{Host: "host.example.com", Port: 8443},
			expectEndpoint: "host.example.com:8443",
		},
		{
			name:           "hostname without dots",
			input:          "http://localhost",
			defaultPort:    443,
			expect:         HostPort{Host: "localhost", Port: 443},
			expectEndpoint: "localhost:443",
		},
		{
			name:           "hostname and port without dots",
			input:          "http://localhost:8443",
			defaultPort:    443,
			expect:         HostPort{Host: "localhost", Port: 8443},
			expectEndpoint: "localhost:8443",
		},
		{
			name:        "http://invalid empty string",
			input:       "",
			defaultPort: 443,
			expectErr:   `host "" is not a valid hostname or IP address`,
		},
		{
			name:        "invalid host with underscores",
			input:       "http://___.example.com:1234",
			defaultPort: 443,
			expectErr:   `host "___.example.com" is not a valid hostname or IP address`,
		},

		{
			name:           "hostname with upper case letters should be valid",
			input:          "https://HoSt.EXamplE.cOM",
			defaultPort:    443,
			expect:         HostPort{Host: "HoSt.EXamplE.cOM", Port: 443},
			expectEndpoint: "HoSt.EXamplE.cOM:443",
		},
		{
			name:        "unicode chars are disallowed in host names",
			input:       "https://Hello.世界🙂.com",
			defaultPort: 443,
			expectErr:   `host "Hello.世界🙂.com" is not a valid hostname or IP address`,
		},
		// new tests for new functionality
		{
			name:           "IPv6 with brackets but without port will strip brackets to create HostPort{}, which will add brackets when HostPort.Endpoint() is called",
			input:          "http://[2001:db8::ffff]",
			defaultPort:    443,
			expect:         HostPort{Host: "2001:db8::ffff", Port: 443},
			expectEndpoint: "[2001:db8::ffff]:443",
		},
		{
			name:           "IPv6 without brackets and without port will create HostPort{}, which will add brackets when HostPort.Endpoint() is called",
			input:          "http://2001:db8::1234",
			defaultPort:    443,
			expect:         HostPort{Host: "2001:db8::1234", Port: 443},
			expectEndpoint: "[2001:db8::1234]:443",
		},
		{
			name:           "IPv6 without brackets and without port with path create HostPort{}, which will add brackets when HostPort.Endpoint() is called",
			input:          "https://0:0:0:0:0:0:0:1/some/fake/path",
			defaultPort:    443,
			expect:         HostPort{Host: "0:0:0:0:0:0:0:1", Port: 443},
			expectEndpoint: "[0:0:0:0:0:0:0:1]:443",
		},
		{
			name:           "IPv6 with mismatched leading bracket will err on bracket",
			input:          "https://[[::1]/some/fake/path",
			defaultPort:    443,
			expect:         HostPort{Host: "[[::1]", Port: 443},
			expectEndpoint: "[[::1]:443",
			expectErr:      `address [[::1]:443: unexpected '[' in address`,
		},
		{
			name:           "IPv6 with mismatched trailing brackets will err on port",
			input:          "https://[::1]]/some/fake/path",
			defaultPort:    443,
			expect:         HostPort{Host: "[::1]]", Port: 443},
			expectEndpoint: "[::1]]:443",
			expectErr:      `address [::1]]:443: missing port in address`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			urlToProcess, err := url.Parse(tt.input)
			require.NoError(t, err, "ParseFromURL expects a valid url.URL, parse errors here are not valuable")

			got, err := ParseFromURL(urlToProcess, tt.defaultPort)
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
