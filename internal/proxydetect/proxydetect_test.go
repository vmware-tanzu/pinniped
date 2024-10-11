// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package proxydetect

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProxyDetectWithoutMock(t *testing.T) {
	// Setting these real env vars means that we cannot run this test in parallel.
	t.Setenv("HTTPS_PROXY", "http://proxy.pinniped.dev")
	t.Setenv("NO_PROXY", "1.2.3.4,1.2.3.5:3333,4.4.4.0/28,example1.pinniped.dev:8443,example2.pinniped.dev")

	subject := New()

	tests := []struct {
		name        string
		host        string
		wantProxied bool
		wantErr     string
	}{
		// This does not test all permutations of how HTTPS_PROXY and NO_PROXY work.
		// Some basic tests to understand how these settings work are included below.
		// See https://pkg.go.dev/golang.org/x/net/http/httpproxy for docs.
		{
			name:        "any host not included in NO_PROXY should use the proxy",
			host:        "www.pinniped.dev",
			wantProxied: true,
		},
		{
			name:        "a port different from the one specified in NO_PROXY should use the proxy, for the default HTTPS port",
			host:        "example1.pinniped.dev",
			wantProxied: true,
		},
		{
			name:        "a port different from the one specified in NO_PROXY should use the proxy, for an explicit port",
			host:        "example1.pinniped.dev:994",
			wantProxied: true,
		},
		{
			name:        "same port as the one specified in NO_PROXY should skip the proxy",
			host:        "example1.pinniped.dev:8443",
			wantProxied: false,
		},
		{
			name:        "any host included in NO_PROXY should skip the proxy, with default ports",
			host:        "example2.pinniped.dev",
			wantProxied: false,
		},
		{
			name:        "an IP specified in NO_PROXY should skip the proxy",
			host:        "1.2.3.4",
			wantProxied: false,
		},
		{
			name:        "an IP specified in NO_PROXY should skip the proxy, with matching explicit ports",
			host:        "1.2.3.5:3333",
			wantProxied: false,
		},
		{
			name:        "an IP specified in NO_PROXY should use the proxy when the ports don't match",
			host:        "1.2.3.5:1234",
			wantProxied: true,
		},
		{
			name:        "an IP included in a NO_PROXY CIDR should skip the proxy",
			host:        "4.4.4.4",
			wantProxied: false,
		},
		{
			name:        "an IP outside a NO_PROXY CIDR should use the proxy",
			host:        "4.4.4.16",
			wantProxied: true,
		},
		{
			name:        "as a special case in the Go documentation, localhost never uses the proxy, regardless of NO_PROXY settings",
			host:        "localhost",
			wantProxied: false,
		},
		{
			name:        "a bad hostname returns an error",
			host:        "bad hostname",
			wantProxied: false,
			wantErr:     `could not determine if requests will be proxied for host "bad hostname": parse "https://bad hostname": invalid character " " in host name`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			usingProxyForHost, err := subject.UsingProxyForHost(tt.host)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantProxied, usingProxyForHost)
		})
	}
}

func TestProxyDetectWithMock(t *testing.T) {
	proxyURL, err := url.Parse("http://myproxy.com")
	require.NoError(t, err)

	tests := []struct {
		name string

		proxyFromEnvironmentReturnsURL *url.URL
		proxyFromEnvironmentReturnsErr error

		host string

		wantProxied bool
		wantErr     string
	}{
		{
			name:                           "when using proxy for host",
			proxyFromEnvironmentReturnsURL: proxyURL,
			host:                           "example.com",
			wantProxied:                    true,
		},
		{
			name:                           "when not using proxy for host",
			proxyFromEnvironmentReturnsURL: nil,
			host:                           "example.com",
			wantProxied:                    false,
		},
		{
			name:                           "when ProxyFromEnvironment returns an error",
			proxyFromEnvironmentReturnsErr: errors.New("some error"),
			host:                           "example.com",
			wantProxied:                    false,
			wantErr:                        `could not determine if requests will be proxied for host "example.com": some error`,
		},
		{
			name:        "invalid host",
			host:        "invalid hostname",
			wantProxied: false,
			wantErr:     `could not determine if requests will be proxied for host "invalid hostname": parse "https://invalid hostname": invalid character " " in host name`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			subject := detector{proxyFromEnvironmentFunc: func(req *http.Request) (*url.URL, error) {
				return tt.proxyFromEnvironmentReturnsURL, tt.proxyFromEnvironmentReturnsErr
			}}

			proxied, err := subject.UsingProxyForHost(tt.host)

			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantProxied, proxied)
		})
	}
}
