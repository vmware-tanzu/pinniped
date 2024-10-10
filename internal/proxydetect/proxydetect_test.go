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

func TestProxyDetect(t *testing.T) {
	t.Parallel()

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

			require.Equal(t, tt.wantProxied, proxied)
			if tt.wantErr != "" {
				require.Equal(t, tt.wantErr, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
