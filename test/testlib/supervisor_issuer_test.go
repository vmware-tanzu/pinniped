// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testlib

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSupervisorIssuer(t *testing.T) {
	tests := []struct {
		name            string
		issuer          string
		wantHostname    string
		wantAddress     string
		wantIP          net.IP
		wantIsIPAddress bool
	}{
		{
			name:         "works for localhost",
			issuer:       "https://localhost:443",
			wantHostname: "localhost",
			wantAddress:  "localhost:443",
		},
		{
			name:         "works for localhost with path",
			issuer:       "https://localhost:443/some/path",
			wantHostname: "localhost",
			wantAddress:  "localhost:443",
		},
		{
			name:         "works for domain",
			issuer:       "https://example.com:443",
			wantHostname: "example.com",
			wantAddress:  "example.com:443",
		},
		{
			name:         "works for domain with path",
			issuer:       "https://example.com:443/some/path",
			wantHostname: "example.com",
			wantAddress:  "example.com:443",
		},
		{
			name:            "works for IPv4",
			issuer:          "https://1.2.3.4:443",
			wantHostname:    "", // don't want DNS records in the cert when using IP address
			wantAddress:     "1.2.3.4:443",
			wantIP:          net.ParseIP("1.2.3.4"),
			wantIsIPAddress: true,
		},
		{
			name:            "works for IPv4 with path",
			issuer:          "https://1.2.3.4:443/some/path",
			wantHostname:    "", // don't want DNS records in the cert when using IP address
			wantAddress:     "1.2.3.4:443",
			wantIP:          net.ParseIP("1.2.3.4"),
			wantIsIPAddress: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			supervisorIssuer := NewSupervisorIssuer(t, test.issuer)
			require.Equal(t, test.issuer, supervisorIssuer.Issuer())
			require.Equal(t, test.wantAddress, supervisorIssuer.Address())
			if test.wantHostname != "" {
				require.Equal(t, []string{test.wantHostname}, supervisorIssuer.Hostnames())
			} else {
				require.Nil(t, supervisorIssuer.Hostnames())
			}
			if test.wantIP != nil {
				require.Equal(t, []net.IP{test.wantIP}, supervisorIssuer.IPs())
			} else {
				require.Nil(t, supervisorIssuer.IPs())
			}
			require.Equal(t, test.wantIsIPAddress, supervisorIssuer.IsIPAddress())
		})
	}
}
