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
		name             string
		issuer           string
		alternativeNames []string

		wantHostnames   []string
		wantAddress     string
		wantIP          net.IP
		wantIsIPAddress bool
	}{
		{
			name:          "works for localhost",
			issuer:        "https://localhost:443",
			wantHostnames: []string{"localhost"},
			wantAddress:   "localhost:443",
		},
		{
			name:          "works for localhost with path",
			issuer:        "https://localhost:443/some/path",
			wantHostnames: []string{"localhost"},
			wantAddress:   "localhost:443",
		},
		{
			name:          "works for domain",
			issuer:        "https://example.com:443",
			wantHostnames: []string{"example.com"},
			wantAddress:   "example.com:443",
		},
		{
			name:          "works for domain with path",
			issuer:        "https://example.com:443/some/path",
			wantHostnames: []string{"example.com"},
			wantAddress:   "example.com:443",
		},
		{
			name:            "works for IPv4",
			issuer:          "https://1.2.3.4:443",
			wantHostnames:   nil, // don't want DNS records in the cert when using IP address without SANs
			wantAddress:     "1.2.3.4:443",
			wantIP:          net.ParseIP("1.2.3.4"),
			wantIsIPAddress: true,
		},
		{
			name:            "works for IPv4 with path",
			issuer:          "https://1.2.3.4:443/some/path",
			wantHostnames:   nil, // don't want DNS records in the cert when using IP address without SANs
			wantAddress:     "1.2.3.4:443",
			wantIP:          net.ParseIP("1.2.3.4"),
			wantIsIPAddress: true,
		},
		{
			name:             "works with one SAN",
			issuer:           "https://example.com:443",
			alternativeNames: []string{"alt.example.com"},
			wantHostnames:    []string{"example.com", "alt.example.com"},
			wantAddress:      "example.com:443",
		},
		{
			name:             "works with two SANs",
			issuer:           "https://example.com:443",
			alternativeNames: []string{"alt1.example.com", "alt2.example.com"},
			wantHostnames:    []string{"example.com", "alt1.example.com", "alt2.example.com"},
			wantAddress:      "example.com:443",
		},
		{
			name:             "IP works with SANs",
			issuer:           "https://1.2.3.4:443",
			alternativeNames: []string{"alt1.example.com", "alt2.example.com"},
			wantHostnames:    []string{"alt1.example.com", "alt2.example.com"},
			wantAddress:      "1.2.3.4:443",
			wantIP:           net.ParseIP("1.2.3.4"),
			wantIsIPAddress:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			supervisorIssuer := NewSupervisorIssuer(t, test.issuer)
			for _, n := range test.alternativeNames {
				supervisorIssuer.AddAlternativeName(n)
			}
			require.Equal(t, test.issuer, supervisorIssuer.Issuer())
			require.Equal(t, test.wantAddress, supervisorIssuer.Address())
			if test.wantHostnames != nil {
				require.Equal(t, test.wantHostnames, supervisorIssuer.hostnamesForCert())
			} else {
				require.Nil(t, supervisorIssuer.hostnamesForCert())
			}
			if test.wantIP != nil {
				require.Equal(t, []net.IP{test.wantIP}, supervisorIssuer.ipsForCert())
			} else {
				require.Nil(t, supervisorIssuer.ipsForCert())
			}
			require.Equal(t, test.wantIsIPAddress, supervisorIssuer.IsIPAddress())
		})
	}
}
