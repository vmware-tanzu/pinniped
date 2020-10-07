// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package issuerprovider

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProvider(t *testing.T) {
	tests := []struct {
		name      string
		issuer    *url.URL
		wantError string
	}{
		{
			name:   "nil issuer",
			issuer: nil,
		},
		{
			name:      "no scheme",
			issuer:    must(url.Parse("tuna.com")),
			wantError: `issuer must have "https" scheme`,
		},
		{
			name:      "bad scheme",
			issuer:    must(url.Parse("ftp://tuna.com")),
			wantError: `issuer must have "https" scheme`,
		},
		{
			name:      "fragment",
			issuer:    must(url.Parse("https://tuna.com/fish#some-frag")),
			wantError: `issuer must not have fragment`,
		},
		{
			name:      "query",
			issuer:    must(url.Parse("https://tuna.com?some=query")),
			wantError: `issuer must not have query`,
		},
		{
			name:      "username",
			issuer:    must(url.Parse("https://username@tuna.com")),
			wantError: `issuer must not have username or password`,
		},
		{
			name:      "password",
			issuer:    must(url.Parse("https://username:password@tuna.com")),
			wantError: `issuer must not have username or password`,
		},
		{
			name:   "without path",
			issuer: must(url.Parse("https://tuna.com")),
		},
		{
			name:   "with path",
			issuer: must(url.Parse("https://tuna.com/fish/marlin")),
		},
		{
			name:      "trailing slash in path",
			issuer:    must(url.Parse("https://tuna.com/")),
			wantError: `issuer must not have trailing slash in path`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			err := p.SetIssuer(tt.issuer)
			if tt.wantError != "" {
				require.EqualError(t, err, tt.wantError)
				require.Nil(t, p.GetIssuer())
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.issuer, p.GetIssuer())
			}
		})
	}
}

func must(u *url.URL, err error) *url.URL {
	if err != nil {
		panic(err)
	}
	return u
}
