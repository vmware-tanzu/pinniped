// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/idtransform"
)

func TestFederationDomainIssuerValidations(t *testing.T) {
	tests := []struct {
		name      string
		issuer    string
		wantError string
	}{
		{
			name:      "must have an issuer",
			issuer:    "",
			wantError: "federation domain must have an issuer",
		},
		{
			name:      "returns url.Parse errors",
			issuer:    "https://example.com" + string(byte(0x7f)),
			wantError: "could not parse issuer as URL: parse \"https://example.com\\x7f\": net/url: invalid control character in URL",
		},
		{
			name:      "no hostname",
			issuer:    "https://",
			wantError: `issuer must have a hostname`,
		},
		{
			name:      "no scheme",
			issuer:    "tuna.com",
			wantError: `issuer must have "https" scheme`,
		},
		{
			name:      "bad scheme",
			issuer:    "ftp://tuna.com",
			wantError: `issuer must have "https" scheme`,
		},
		{
			name:      "fragment",
			issuer:    "https://tuna.com/fish#some-frag",
			wantError: `issuer must not have fragment`,
		},
		{
			name:      "query",
			issuer:    "https://tuna.com?some=query",
			wantError: `issuer must not have query`,
		},
		{
			name:      "username",
			issuer:    "https://username@tuna.com",
			wantError: `issuer must not have username or password`,
		},
		{
			name:      "password",
			issuer:    "https://username:password@tuna.com",
			wantError: `issuer must not have username or password`,
		},
		{
			name:   "without path",
			issuer: "https://tuna.com",
		},
		{
			name:   "with path",
			issuer: "https://tuna.com/fish/marlin",
		},
		{
			name:      "with http scheme",
			issuer:    "http://tuna.com",
			wantError: `issuer must have "https" scheme`,
		},
		{
			name:      "trailing slash in path",
			issuer:    "https://tuna.com/",
			wantError: `issuer must not have trailing slash in path`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFederationDomainIssuer(tt.issuer, []*FederationDomainIdentityProvider{})
			if tt.wantError != "" {
				require.EqualError(t, err, tt.wantError)
			} else {
				require.NoError(t, err)
			}

			// This alternate constructor should perform all the same validations on the issuer string.
			_, err = NewFederationDomainIssuerWithDefaultIDP(tt.issuer, &FederationDomainIdentityProvider{
				DisplayName: "foobar",
				UID:         "foo-123",
				Transforms:  idtransform.NewTransformationPipeline(),
			})
			if tt.wantError != "" {
				require.EqualError(t, err, tt.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
