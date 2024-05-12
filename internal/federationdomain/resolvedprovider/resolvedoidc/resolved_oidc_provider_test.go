// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package resolvedoidc

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/testutil/oidctestutil"
)

func TestMapAdditionalClaimsFromUpstreamIDToken(t *testing.T) {
	tests := []struct {
		name                    string
		additionalClaimMappings map[string]string
		upstreamClaims          map[string]any
		wantClaims              map[string]any
	}{
		{
			name: "happy path",
			additionalClaimMappings: map[string]string{
				"email": "notification_email",
			},
			upstreamClaims: map[string]any{
				"notification_email": "test@example.com",
			},
			wantClaims: map[string]any{
				"email": "test@example.com",
			},
		},
		{
			name: "missing",
			additionalClaimMappings: map[string]string{
				"email": "email",
			},
			upstreamClaims: map[string]any{},
			wantClaims:     map[string]any{},
		},
		{
			name: "complex",
			additionalClaimMappings: map[string]string{
				"complex": "complex",
			},
			upstreamClaims: map[string]any{
				"complex": map[string]string{
					"subClaim": "subValue",
				},
			},
			wantClaims: map[string]any{
				"complex": map[string]string{
					"subClaim": "subValue",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			idp := oidctestutil.NewTestUpstreamOIDCIdentityProviderBuilder().
				WithAdditionalClaimMappings(test.additionalClaimMappings).
				Build()
			actual := mapAdditionalClaimsFromUpstreamIDToken(idp, test.upstreamClaims)

			require.Equal(t, test.wantClaims, actual)
		})
	}
}
