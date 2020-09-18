// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/pkg/config/api"
)

func TestFromPath(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantConfig *api.Config
		wantError  string
	}{
		{
			name: "Happy",
			path: "testdata/happy.yaml",
			wantConfig: &api.Config{
				DiscoveryInfo: api.DiscoveryInfoSpec{
					URL: stringPtr("https://some.discovery/url"),
				},
				APIConfig: api.APIConfigSpec{
					ServingCertificateConfig: api.ServingCertificateConfigSpec{
						DurationSeconds:    int64Ptr(3600),
						RenewBeforeSeconds: int64Ptr(2400),
					},
				},
			},
		},
		{
			name: "Default",
			path: "testdata/default.yaml",
			wantConfig: &api.Config{
				DiscoveryInfo: api.DiscoveryInfoSpec{
					URL: nil,
				},
				APIConfig: api.APIConfigSpec{
					ServingCertificateConfig: api.ServingCertificateConfigSpec{
						DurationSeconds:    int64Ptr(60 * 60 * 24 * 365),    // about a year
						RenewBeforeSeconds: int64Ptr(60 * 60 * 24 * 30 * 9), // about 9 months
					},
				},
			},
		},
		{
			name:      "InvalidDurationRenewBefore",
			path:      "testdata/invalid-duration-renew-before.yaml",
			wantError: "validate api: durationSeconds cannot be smaller than renewBeforeSeconds",
		},
		{
			name:      "NegativeRenewBefore",
			path:      "testdata/negative-renew-before.yaml",
			wantError: "validate api: renewBefore must be positive",
		},
		{
			name:      "ZeroRenewBefore",
			path:      "testdata/zero-renew-before.yaml",
			wantError: "validate api: renewBefore must be positive",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			config, err := FromPath(test.path)
			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.wantConfig, config)
			}
		})
	}
}

func stringPtr(s string) *string {
	return &s
}
