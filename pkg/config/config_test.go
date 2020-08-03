/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/suzerain-io/placeholder-name/pkg/config/api"
)

func TestFromPath(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantConfig *api.Config
	}{
		{
			name: "Happy",
			path: "testdata/happy.yaml",
			wantConfig: &api.Config{
				DiscoveryConfig: api.DiscoveryConfigSpec{
					URL: stringPtr("https://some.discovery/url"),
				},
				WebhookConfig: api.WebhookConfigSpec{
					URL:      "https://tuna.com/fish?marlin",
					CABundle: []byte("-----BEGIN CERTIFICATE-----..."),
				},
			},
		},
		{
			name: "NoDiscovery",
			path: "testdata/no-discovery.yaml",
			wantConfig: &api.Config{
				DiscoveryConfig: api.DiscoveryConfigSpec{
					URL: nil,
				},
				WebhookConfig: api.WebhookConfigSpec{
					URL:      "https://tuna.com/fish?marlin",
					CABundle: []byte("-----BEGIN CERTIFICATE-----..."),
				},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			config, err := FromPath(test.path)
			require.NoError(t, err)
			require.Equal(t, test.wantConfig, config)
		})
	}
}

func stringPtr(s string) *string {
	sPtr := new(string)
	*sPtr = s
	return sPtr
}
