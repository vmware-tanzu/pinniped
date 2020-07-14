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
	expect := require.New(t)

	config, err := FromPath("testdata/happy.yaml")
	expect.NoError(err)
	expect.Equal(config, &api.Config{
		WebhookConfig: api.WebhookConfigSpec{
			URL:      "https://tuna.com/fish?marlin",
			CABundle: []byte("-----BEGIN CERTIFICATE-----..."),
		},
	})
}
