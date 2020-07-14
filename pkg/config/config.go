/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package config contains functionality to load/store api.Config's from/to
// some source.
package config

import (
	"fmt"
	"io/ioutil"

	"sigs.k8s.io/yaml"

	"github.com/suzerain-io/placeholder-name/pkg/config/api"
)

// FromPath loads an api.Config from a provided local file path.
//
// Note! The api.Config file should contain base64-encoded WebhookCABundle data.
// This function will decode that base64-encoded data to PEM bytes to be stored
// in the api.Config.
func FromPath(path string) (*api.Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var config api.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("decode yaml: %w", err)
	}

	return &config, nil
}
