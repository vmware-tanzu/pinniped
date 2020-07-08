/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package config contains functionality to load/store api.Config's from/to
// some source.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"

	"github.com/suzerain-io/placeholder-name/cmd/placeholder-name/app/config/api"
)

// FromPath loads an api.Config from a provided local file path.
func FromPath(path string) (*api.Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config api.Config
	if err := yaml.NewDecoder(file).Decode(&config); err != nil {
		return nil, fmt.Errorf("decode yaml: %w", err)
	}

	return &config, nil
}
