// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package supervisor contains functionality to load/store Config's from/to
// some source.
package supervisor

import (
	"fmt"
	"io/ioutil"

	"sigs.k8s.io/yaml"
)

// FromPath loads an Config from a provided local file path, inserts any
// defaults (from the Config documentation), and verifies that the config is
// valid (Config documentation).
func FromPath(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("decode yaml: %w", err)
	}

	if config.Labels == nil {
		config.Labels = make(map[string]string)
	}

	return &config, nil
}
