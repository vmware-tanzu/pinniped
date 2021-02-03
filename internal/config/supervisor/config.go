// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package supervisor contains functionality to load/store Config's from/to
// some source.
package supervisor

import (
	"fmt"
	"io/ioutil"
	"strings"

	"sigs.k8s.io/yaml"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/plog"
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

	maybeSetAPIGroupSuffixDefault(&config.APIGroupSuffix)

	if err := validateAPIGroupSuffix(*config.APIGroupSuffix); err != nil {
		return nil, fmt.Errorf("validate apiGroupSuffix: %w", err)
	}

	if err := validateNames(&config.NamesConfig); err != nil {
		return nil, fmt.Errorf("validate names: %w", err)
	}

	if err := plog.ValidateAndSetLogLevelGlobally(config.LogLevel); err != nil {
		return nil, fmt.Errorf("validate log level: %w", err)
	}

	return &config, nil
}

func maybeSetAPIGroupSuffixDefault(apiGroupSuffix **string) {
	if *apiGroupSuffix == nil {
		*apiGroupSuffix = stringPtr("pinniped.dev")
	}
}

func validateAPIGroupSuffix(apiGroupSuffix string) error {
	return groupsuffix.Validate(apiGroupSuffix)
}

func validateNames(names *NamesConfigSpec) error {
	missingNames := []string{}
	if names.DefaultTLSCertificateSecret == "" {
		missingNames = append(missingNames, "defaultTLSCertificateSecret")
	}
	if len(missingNames) > 0 {
		return constable.Error("missing required names: " + strings.Join(missingNames, ", "))
	}
	return nil
}

func stringPtr(s string) *string {
	return &s
}
