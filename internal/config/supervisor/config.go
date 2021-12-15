// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package supervisor contains functionality to load/store Config's from/to
// some source.
package supervisor

import (
	"fmt"
	"io/ioutil"
	"strings"

	"k8s.io/utils/pointer"
	"sigs.k8s.io/yaml"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/plog"
)

const (
	NetworkDisabled = "disabled"
	NetworkUnix     = "unix"
	NetworkTCP      = "tcp"
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

	// support setting this to null or {} or empty in the YAML
	if config.Endpoints == nil {
		config.Endpoints = &Endpoints{}
	}

	maybeSetEndpointDefault(&config.Endpoints.HTTPS, Endpoint{
		Network: NetworkTCP,
		Address: ":8443",
	})
	maybeSetEndpointDefault(&config.Endpoints.HTTP, Endpoint{
		Network: NetworkTCP,
		Address: ":8080",
	})

	if err := validateEndpoint(*config.Endpoints.HTTPS); err != nil {
		return nil, fmt.Errorf("validate https endpoint: %w", err)
	}
	if err := validateEndpoint(*config.Endpoints.HTTP); err != nil {
		return nil, fmt.Errorf("validate http endpoint: %w", err)
	}
	if err := validateAtLeastOneEnabledEndpoint(*config.Endpoints.HTTPS, *config.Endpoints.HTTP); err != nil {
		return nil, fmt.Errorf("validate endpoints: %w", err)
	}

	return &config, nil
}

func maybeSetEndpointDefault(endpoint **Endpoint, defaultEndpoint Endpoint) {
	if *endpoint != nil {
		return
	}
	*endpoint = &defaultEndpoint
}

func maybeSetAPIGroupSuffixDefault(apiGroupSuffix **string) {
	if *apiGroupSuffix == nil {
		*apiGroupSuffix = pointer.StringPtr(groupsuffix.PinnipedDefaultSuffix)
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

func validateEndpoint(endpoint Endpoint) error {
	switch n := endpoint.Network; n {
	case NetworkTCP, NetworkUnix:
		if len(endpoint.Address) == 0 {
			return fmt.Errorf("address must be set with %q network", n)
		}
		return nil
	case NetworkDisabled:
		if len(endpoint.Address) != 0 {
			return fmt.Errorf("address set to %q when disabled, should be empty", endpoint.Address)
		}
		return nil
	default:
		return fmt.Errorf("unknown network %q", n)
	}
}

func validateAtLeastOneEnabledEndpoint(endpoints ...Endpoint) error {
	for _, endpoint := range endpoints {
		if endpoint.Network != NetworkDisabled {
			return nil
		}
	}
	return constable.Error("all endpoints are disabled")
}
