// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package config contains functionality to load/store api.Config's from/to
// some source.
package config

import (
	"fmt"
	"io/ioutil"
	"strings"

	"sigs.k8s.io/yaml"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/pkg/config/api"
)

const (
	aboutAYear   = 60 * 60 * 24 * 365
	about9Months = 60 * 60 * 24 * 30 * 9
)

// FromPath loads an api.Config from a provided local file path, inserts any
// defaults (from the api.Config documentation), and verifies that the config is
// valid (per the api.Config documentation).
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

	maybeSetAPIDefaults(&config.APIConfig)

	if err := validateAPI(&config.APIConfig); err != nil {
		return nil, fmt.Errorf("validate api: %w", err)
	}

	if err := validateNames(&config.NamesConfig); err != nil {
		return nil, fmt.Errorf("validate names: %w", err)
	}

	return &config, nil
}

func maybeSetAPIDefaults(apiConfig *api.APIConfigSpec) {
	if apiConfig.ServingCertificateConfig.DurationSeconds == nil {
		apiConfig.ServingCertificateConfig.DurationSeconds = int64Ptr(aboutAYear)
	}

	if apiConfig.ServingCertificateConfig.RenewBeforeSeconds == nil {
		apiConfig.ServingCertificateConfig.RenewBeforeSeconds = int64Ptr(about9Months)
	}
}

func validateNames(names *api.NamesConfigSpec) error {
	missingNames := []string{}
	if names == nil {
		missingNames = append(missingNames, "servingCertificateSecret", "credentialIssuerConfig", "apiService")
	} else {
		if names.ServingCertificateSecret == "" {
			missingNames = append(missingNames, "servingCertificateSecret")
		}
		if names.CredentialIssuerConfig == "" {
			missingNames = append(missingNames, "credentialIssuerConfig")
		}
		if names.APIService == "" {
			missingNames = append(missingNames, "apiService")
		}
	}
	if len(missingNames) > 0 {
		return constable.Error("missing required names: " + strings.Join(missingNames, ", "))
	}
	return nil
}

func validateAPI(apiConfig *api.APIConfigSpec) error {
	if *apiConfig.ServingCertificateConfig.DurationSeconds < *apiConfig.ServingCertificateConfig.RenewBeforeSeconds {
		return constable.Error("durationSeconds cannot be smaller than renewBeforeSeconds")
	}

	if *apiConfig.ServingCertificateConfig.RenewBeforeSeconds <= 0 {
		return constable.Error("renewBefore must be positive")
	}

	return nil
}

func int64Ptr(i int64) *int64 {
	return &i
}
