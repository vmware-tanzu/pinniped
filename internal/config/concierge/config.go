// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package concierge contains functionality to load/store Config's from/to
// some source.
package concierge

import (
	"fmt"
	"io/ioutil"
	"strings"

	"sigs.k8s.io/yaml"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/plog"
)

const (
	aboutAYear   = 60 * 60 * 24 * 365
	about9Months = 60 * 60 * 24 * 30 * 9
)

// FromPath loads an Config from a provided local file path, inserts any
// defaults (from the Config documentation), and verifies that the config is
// valid (per the Config documentation).
//
// Note! The Config file should contain base64-encoded WebhookCABundle data.
// This function will decode that base64-encoded data to PEM bytes to be stored
// in the Config.
func FromPath(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("decode yaml: %w", err)
	}

	maybeSetAPIDefaults(&config.APIConfig)
	maybeSetAPIGroupSuffixDefault(&config.APIGroupSuffix)
	maybeSetKubeCertAgentDefaults(&config.KubeCertAgentConfig)

	if err := validateAPI(&config.APIConfig); err != nil {
		return nil, fmt.Errorf("validate api: %w", err)
	}

	if err := validateAPIGroupSuffix(*config.APIGroupSuffix); err != nil {
		return nil, fmt.Errorf("validate apiGroupSuffix: %w", err)
	}

	if err := validateNames(&config.NamesConfig); err != nil {
		return nil, fmt.Errorf("validate names: %w", err)
	}

	if err := plog.ValidateAndSetLogLevelGlobally(config.LogLevel); err != nil {
		return nil, fmt.Errorf("validate log level: %w", err)
	}

	if config.Labels == nil {
		config.Labels = make(map[string]string)
	}

	return &config, nil
}

func maybeSetAPIDefaults(apiConfig *APIConfigSpec) {
	if apiConfig.ServingCertificateConfig.DurationSeconds == nil {
		apiConfig.ServingCertificateConfig.DurationSeconds = int64Ptr(aboutAYear)
	}

	if apiConfig.ServingCertificateConfig.RenewBeforeSeconds == nil {
		apiConfig.ServingCertificateConfig.RenewBeforeSeconds = int64Ptr(about9Months)
	}
}

func maybeSetAPIGroupSuffixDefault(apiGroupSuffix **string) {
	if *apiGroupSuffix == nil {
		*apiGroupSuffix = stringPtr("pinniped.dev")
	}
}

func maybeSetKubeCertAgentDefaults(cfg *KubeCertAgentSpec) {
	if cfg.NamePrefix == nil {
		cfg.NamePrefix = stringPtr("pinniped-kube-cert-agent-")
	}

	if cfg.Image == nil {
		cfg.Image = stringPtr("debian:latest")
	}
}

func validateNames(names *NamesConfigSpec) error {
	missingNames := []string{}
	if names == nil {
		missingNames = append(missingNames, "servingCertificateSecret", "credentialIssuer", "apiService")
	} else {
		if names.ServingCertificateSecret == "" {
			missingNames = append(missingNames, "servingCertificateSecret")
		}
		if names.CredentialIssuer == "" {
			missingNames = append(missingNames, "credentialIssuer")
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

func validateAPI(apiConfig *APIConfigSpec) error {
	if *apiConfig.ServingCertificateConfig.DurationSeconds < *apiConfig.ServingCertificateConfig.RenewBeforeSeconds {
		return constable.Error("durationSeconds cannot be smaller than renewBeforeSeconds")
	}

	if *apiConfig.ServingCertificateConfig.RenewBeforeSeconds <= 0 {
		return constable.Error("renewBefore must be positive")
	}

	return nil
}

func validateAPIGroupSuffix(apiGroupSuffix string) error {
	return groupsuffix.Validate(apiGroupSuffix)
}

func int64Ptr(i int64) *int64 {
	return &i
}

func stringPtr(s string) *string {
	return &s
}
