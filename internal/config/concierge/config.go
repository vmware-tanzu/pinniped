// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package concierge contains functionality to load/store Config's from/to
// some source.
package concierge

import (
	"context"
	"fmt"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	"go.pinniped.dev/internal/admissionpluginconfig"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/plog"
)

const (
	aboutAYear   = 60 * 60 * 24 * 365
	about9Months = 60 * 60 * 24 * 30 * 9

	// Use 10250 because it happens to be the same port on which the Kubelet listens, so some cluster types
	// are more permissive with servers that run on this port. For example, GKE private clusters do not
	// allow traffic from the control plane to most ports, but do allow traffic to port 10250. This allows
	// the Concierge to work without additional configuration on these types of clusters.
	aggregatedAPIServerPortDefault = 10250

	// Use port 8444 because that is the port that was selected for the first released version of the
	// impersonation proxy, and has been the value since. It was originally selected because the
	// aggregated API server used to run on 8443 (has since changed), so 8444 was the next available port.
	impersonationProxyPortDefault = 8444
)

// FromPath loads a Config from a provided local file path, inserts any
// defaults (from the Config documentation), and verifies that the config is
// valid (per the Config documentation).
//
// Note! The Config file should contain base64-encoded WebhookCABundle data.
// This function will decode that base64-encoded data to PEM bytes to be stored
// in the Config.
func FromPath(ctx context.Context, path string, setAllowedCiphers ptls.SetAllowedCiphersFunc) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("decode yaml: %w", err)
	}

	maybeSetAPIDefaults(&config.APIConfig)
	maybeSetAggregatedAPIServerPortDefaults(&config.AggregatedAPIServerPort)
	maybeSetImpersonationProxyServerPortDefaults(&config.ImpersonationProxyServerPort)
	maybeSetAPIGroupSuffixDefault(&config.APIGroupSuffix)
	maybeSetKubeCertAgentDefaults(&config.KubeCertAgentConfig)

	if err := validateAPI(&config.APIConfig); err != nil {
		return nil, fmt.Errorf("validate api: %w", err)
	}

	if err := validateAPIGroupSuffix(*config.APIGroupSuffix); err != nil {
		return nil, fmt.Errorf("validate apiGroupSuffix: %w", err)
	}

	if err := admissionpluginconfig.ValidateAdmissionPluginNames(config.AggregatedAPIServerDisableAdmissionPlugins); err != nil {
		return nil, fmt.Errorf("validate aggregatedAPIServerDisableAdmissionPlugins: %w", err)
	}

	if err := validateServerPort(config.AggregatedAPIServerPort); err != nil {
		return nil, fmt.Errorf("validate aggregatedAPIServerPort: %w", err)
	}

	if err := validateServerPort(config.ImpersonationProxyServerPort); err != nil {
		return nil, fmt.Errorf("validate impersonationProxyServerPort: %w", err)
	}

	if err := validateNames(&config.NamesConfig); err != nil {
		return nil, fmt.Errorf("validate names: %w", err)
	}

	if err := validateKubeCertAgent(&config.KubeCertAgentConfig); err != nil {
		return nil, fmt.Errorf("validate kubeCertAgent: %w", err)
	}

	if err := plog.ValidateAndSetLogLevelAndFormatGlobally(ctx, config.Log); err != nil {
		return nil, fmt.Errorf("validate log level: %w", err)
	}

	if err := setAllowedCiphers(config.TLS.OneDotTwo.AllowedCiphers); err != nil {
		return nil, fmt.Errorf("validate tls: %w", err)
	}

	if err := validateAudit(&config.Audit); err != nil {
		return nil, fmt.Errorf("validate audit: %w", err)
	}

	if config.Labels == nil {
		config.Labels = make(map[string]string)
	}

	return &config, nil
}

func maybeSetAPIDefaults(apiConfig *APIConfigSpec) {
	if apiConfig.ServingCertificateConfig.DurationSeconds == nil {
		apiConfig.ServingCertificateConfig.DurationSeconds = ptr.To[int64](aboutAYear)
	}

	if apiConfig.ServingCertificateConfig.RenewBeforeSeconds == nil {
		apiConfig.ServingCertificateConfig.RenewBeforeSeconds = ptr.To[int64](about9Months)
	}
}

func maybeSetAPIGroupSuffixDefault(apiGroupSuffix **string) {
	if *apiGroupSuffix == nil {
		*apiGroupSuffix = ptr.To(groupsuffix.PinnipedDefaultSuffix)
	}
}

func maybeSetAggregatedAPIServerPortDefaults(port **int64) {
	if *port == nil {
		*port = ptr.To[int64](aggregatedAPIServerPortDefault)
	}
}

func maybeSetImpersonationProxyServerPortDefaults(port **int64) {
	if *port == nil {
		*port = ptr.To[int64](impersonationProxyPortDefault)
	}
}

func maybeSetKubeCertAgentDefaults(cfg *KubeCertAgentSpec) {
	if cfg.NamePrefix == nil {
		cfg.NamePrefix = ptr.To("pinniped-kube-cert-agent-")
	}

	if cfg.Image == nil {
		cfg.Image = ptr.To("debian:latest")
	}
}

func validateNames(names *NamesConfigSpec) error {
	missingNames := []string{}
	if names == nil {
		names = &NamesConfigSpec{}
	}
	if names.ServingCertificateSecret == "" {
		missingNames = append(missingNames, "servingCertificateSecret")
	}
	if names.CredentialIssuer == "" {
		missingNames = append(missingNames, "credentialIssuer")
	}
	if names.APIService == "" {
		missingNames = append(missingNames, "apiService")
	}
	if names.ImpersonationLoadBalancerService == "" {
		missingNames = append(missingNames, "impersonationLoadBalancerService")
	}
	if names.ImpersonationClusterIPService == "" {
		missingNames = append(missingNames, "impersonationClusterIPService")
	}
	if names.ImpersonationTLSCertificateSecret == "" {
		missingNames = append(missingNames, "impersonationTLSCertificateSecret")
	}
	if names.ImpersonationCACertificateSecret == "" {
		missingNames = append(missingNames, "impersonationCACertificateSecret")
	}
	if names.ImpersonationSignerSecret == "" {
		missingNames = append(missingNames, "impersonationSignerSecret")
	}
	if names.AgentServiceAccount == "" {
		missingNames = append(missingNames, "agentServiceAccount")
	}
	if names.ImpersonationProxyServiceAccount == "" {
		missingNames = append(missingNames, "impersonationProxyServiceAccount")
	}
	if names.ImpersonationProxyLegacySecret == "" {
		missingNames = append(missingNames, "impersonationProxyLegacySecret")
	}
	if len(missingNames) > 0 {
		return constable.Error("missing required names: " + strings.Join(missingNames, ", "))
	}
	return nil
}

func validateKubeCertAgent(agentConfig *KubeCertAgentSpec) error {
	if len(agentConfig.PriorityClassName) == 0 {
		// Optional, so empty is valid.
		return nil
	}

	// See https://kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/#priorityclass
	// for PriorityClassName rules.
	errStrings := validation.IsDNS1123Subdomain(agentConfig.PriorityClassName)
	if len(errStrings) > 0 {
		// Always good enough to return the first error. IsDNS1123Subdomain only has two errors that it can return.
		return fmt.Errorf("invalid priorityClassName: %s", errStrings[0])
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

func validateServerPort(port *int64) error {
	// It cannot be below 1024 because the container is not running as root.
	if *port < 1024 || *port > 65535 {
		return constable.Error("must be within range 1024 to 65535")
	}
	return nil
}

func validateAudit(auditConfig *AuditSpec) error {
	v := auditConfig.LogUsernamesAndGroups
	if v != "" && v != Enabled && v != Disabled {
		return constable.Error("invalid logUsernamesAndGroups format, valid choices are 'enabled', 'disabled', or empty string (equivalent to 'disabled')")
	}
	return nil
}
