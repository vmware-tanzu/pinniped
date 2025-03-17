// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package supervisor contains functionality to load/store Config's from/to
// some source.
package supervisor

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	"go.pinniped.dev/internal/admissionpluginconfig"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/plog"
)

const (
	NetworkDisabled = "disabled"
	NetworkUnix     = "unix"
	NetworkTCP      = "tcp"

	// Use 10250 because it happens to be the same port on which the Kubelet listens, so some cluster types
	// are more permissive with servers that run on this port. For example, GKE private clusters do not
	// allow traffic from the control plane to most ports, but do allow traffic to port 10250. This allows
	// the Concierge to work without additional configuration on these types of clusters.
	aggregatedAPIServerPortDefault = 10250
)

// FromPath loads an Config from a provided local file path, inserts any
// defaults (from the Config documentation), and verifies that the config is
// valid (Config documentation).
func FromPath(ctx context.Context, path string, setAllowedCiphers ptls.SetAllowedCiphersFunc) (*Config, error) {
	data, err := os.ReadFile(path)
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

	if err := admissionpluginconfig.ValidateAdmissionPluginNames(config.AggregatedAPIServerDisableAdmissionPlugins); err != nil {
		return nil, fmt.Errorf("validate aggregatedAPIServerDisableAdmissionPlugins: %w", err)
	}

	maybeSetAggregatedAPIServerPortDefaults(&config.AggregatedAPIServerPort)

	if err := validateServerPort(config.AggregatedAPIServerPort); err != nil {
		return nil, fmt.Errorf("validate aggregatedAPIServerPort: %w", err)
	}

	if err := validateNames(&config.NamesConfig); err != nil {
		return nil, fmt.Errorf("validate names: %w", err)
	}

	if err := plog.ValidateAndSetLogLevelAndFormatGlobally(ctx, config.Log); err != nil {
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
		Network: NetworkDisabled,
	})

	if err := validateEndpoint(*config.Endpoints.HTTPS); err != nil {
		return nil, fmt.Errorf("validate https endpoint: %w", err)
	}
	if err := validateEndpoint(*config.Endpoints.HTTP); err != nil {
		return nil, fmt.Errorf("validate http endpoint: %w", err)
	}
	if err := validateAdditionalHTTPEndpointRequirements(*config.Endpoints.HTTP); err != nil {
		return nil, fmt.Errorf("validate http endpoint: %w", err)
	}
	if err := validateAtLeastOneEnabledEndpoint(*config.Endpoints.HTTPS, *config.Endpoints.HTTP); err != nil {
		return nil, fmt.Errorf("validate endpoints: %w", err)
	}
	if err := setAllowedCiphers(config.TLS.OneDotTwo.AllowedCiphers); err != nil {
		return nil, fmt.Errorf("validate tls: %w", err)
	}

	if err := validateAudit(&config.Audit); err != nil {
		return nil, fmt.Errorf("validate audit: %w", err)
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
		*apiGroupSuffix = ptr.To(groupsuffix.PinnipedDefaultSuffix)
	}
}

func validateAPIGroupSuffix(apiGroupSuffix string) error {
	return groupsuffix.Validate(apiGroupSuffix)
}

func maybeSetAggregatedAPIServerPortDefaults(port **int64) {
	if *port == nil {
		*port = ptr.To[int64](aggregatedAPIServerPortDefault)
	}
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

func validateAdditionalHTTPEndpointRequirements(endpoint Endpoint) error {
	if endpoint.Network == NetworkTCP && !addrIsOnlyOnLoopback(endpoint.Address) {
		return fmt.Errorf(
			"http listener address %q for %q network may only bind to loopback interfaces",
			endpoint.Address,
			endpoint.Network)
	}
	return nil
}

func validateAtLeastOneEnabledEndpoint(endpoints ...Endpoint) error {
	for _, endpoint := range endpoints {
		if endpoint.Network != NetworkDisabled {
			return nil
		}
	}
	return constable.Error("all endpoints are disabled")
}

// For tcp networks, the address can be in several formats: host:port, host:, and :port.
// See address description in https://pkg.go.dev/net#Listen and https://pkg.go.dev/net#Dial.
// The host may be a literal IP address, or a host name that can be resolved to IP addresses,
// or a literal unspecified IP address (as in "0.0.0.0:80" or "[::]:80"), or empty.
// If the host is a literal IPv6 address it must be enclosed in square brackets, as in "[2001:db8::1]:80" or
// "[fe80::1%zone]:80". The zone specifies the scope of the literal IPv6 address as defined in RFC 4007.
// The port may be a literal port number or a service name, the value 0, or empty.
// Returns true if a net.Listen listener at this address would only listen on loopback interfaces.
// Returns false if the listener would listen on any non-loopback interfaces, or when called with illegal input.
func addrIsOnlyOnLoopback(addr string) bool {
	// First try parsing as a `host:port`. net.SplitHostPort allows empty host and empty port.
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Illegal input.
		return false
	}
	if host == "" {
		// Input was :port. This would bind to all interfaces, so it is not only on loopback.
		return false
	}
	if host == "localhost" || host == "ip6-localhost" || host == "ip6-loopback" {
		// These hostnames are documented as the loopback hostnames seen inside the pod's containers in
		// https://kubernetes.io/docs/tasks/network/customize-hosts-file-for-pods/#default-hosts-file-content
		return true
	}
	// The host could be a hostname, an IPv4 address, or an IPv6 address.
	ip := net.ParseIP(host)
	if ip == nil {
		// The address was not an IP. It must have been some hostname other than "localhost".
		return false
	}
	return ip.IsLoopback()
}

func validateServerPort(port *int64) error {
	// It cannot be below 1024 because the container is not running as root.
	if *port < 1024 || *port > 65535 {
		return constable.Error("must be within range 1024 to 65535")
	}
	return nil
}

func validateAudit(auditConfig *AuditSpec) error {
	const errFmt = "invalid %s format, valid choices are 'enabled', 'disabled', or empty string (equivalent to 'disabled')"

	switch auditConfig.LogUsernamesAndGroups {
	case Enabled, Disabled, "":
		// no-op
	default:
		return fmt.Errorf(errFmt, "logUsernamesAndGroups")
	}

	switch auditConfig.LogInternalPaths {
	case Enabled, Disabled, "":
		// no-op
	default:
		return fmt.Errorf(errFmt, "logInternalPaths")
	}

	return nil
}
