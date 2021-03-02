// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonator

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

type Mode string

const (
	// Explicitly enable the impersonation proxy.
	ModeEnabled Mode = "enabled"

	// Explicitly disable the impersonation proxy.
	ModeDisabled Mode = "disabled"

	// Allow the proxy to decide if it should be enabled or disabled based upon the cluster in which it is running.
	ModeAuto Mode = "auto"
)

const (
	ConfigMapDataKey = "config.yaml"
)

type Config struct {
	// Enable or disable the impersonation proxy. Optional. Defaults to ModeAuto.
	Mode Mode `json:"mode,omitempty"`

	// Used when creating TLS certificates and for clients to discover the endpoint. Optional. When not specified, if the
	// impersonation proxy is started, then it will automatically create a LoadBalancer Service and use its ingress as the
	// endpoint.
	//
	// When specified, it may be a hostname or IP address, optionally with a port number, of the impersonation proxy
	// for clients to use from outside the cluster. E.g. myhost.mycompany.com:8443. Clients should assume that they should
	// connect via HTTPS to this service.
	Endpoint string `json:"endpoint,omitempty"`
}

func NewConfig() *Config {
	return &Config{Mode: ModeAuto}
}

func ConfigFromConfigMap(configMap *v1.ConfigMap) (*Config, error) {
	stringConfig, ok := configMap.Data[ConfigMapDataKey]
	if !ok {
		return nil, fmt.Errorf(`ConfigMap is missing expected key "%s"`, ConfigMapDataKey)
	}
	config := NewConfig()
	if err := yaml.Unmarshal([]byte(stringConfig), config); err != nil {
		return nil, fmt.Errorf("decode yaml: %w", err)
	}
	if config.Mode != ModeAuto && config.Mode != ModeEnabled && config.Mode != ModeDisabled {
		return nil, fmt.Errorf(`illegal value for "mode": %s`, config.Mode)
	}
	return config, nil
}
