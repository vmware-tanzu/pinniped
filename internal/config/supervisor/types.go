// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"strings"

	"go.pinniped.dev/internal/plog"
)

// Config contains knobs to setup an instance of the Pinniped Supervisor.
type Config struct {
	APIGroupSuffix *string           `json:"apiGroupSuffix,omitempty"`
	Labels         map[string]string `json:"labels"`
	NamesConfig    NamesConfigSpec   `json:"names"`
	LogLevel       plog.LogLevel     `json:"logLevel"`

	SupervisorHTTPListener  string `json:"supervisorHTTPListener"`
	SupervisorHTTPSListener string `json:"supervisorHTTPSListener"`
}

// NamesConfigSpec configures the names of some Kubernetes resources for the Supervisor.
type NamesConfigSpec struct {
	DefaultTLSCertificateSecret string `json:"defaultTLSCertificateSecret"`
}

func (c *Config) SupervisorHTTPListenerNetwork() string {
	if len(c.SupervisorHTTPListener) > 0 {
		return strings.SplitN(c.SupervisorHTTPListener, ",", 2)[0]
	}
	return ""
}

func (c *Config) SupervisorHTTPListenerAddress() string {
	if len(c.SupervisorHTTPListener) > 0 {
		return strings.SplitN(c.SupervisorHTTPListener, ",", 2)[1]
	}
	return ""
}

func (c *Config) SupervisorHTTPSListenerNetwork() string {
	return strings.SplitN(c.SupervisorHTTPSListener, ",", 2)[0]
}

func (c *Config) SupervisorHTTPSListenerAddress() string {
	return strings.SplitN(c.SupervisorHTTPSListener, ",", 2)[1]
}
