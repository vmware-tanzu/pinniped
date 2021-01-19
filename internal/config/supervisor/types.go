// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisor

import "go.pinniped.dev/internal/plog"

// Config contains knobs to setup an instance of the Pinniped Supervisor.
type Config struct {
	APIGroupSuffix *string           `json:"apiGroupSuffix,omitempty"`
	Labels         map[string]string `json:"labels"`
	NamesConfig    NamesConfigSpec   `json:"names"`
	LogLevel       plog.LogLevel     `json:"logLevel"`
}

// NamesConfigSpec configures the names of some Kubernetes resources for the Supervisor.
type NamesConfigSpec struct {
	DefaultTLSCertificateSecret string `json:"defaultTLSCertificateSecret"`
}
