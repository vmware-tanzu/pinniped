// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"errors"

	"go.pinniped.dev/internal/plog"
)

// Config contains knobs to setup an instance of the Pinniped Supervisor.
type Config struct {
	APIGroupSuffix *string           `json:"apiGroupSuffix,omitempty"`
	Labels         map[string]string `json:"labels"`
	NamesConfig    NamesConfigSpec   `json:"names"`
	// Deprecated: use log.level instead
	LogLevel          *plog.LogLevel     `json:"logLevel"`
	Log               plog.LogSpec       `json:"log"`
	Endpoints         *Endpoints         `json:"endpoints"`
	AllowExternalHTTP stringOrBoolAsBool `json:"insecureAcceptExternalUnencryptedHttpRequests"`
}

// NamesConfigSpec configures the names of some Kubernetes resources for the Supervisor.
type NamesConfigSpec struct {
	DefaultTLSCertificateSecret string `json:"defaultTLSCertificateSecret"`
	APIService                  string `json:"apiService"`
}

type Endpoints struct {
	HTTPS *Endpoint `json:"https,omitempty"`
	HTTP  *Endpoint `json:"http,omitempty"`
}

type Endpoint struct {
	Network string `json:"network"`
	Address string `json:"address"`
}

type stringOrBoolAsBool bool

func (sb *stringOrBoolAsBool) UnmarshalJSON(b []byte) error {
	switch string(b) {
	case "true", `"true"`:
		*sb = true
	case "false", `"false"`:
		*sb = false
	default:
		return errors.New("invalid value for boolean")
	}
	return nil
}
