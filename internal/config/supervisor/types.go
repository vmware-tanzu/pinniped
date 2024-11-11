// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"go.pinniped.dev/internal/plog"
)

const (
	Enabled  = "enabled"
	Disabled = "disabled"
)

// Config contains knobs to set up an instance of the Pinniped Supervisor.
type Config struct {
	APIGroupSuffix          *string           `json:"apiGroupSuffix,omitempty"`
	Labels                  map[string]string `json:"labels"`
	NamesConfig             NamesConfigSpec   `json:"names"`
	Log                     plog.LogSpec      `json:"log"`
	Endpoints               *Endpoints        `json:"endpoints"`
	AggregatedAPIServerPort *int64            `json:"aggregatedAPIServerPort"`
	TLS                     TLSSpec           `json:"tls"`
	Audit                   AuditSpec         `json:"audit"`
}

type AuditInternalPaths string
type AuditUsernamesAndGroups string

func (l AuditInternalPaths) Enabled() bool {
	return l == Enabled
}
func (l AuditUsernamesAndGroups) Enabled() bool {
	return l == Enabled
}

type AuditSpec struct {
	LogInternalPaths      AuditInternalPaths      `json:"logInternalPaths"`
	LogUsernamesAndGroups AuditUsernamesAndGroups `json:"logUsernamesAndGroups"`
}

type TLSSpec struct {
	OneDotTwo TLSProtocolSpec `json:"onedottwo"`
}

type TLSProtocolSpec struct {
	// AllowedCiphers will permit Pinniped to use only the listed ciphers.
	// This affects Pinniped both when it acts as a client and as a server.
	// If empty, Pinniped will use a built-in list of ciphers.
	AllowedCiphers []string `json:"allowedCiphers"`
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
