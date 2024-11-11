// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package concierge

import "go.pinniped.dev/internal/plog"

const (
	Enabled  = "enabled"
	Disabled = "disabled"
)

// Config contains knobs to set up an instance of the Pinniped Concierge.
type Config struct {
	DiscoveryInfo                DiscoveryInfoSpec `json:"discovery"`
	APIConfig                    APIConfigSpec     `json:"api"`
	APIGroupSuffix               *string           `json:"apiGroupSuffix,omitempty"`
	AggregatedAPIServerPort      *int64            `json:"aggregatedAPIServerPort"`
	ImpersonationProxyServerPort *int64            `json:"impersonationProxyServerPort"`
	NamesConfig                  NamesConfigSpec   `json:"names"`
	KubeCertAgentConfig          KubeCertAgentSpec `json:"kubeCertAgent"`
	Labels                       map[string]string `json:"labels"`
	Log                          plog.LogSpec      `json:"log"`
	TLS                          TLSSpec           `json:"tls"`
	Audit                        AuditSpec         `json:"audit"`
}

type AuditUsernamesAndGroups string

func (l AuditUsernamesAndGroups) Enabled() bool {
	return l == Enabled
}

type AuditSpec struct {
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

// DiscoveryInfoSpec contains configuration knobs specific to
// Pinniped's publishing of discovery information. These values can be
// viewed as overrides, i.e., if these are set, then Pinniped will
// publish these values in its discovery document instead of the ones it finds.
type DiscoveryInfoSpec struct {
	// URL contains the URL at which pinniped can be contacted.
	URL *string `json:"url,omitempty"`
}

// APIConfigSpec contains configuration knobs for the Pinniped API.
type APIConfigSpec struct {
	ServingCertificateConfig ServingCertificateConfigSpec `json:"servingCertificate"`
}

// NamesConfigSpec configures the names of some Kubernetes resources for the Concierge.
type NamesConfigSpec struct {
	ServingCertificateSecret          string `json:"servingCertificateSecret"`
	CredentialIssuer                  string `json:"credentialIssuer"`
	APIService                        string `json:"apiService"`
	ImpersonationLoadBalancerService  string `json:"impersonationLoadBalancerService"`
	ImpersonationClusterIPService     string `json:"impersonationClusterIPService"`
	ImpersonationTLSCertificateSecret string `json:"impersonationTLSCertificateSecret"`
	ImpersonationCACertificateSecret  string `json:"impersonationCACertificateSecret"`
	ImpersonationSignerSecret         string `json:"impersonationSignerSecret"`
	AgentServiceAccount               string `json:"agentServiceAccount"`
	ImpersonationProxyServiceAccount  string `json:"impersonationProxyServiceAccount"`
	ImpersonationProxyLegacySecret    string `json:"impersonationProxyLegacySecret"`
}

// ServingCertificateConfigSpec contains the configuration knobs for the API's
// serving certificate, i.e., the x509 certificate that it uses for the server
// certificate in inbound TLS connections.
type ServingCertificateConfigSpec struct {
	// DurationSeconds is the validity period, in seconds, of the API serving
	// certificate. By default, the serving certificate is issued for 31536000
	// seconds (1 year). This value is also used for the serving certificate's
	// CA certificate.
	DurationSeconds *int64 `json:"durationSeconds,omitempty"`

	// RenewBeforeSeconds is the period of time, in seconds, that Pinniped will
	// wait before rotating the serving certificate. This period of time starts
	// upon issuance of the serving certificate. This must be less than
	// DurationSeconds. By default, Pinniped begins rotation after 23328000
	// seconds (about 9 months).
	RenewBeforeSeconds *int64 `json:"renewBeforeSeconds,omitempty"`
}

type KubeCertAgentSpec struct {
	// NamePrefix is the prefix of the name of the kube-cert-agent pods. For example, if this field is
	// set to "some-prefix-", then the name of the pods will look like "some-prefix-blah". The default
	// for this value is "pinniped-kube-cert-agent-".
	NamePrefix *string `json:"namePrefix,omitempty"`

	// Image is the container image that will be used by the kube-cert-agent pod. The container image
	// should contain at least 2 binaries: /bin/sleep and cat (somewhere on the $PATH). The default
	// for this value is "debian:latest".
	Image *string `json:"image"`

	// ImagePullSecrets is a list of names of Kubernetes Secret objects that will be used as
	// ImagePullSecrets on the kube-cert-agent pods.
	ImagePullSecrets []string
}
