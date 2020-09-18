// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package api

// Config contains knobs to setup an instance of Pinniped.
type Config struct {
	DiscoveryInfo DiscoveryInfoSpec `json:"discovery"`
	APIConfig     APIConfigSpec     `json:"api"`
	NamesConfig   NamesConfigSpec   `json:"names"`
}

// DiscoveryInfoSpec contains configuration knobs specific to
// pinniped's publishing of discovery information. These values can be
// viewed as overrides, i.e., if these are set, then pinniped will
// publish these values in its discovery document instead of the ones it finds.
type DiscoveryInfoSpec struct {
	// URL contains the URL at which pinniped can be contacted.
	URL *string `json:"url,omitempty"`
}

// APIConfigSpec contains configuration knobs for the Pinniped API.
//nolint: golint
type APIConfigSpec struct {
	ServingCertificateConfig ServingCertificateConfigSpec `json:"servingCertificate"`
}

// NamesConfigSpec configures the names of some Kubernetes resources for Pinniped.
type NamesConfigSpec struct {
	ServingCertificateSecret string `json:"servingCertificateSecret"`
	CredentialIssuerConfig   string `json:"credentialIssuerConfig"`
	APIService               string `json:"apiService"`
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
