/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package v1alpha1

// Configuration for configuring TLS on various identity providers.
type TLSSpec struct {
	// X.509 Certificate Authority (base64-encoded PEM bundle). If omitted, a default set of system roots will be trusted.
	// +optional
	CertificateAuthorityData string `json:"certificateAuthorityData,omitempty"`
}
