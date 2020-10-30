// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// Configuration for configuring TLS on various authenticators.
type TLSSpec struct {
	// X.509 Certificate Authority (base64-encoded PEM bundle). If omitted, a default set of system roots will be trusted.
	// +optional
	CertificateAuthorityData string `json:"certificateAuthorityData,omitempty"`
}
