// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1


// CABundleSource provides a source for CA bundle used for client-side TLS verification.
type CABundleSource struct {
	// Whether the CA bundle is being sourced from a kubernetes secret or a configmap.
	// Secrets must be of type kubernetes.io/tls or Opaque.
	// For configmaps, the value associated with the key is not expected to be base64 encoded.
	// +kubebuilder:validation:Enum=Secret;ConfigMap
	Kind string `json:"kind"`
	// Name of the secret or configmap from which to read the CA bundle.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Key within the secret or configmap from which to read the CA bundle.
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}

// TLSSpec provides TLS configuration for identity provider integration.
type TLSSpec struct {
	// X.509 Certificate Authority (base64-encoded PEM bundle). If omitted, a default set of system roots will be trusted.
	// +optional
	CertificateAuthorityData string `json:"certificateAuthorityData,omitempty"`
	// Reference to a CA bundle in a secret or a configmap.
	// +optional
	CertificateAuthorityDataSource *CABundleSource `json:"certificateAuthorityDataSource,omitempty"`
}
