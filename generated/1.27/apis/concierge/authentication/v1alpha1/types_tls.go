// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// CertificateAuthorityDataSourceKind enumerates the sources for CA Bundles.
//
// +kubebuilder:validation:Enum=Secret;ConfigMap
type CertificateAuthorityDataSourceKind string

const (
	// CertificateAuthorityDataSourceKindConfigMap uses a Kubernetes configmap to source CA Bundles.
	CertificateAuthorityDataSourceKindConfigMap = CertificateAuthorityDataSourceKind("ConfigMap")

	// CertificateAuthorityDataSourceKindSecret uses a Kubernetes secret to source CA Bundles.
	// Secrets used to source CA Bundles must be of type kubernetes.io/tls or Opaque.
	CertificateAuthorityDataSourceKindSecret = CertificateAuthorityDataSourceKind("Secret")
)

// CertificateAuthorityDataSourceSpec provides a source for CA bundle used for client-side TLS verification.
type CertificateAuthorityDataSourceSpec struct {
	// Kind configures whether the CA bundle is being sourced from a Kubernetes secret or a configmap.
	// Allowed values are "Secret" or "ConfigMap".
	// "ConfigMap" uses a Kubernetes configmap to source CA Bundles.
	// "Secret" uses Kubernetes secrets of type kubernetes.io/tls or Opaque to source CA Bundles.
	Kind CertificateAuthorityDataSourceKind `json:"kind"`
	// Name is the resource name of the secret or configmap from which to read the CA bundle.
	// The referenced secret or configmap must be created in the same namespace where Pinniped Concierge is installed.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Key is the key name within the secret or configmap from which to read the CA bundle.
	// The value found at this key in the secret or configmap must not be empty, and must be a valid PEM-encoded
	// certificate bundle.
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}

// TLSSpec provides TLS configuration on various authenticators.
type TLSSpec struct {
	// X.509 Certificate Authority (base64-encoded PEM bundle). If omitted, a default set of system roots will be trusted.
	// +optional
	CertificateAuthorityData string `json:"certificateAuthorityData,omitempty"`
	// Reference to a CA bundle in a secret or a configmap.
	// Any changes to the CA bundle in the secret or configmap will be dynamically reloaded.
	// +optional
	CertificateAuthorityDataSource *CertificateAuthorityDataSourceSpec `json:"certificateAuthorityDataSource,omitempty"`
}
