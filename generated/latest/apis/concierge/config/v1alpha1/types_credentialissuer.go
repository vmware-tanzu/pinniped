// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +kubebuilder:validation:Enum=KubeClusterSigningCertificate
type StrategyType string

// +kubebuilder:validation:Enum=TokenCredentialRequestAPI
type FrontendType string

// +kubebuilder:validation:Enum=Success;Error
type StrategyStatus string

// +kubebuilder:validation:Enum=FetchedKey;CouldNotFetchKey
type StrategyReason string

const (
	KubeClusterSigningCertificateStrategyType = StrategyType("KubeClusterSigningCertificate")

	TokenCredentialRequestAPIFrontendType = FrontendType("TokenCredentialRequestAPI")

	SuccessStrategyStatus = StrategyStatus("Success")
	ErrorStrategyStatus   = StrategyStatus("Error")

	CouldNotFetchKeyStrategyReason       = StrategyReason("CouldNotFetchKey")
	CouldNotGetClusterInfoStrategyReason = StrategyReason("CouldNotGetClusterInfo")
	FetchedKeyStrategyReason             = StrategyReason("FetchedKey")
)

// Status of a credential issuer.
type CredentialIssuerStatus struct {
	// List of integration strategies that were attempted by Pinniped.
	Strategies []CredentialIssuerStrategy `json:"strategies"`

	// Information needed to form a valid Pinniped-based kubeconfig using this credential issuer.
	// This field is deprecated and will be removed in a future version.
	// +optional
	KubeConfigInfo *CredentialIssuerKubeConfigInfo `json:"kubeConfigInfo,omitempty"`
}

// Information needed to form a valid Pinniped-based kubeconfig using this credential issuer.
type CredentialIssuerKubeConfigInfo struct {
	// The K8s API server URL.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://|^http://`
	Server string `json:"server"`

	// The K8s API server CA bundle.
	// +kubebuilder:validation:MinLength=1
	CertificateAuthorityData string `json:"certificateAuthorityData"`
}

// Status of an integration strategy that was attempted by Pinniped.
type CredentialIssuerStrategy struct {
	// Type of integration attempted.
	Type StrategyType `json:"type"`

	// Status of the attempted integration strategy.
	Status StrategyStatus `json:"status"`

	// Reason for the current status.
	Reason StrategyReason `json:"reason"`

	// Human-readable description of the current status.
	// +kubebuilder:validation:MinLength=1
	Message string `json:"message"`

	// When the status was last checked.
	LastUpdateTime metav1.Time `json:"lastUpdateTime"`

	// Frontend describes how clients can connect using this strategy.
	Frontend *CredentialIssuerFrontend `json:"frontend,omitempty"`
}

type CredentialIssuerFrontend struct {
	// Type describes which frontend mechanism clients can use with a strategy.
	Type FrontendType `json:"type"`

	// TokenCredentialRequestAPIInfo describes the parameters for the TokenCredentialRequest API on this Concierge.
	// This field is only set when Type is "TokenCredentialRequestAPI".
	TokenCredentialRequestAPIInfo *TokenCredentialRequestAPIInfo `json:"tokenCredentialRequestInfo,omitempty"`
}

// TokenCredentialRequestAPIInfo describes the parameters for the TokenCredentialRequest API on this Concierge.
type TokenCredentialRequestAPIInfo struct {
	// Server is the Kubernetes API server URL.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://|^http://`
	Server string `json:"server"`

	// CertificateAuthorityData is the Kubernetes API server CA bundle.
	// +kubebuilder:validation:MinLength=1
	CertificateAuthorityData string `json:"certificateAuthorityData"`
}

// Describes the configuration status of a Pinniped credential issuer.
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=pinniped,scope=Cluster
// +kubebuilder:subresource:status
type CredentialIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Status of the credential issuer.
	// +optional
	Status CredentialIssuerStatus `json:"status"`
}

// List of CredentialIssuer objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type CredentialIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CredentialIssuer `json:"items"`
}
