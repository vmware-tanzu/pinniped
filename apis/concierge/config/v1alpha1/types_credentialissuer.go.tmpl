// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +kubebuilder:validation:Enum=KubeClusterSigningCertificate
type StrategyType string

// +kubebuilder:validation:Enum=Success;Error
type StrategyStatus string

// +kubebuilder:validation:Enum=FetchedKey;CouldNotFetchKey
type StrategyReason string

const (
	KubeClusterSigningCertificateStrategyType = StrategyType("KubeClusterSigningCertificate")
	ImpersonationProxyStrategyType            = StrategyType("ImpersonationProxy")

	SuccessStrategyStatus = StrategyStatus("Success")
	ErrorStrategyStatus   = StrategyStatus("Error")

	CouldNotFetchKeyStrategyReason = StrategyReason("CouldNotFetchKey")
	FetchedKeyStrategyReason       = StrategyReason("FetchedKey")
	ListeningStrategyReason        = StrategyReason("Listening")
	DisabledStrategyReason         = StrategyReason("Disabled")
)

// Status of a credential issuer.
type CredentialIssuerStatus struct {
	// List of integration strategies that were attempted by Pinniped.
	Strategies []CredentialIssuerStrategy `json:"strategies"`

	// Information needed to form a valid Pinniped-based kubeconfig using the TokenCredentialRequest API.
	// +optional
	KubeConfigInfo *CredentialIssuerKubeConfigInfo `json:"kubeConfigInfo,omitempty"`

	// Information needed to form a valid Pinniped-based kubeconfig using the impersonation proxy.
	// +optional
	ImpersonationProxyInfo *CredentialIssuerImpersonationProxyInfo `json:"impersonationProxyInfo,omitempty"`
}

// Information needed to connect to the TokenCredentialRequest API on this cluster.
type CredentialIssuerKubeConfigInfo struct {
	// The Kubernetes API server URL.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://|^http://`
	Server string `json:"server"`

	// The Kubernetes API server CA bundle.
	// +kubebuilder:validation:MinLength=1
	CertificateAuthorityData string `json:"certificateAuthorityData"`
}

// Information needed to connect to the TokenCredentialRequest API on this cluster.
type CredentialIssuerImpersonationProxyInfo struct {
	// The HTTPS endpoint of the impersonation proxy.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://`
	Endpoint string `json:"endpoint"`

	// The CA bundle to validate connections to the impersonation proxy.
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
