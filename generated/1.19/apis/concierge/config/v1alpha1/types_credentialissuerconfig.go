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

	SuccessStrategyStatus = StrategyStatus("Success")
	ErrorStrategyStatus   = StrategyStatus("Error")

	CouldNotFetchKeyStrategyReason = StrategyReason("CouldNotFetchKey")
	FetchedKeyStrategyReason       = StrategyReason("FetchedKey")
)

// Status of a credential issuer.
type CredentialIssuerConfigStatus struct {
	// List of integration strategies that were attempted by Pinniped.
	Strategies []CredentialIssuerConfigStrategy `json:"strategies"`

	// Information needed to form a valid Pinniped-based kubeconfig using this credential issuer.
	// +optional
	KubeConfigInfo *CredentialIssuerConfigKubeConfigInfo `json:"kubeConfigInfo,omitempty"`
}

// Information needed to form a valid Pinniped-based kubeconfig using this credential issuer.
type CredentialIssuerConfigKubeConfigInfo struct {
	// The K8s API server URL.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://|^http://`
	Server string `json:"server"`

	// The K8s API server CA bundle.
	// +kubebuilder:validation:MinLength=1
	CertificateAuthorityData string `json:"certificateAuthorityData"`
}

// Status of an integration strategy that was attempted by Pinniped.
type CredentialIssuerConfigStrategy struct {
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
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:shortName=cic

type CredentialIssuerConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Status of the credential issuer.
	Status CredentialIssuerConfigStatus `json:"status"`
}

// List of CredentialIssuerConfig objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type CredentialIssuerConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CredentialIssuerConfig `json:"items"`
}
