// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
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
type CredentialIssuerStatus struct {
	// List of integration strategies that were attempted by Pinniped.
	Strategies []CredentialIssuerStrategy `json:"strategies"`

	// Information needed to form a valid Pinniped-based kubeconfig using this credential issuer.
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
}

type TLSConfig struct {
    // The CA that clients should validate when connecting to the impersonation proxy endpoint
	CertificateAuthorityData string `json:"certificateAuthorityData"`
	// The name of a secret of type "kubernetes.io/tls" that will be used to serve the endpoint
	SecretName string `json:"secretName"`
}

type ImpersonationProxySpec struct {
	// specify the external endpoint name that will route to the impersonation proxy port
	ExternalEndpoint string `json:"externalEndpoint"`
	// TLS configuration to communicate with the impersonation proxy
	TLS TLSConfig `json:"tls"`
}

// Spec for the credential issuer
type CredentialIssuerSpec struct {
	ImpersonationProxy ImpersonationProxySpec `json:"impersonationProxy"`
}

// Describes the configuration status of a Pinniped credential issuer.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=pinniped
type CredentialIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Status of the credential issuer.
	Status CredentialIssuerStatus `json:"status"`

	Spec CredentialIssuerSpec `json:"spec"`
}

// List of CredentialIssuer objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type CredentialIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CredentialIssuer `json:"items"`
}
