/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type CredentialIssuerConfigStatus struct {
	Strategies []CredentialIssuerConfigStrategy `json:"strategies"`

	// +optional
	KubeConfigInfo *CredentialIssuerConfigKubeConfigInfo `json:"kubeConfigInfo,omitempty"`
}

type CredentialIssuerConfigKubeConfigInfo struct {
	// The K8s API server URL. Required.
	Server string `json:"server,omitempty"`

	// The K8s API server CA bundle. Required.
	CertificateAuthorityData string `json:"certificateAuthorityData,omitempty"`
}

type CredentialIssuerConfigStrategy struct {
	Type           string      `json:"type,omitempty"`
	Status         string      `json:"status,omitempty"`
	Reason         string      `json:"reason,omitempty"`
	Message        string      `json:"message,omitempty"`
	LastUpdateTime metav1.Time `json:"lastUpdateTime"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type CredentialIssuerConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Status CredentialIssuerConfigStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type CredentialIssuerConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CredentialIssuerConfig `json:"items"`
}
