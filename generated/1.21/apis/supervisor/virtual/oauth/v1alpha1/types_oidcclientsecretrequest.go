// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type OIDCClientSecretRequestSpec struct {
	GenerateNewSecret bool `json:"generateNewSecret"`
	RevokeOldSecrets  bool `json:"revokeOldSecrets"`
}

type OIDCClientSecretRequestStatus struct {
	GeneratedSecret    string `json:"generatedSecret,omitempty"`
	TotalClientSecrets int    `json:"totalClientSecrets"`
}

// +genclient
// +genclient:onlyVerbs=create
// +kubebuilder:subresource:status
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OIDCClientSecretRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"` // metadata.name must be set to the client ID

	Spec   OIDCClientSecretRequestSpec   `json:"spec"`
	Status OIDCClientSecretRequestStatus `json:"status"`
}
