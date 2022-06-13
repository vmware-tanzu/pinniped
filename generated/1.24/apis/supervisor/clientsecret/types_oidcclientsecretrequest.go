// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package clientsecret

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type OIDCClientSecretRequestSpec struct {
	GenerateNewSecret bool `json:"generateNewSecret"`
	RevokeOldSecrets  bool `json:"revokeOldSecrets"`
}

type OIDCClientSecretRequestStatus struct {
	GeneratedSecret    string `json:"generatedSecret,omitempty"`
	TotalClientSecrets int    `json:"totalClientSecrets"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OIDCClientSecretRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"` // metadata.name must be set to the client ID

	Spec   OIDCClientSecretRequestSpec   `json:"spec"`
	Status OIDCClientSecretRequestStatus `json:"status"`
}
