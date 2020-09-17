// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package login

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type TokenCredentialRequestSpec struct {
	// Bearer token supplied with the credential request.
	Token string
}

type TokenCredentialRequestStatus struct {
	// A ClusterCredential will be returned for a successful credential request.
	// +optional
	Credential *ClusterCredential

	// An error message will be returned for an unsuccessful credential request.
	// +optional
	Message *string
}

// TokenCredentialRequest submits an IDP-specific credential to Pinniped in exchange for a cluster-specific credential.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TokenCredentialRequest struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   TokenCredentialRequestSpec
	Status TokenCredentialRequestStatus
}

// TokenCredentialRequestList is a list of TokenCredentialRequest objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TokenCredentialRequestList struct {
	metav1.TypeMeta
	metav1.ListMeta

	// Items is a list of TokenCredentialRequest
	Items []TokenCredentialRequest
}
