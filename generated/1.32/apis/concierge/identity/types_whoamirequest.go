// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WhoAmIRequest submits a request to echo back the current authenticated user.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type WhoAmIRequest struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   WhoAmIRequestSpec
	Status WhoAmIRequestStatus
}

// Spec is always empty for a WhoAmIRequest.
type WhoAmIRequestSpec struct {
	// empty for now but we may add some config here in the future
	// any such config must be safe in the context of an unauthenticated user
}

// Status is set by the server in the response to a WhoAmIRequest.
type WhoAmIRequestStatus struct {
	// The current authenticated user, exactly as Kubernetes understands it.
	KubernetesUserInfo KubernetesUserInfo

	// We may add concierge specific information here in the future.
}

// WhoAmIRequestList is a list of WhoAmIRequest objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type WhoAmIRequestList struct {
	metav1.TypeMeta
	metav1.ListMeta

	// Items is a list of WhoAmIRequest.
	Items []WhoAmIRequest
}
