// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type JWTAuthenticatorPhase string

const (
	// JWTAuthenticatorPhasePending is the default phase for newly-created JWTAuthenticator resources.
	JWTAuthenticatorPhasePending JWTAuthenticatorPhase = "Pending"

	// JWTAuthenticatorPhaseReady is the phase for an JWTAuthenticator resource in a healthy state.
	JWTAuthenticatorPhaseReady JWTAuthenticatorPhase = "Ready"

	// JWTAuthenticatorPhaseError is the phase for an JWTAuthenticator in an unhealthy state.
	JWTAuthenticatorPhaseError JWTAuthenticatorPhase = "Error"
)

// Status of a JWT authenticator.
type JWTAuthenticatorStatus struct {
	// Represents the observations of the authenticator's current state.
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
	// Phase summarizes the overall status of the JWTAuthenticator.
	// +kubebuilder:default=Pending
	// +kubebuilder:validation:Enum=Pending;Ready;Error
	Phase JWTAuthenticatorPhase `json:"phase,omitempty"`
}

// Spec for configuring a JWT authenticator.
type JWTAuthenticatorSpec struct {
	// Issuer is the OIDC issuer URL that will be used to discover public signing keys. Issuer is
	// also used to validate the "iss" JWT claim.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://`
	Issuer string `json:"issuer"`

	// Audience is the required value of the "aud" JWT claim.
	// +kubebuilder:validation:MinLength=1
	Audience string `json:"audience"`

	// Claims allows customization of the claims that will be mapped to user identity
	// for Kubernetes access.
	// +optional
	Claims JWTTokenClaims `json:"claims"`

	// TLS configuration for communicating with the OIDC provider.
	// +optional
	TLS *TLSSpec `json:"tls,omitempty"`
}

// JWTTokenClaims allows customization of the claims that will be mapped to user identity
// for Kubernetes access.
type JWTTokenClaims struct {
	// Groups is the name of the claim which should be read to extract the user's
	// group membership from the JWT token. When not specified, it will default to "groups".
	// +optional
	Groups string `json:"groups"`

	// Username is the name of the claim which should be read to extract the
	// username from the JWT token. When not specified, it will default to "username".
	// +optional
	Username string `json:"username"`
}

// JWTAuthenticator describes the configuration of a JWT authenticator.
//
// Upon receiving a signed JWT, a JWTAuthenticator will performs some validation on it (e.g., valid
// signature, existence of claims, etc.) and extract the username and groups from the token.
//
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=pinniped;pinniped-authenticator;pinniped-authenticators,scope=Cluster
// +kubebuilder:printcolumn:name="Issuer",type=string,JSONPath=`.spec.issuer`
// +kubebuilder:printcolumn:name="Audience",type=string,JSONPath=`.spec.audience`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:subresource:status
type JWTAuthenticator struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec for configuring the authenticator.
	Spec JWTAuthenticatorSpec `json:"spec"`

	// Status of the authenticator.
	Status JWTAuthenticatorStatus `json:"status,omitempty"`
}

// List of JWTAuthenticator objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type JWTAuthenticatorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []JWTAuthenticator `json:"items"`
}
