// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type LDAPIdentityProviderPhase string

const (
	// LDAPPhasePending is the default phase for newly-created LDAPIdentityProvider resources.
	LDAPPhasePending LDAPIdentityProviderPhase = "Pending"

	// LDAPPhaseReady is the phase for an LDAPIdentityProvider resource in a healthy state.
	LDAPPhaseReady LDAPIdentityProviderPhase = "Ready"

	// LDAPPhaseError is the phase for an LDAPIdentityProvider in an unhealthy state.
	LDAPPhaseError LDAPIdentityProviderPhase = "Error"
)

// Status of an LDAP identity provider.
type LDAPIdentityProviderStatus struct {
	// Phase summarizes the overall status of the LDAPIdentityProvider.
	// +kubebuilder:default=Pending
	// +kubebuilder:validation:Enum=Pending;Ready;Error
	Phase LDAPIdentityProviderPhase `json:"phase,omitempty"`
}

type LDAPIdentityProviderTLSSpec struct {
	// X.509 Certificate Authority (base64-encoded PEM bundle) to trust when connecting to the LDAP provider.
	// If omitted, a default set of system roots will be trusted.
	// +optional
	CertificateAuthorityData string `json:"certificateAuthorityData,omitempty"`
}

type LDAPIdentityProviderBindSpec struct {
	// SecretName contains the name of a namespace-local Secret object that provides the username and
	// password for an LDAP bind user. This account will be used to perform LDAP searches. The Secret should be
	// of type "kubernetes.io/basic-auth" which includes "username" and "password" keys. The username value
	// should be the full DN of your bind account, e.g. "cn=bind-account,ou=users,dc=example,dc=com".
	// +kubebuilder:validation:MinLength=1
	SecretName string `json:"secretName"`
}

type LDAPIdentityProviderUserSearchAttributesSpec struct {
	// Username specifies the name of attribute in the LDAP entry which whose value shall become the username
	// of the user after a successful authentication. This would typically be the same attribute name used in
	// the user search filter. E.g. "mail" or "uid" or "userPrincipalName".
	// +kubebuilder:validation:MinLength=1
	Username string `json:"username,omitempty"`

	// UniqueID specifies the name of the attribute in the LDAP entry which whose value shall be used to uniquely
	// identify the user within this LDAP provider after a successful authentication. E.g. "uidNumber" or "objectGUID".
	// +kubebuilder:validation:MinLength=1
	UniqueID string `json:"uniqueID,omitempty"`
}

type LDAPIdentityProviderUserSearchSpec struct {
	// Base is the DN that should be used as the search base when searching for users. E.g. "ou=users,dc=example,dc=com".
	// +kubebuilder:validation:MinLength=1
	Base string `json:"base,omitempty"`

	// Filter is the LDAP search filter which should be applied when searching for users. The pattern "{}" must occur
	// in the filter and will be dynamically replaced by the username for which the search is being run. E.g. "mail={}"
	// or "&(objectClass=person)(uid={})". For more information about LDAP filters, see https://ldap.com/ldap-filters.
	// Optional. When not specified, the default will act as if the Filter were specified as the value from
	// Attributes.Username appended by "={}".
	// +optional
	Filter string `json:"filter,omitempty"`

	// Attributes specifies how the user's information should be read from the LDAP entry which was found as
	// the result of the user search.
	// +optional
	Attributes LDAPIdentityProviderUserSearchAttributesSpec `json:"attributes,omitempty"`
}

// Spec for configuring an LDAP identity provider.
type LDAPIdentityProviderSpec struct {
	// Host is the hostname of this LDAP identity provider, i.e., where to connect. For example: ldap.example.com:636.
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`

	// TLS contains the connection settings for how to establish the connection to the Host.
	TLS *LDAPIdentityProviderTLSSpec `json:"tls,omitempty"`

	// Bind contains the configuration for how to provide access credentials during an initial bind to the LDAP server
	// to be allowed to perform searches and binds to validate a user's credentials during a user's authentication attempt.
	Bind LDAPIdentityProviderBindSpec `json:"bind,omitempty"`

	// UserSearch contains the configuration for searching for a user by name in the LDAP provider.
	UserSearch LDAPIdentityProviderUserSearchSpec `json:"userSearch,omitempty"`
}

// LDAPIdentityProvider describes the configuration of an upstream Lightweight Directory Access
// Protocol (LDAP) identity provider.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=pinniped;pinniped-idp;pinniped-idps
// +kubebuilder:printcolumn:name="Host",type=string,JSONPath=`.spec.host`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:subresource:status
type LDAPIdentityProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec for configuring the identity provider.
	Spec LDAPIdentityProviderSpec `json:"spec"`

	// Status of the identity provider.
	Status LDAPIdentityProviderStatus `json:"status,omitempty"`
}

// List of LDAPIdentityProvider objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type LDAPIdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []LDAPIdentityProvider `json:"items"`
}
