// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ActiveDirectoryIdentityProviderPhase string

const (
	// ActiveDirectoryPhasePending is the default phase for newly-created ActiveDirectoryIdentityProvider resources.
	ActiveDirectoryPhasePending ActiveDirectoryIdentityProviderPhase = "Pending"

	// ActiveDirectoryPhaseReady is the phase for an ActiveDirectoryIdentityProvider resource in a healthy state.
	ActiveDirectoryPhaseReady ActiveDirectoryIdentityProviderPhase = "Ready"

	// ActiveDirectoryPhaseError is the phase for an ActiveDirectoryIdentityProvider in an unhealthy state.
	ActiveDirectoryPhaseError ActiveDirectoryIdentityProviderPhase = "Error"
)

// Status of an Active Directory identity provider.
type ActiveDirectoryIdentityProviderStatus struct {
	// Phase summarizes the overall status of the ActiveDirectoryIdentityProvider.
	// +kubebuilder:default=Pending
	// +kubebuilder:validation:Enum=Pending;Ready;Error
	Phase ActiveDirectoryIdentityProviderPhase `json:"phase,omitempty"`

	// Represents the observations of an identity provider's current state.
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

type ActiveDirectoryIdentityProviderBind struct {
	// SecretName contains the name of a namespace-local Secret object that provides the username and
	// password for an Active Directory bind user. This account will be used to perform LDAP searches. The Secret should be
	// of type "kubernetes.io/basic-auth" which includes "username" and "password" keys. The username value
	// should be the full dn (distinguished name) of your bind account, e.g. "cn=bind-account,ou=users,dc=example,dc=com".
	// The password must be non-empty.
	// +kubebuilder:validation:MinLength=1
	SecretName string `json:"secretName"`
}

type ActiveDirectoryIdentityProviderUserSearchAttributes struct {
	// Username specifies the name of the attribute in the ActiveDirectory entry whose value shall become the username
    // of the user after a successful authentication. This would typically be the same attribute name used in
    // Optional, when empty this defaults to "sAMAccountName".
    // +optional
	Username string `json:"username,omitempty"`

	// UID specifies the name of the attribute in the ActiveDirectory entry which whose value shall be used to uniquely
	// identify the user within this ActiveDirectory provider after a successful authentication.
	// Optional, when empty this defaults to "objectGUID".
	// +optional
	UID string `json:"uid,omitempty"`
}

type ActiveDirectoryIdentityProviderGroupSearchAttributes struct {
	// GroupName specifies the name of the attribute in the Active Directory entries whose value shall become a group name
	// in the user's list of groups after a successful authentication.
	// The value of this field is case-sensitive and must match the case of the attribute name returned by the ActiveDirectory
	// server in the user's entry. E.g. "cn" for common name. Distinguished names can be used by specifying lower-case "dn".
	// Optional. When not specified, the default will act as if the GroupName were specified as "dn" (distinguished name).
	// +optional
	GroupName string `json:"groupName,omitempty"`
}

type ActiveDirectoryIdentityProviderUserSearch struct {
	// Base is the dn (distinguished name) that should be used as the search base when searching for users.
	// E.g. "ou=users,dc=example,dc=com".
	// Optional, when not specified it will search the whole directory tree.
	// Note that if your bind user only has permission to search a subtree, this must be specified.
	// Search a subtree will also be faster.
	// +optional
	Base string `json:"base,omitempty"`

	// Filter is the ActiveDirectory search filter which should be applied when searching for users. The pattern "{}" must occur
	// in the filter at least once and will be dynamically replaced by the username for which the search is being run.
	// E.g. "mail={}" or "&(objectClass=person)(uid={})". For more information about ActiveDirectory filters, see
	// https://ldap.com/ldap-filters.
	// Note that the dn (distinguished name) is not an attribute of an entry, so "dn={}" cannot be used.
	// Optional. When not specified, the default will act as if the Filter were specified as the value from
	// Attributes.Username appended by "={}". When the Attributes.Username is set to "dn" then the Filter must be
	// explicitly specified, since the default value of "dn={}" would not work.
	// +optional
	Filter string `json:"filter,omitempty"`

	// Attributes specifies how the user's information should be read from the ActiveDirectory entry which was found as
	// the result of the user search.
	// +optional
	Attributes ActiveDirectoryIdentityProviderUserSearchAttributes `json:"attributes,omitempty"`
}

type ActiveDirectoryIdentityProviderGroupSearch struct {
	// Base is the dn (distinguished name) that should be used as the search base when searching for groups. E.g.
	// "ou=groups,dc=example,dc=com". When not specified, no group search will be performed and
	// authenticated users will not belong to any groups from the ActiveDirectory provider. Also, when not specified,
	// the values of Filter and Attributes are ignored.
	// +optional
	Base string `json:"base,omitempty"`

	// Filter is the ActiveDirectory search filter which should be applied when searching for groups for a user.
	// The pattern "{}" must occur in the filter at least once and will be dynamically replaced by the
	// dn (distinguished name) of the user entry found as a result of the user search. E.g. "member={}" or
	// "&(objectClass=groupOfNames)(member={})". For more information about ActiveDirectory filters, see
	// https://ldap.com/ldap-filters.
	// Note that the dn (distinguished name) is not an attribute of an entry, so "dn={}" cannot be used.
	// Optional. When not specified, the default will act as if the Filter were specified as "member={}".
	// +optional
	Filter string `json:"filter,omitempty"`

	// Attributes specifies how the group's information should be read from each ActiveDirectory entry which was found as
	// the result of the group search.
	// +optional
	Attributes ActiveDirectoryIdentityProviderGroupSearchAttributes `json:"attributes,omitempty"`
}

// Spec for configuring an ActiveDirectory identity provider.
type ActiveDirectoryIdentityProviderSpec struct {
	// Host is the hostname of this Active Directory identity provider, i.e., where to connect. For example: ldap.example.com:636.
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`

	// TLS contains the connection settings for how to establish the connection to the Host.
	TLS *TLSSpec `json:"tls,omitempty"`

	// Bind contains the configuration for how to provide access credentials during an initial bind to the ActiveDirectory server
	// to be allowed to perform searches and binds to validate a user's credentials during a user's authentication attempt.
	Bind ActiveDirectoryIdentityProviderBind `json:"bind,omitempty"`

	// UserSearch contains the configuration for searching for a user by name in Active Directory.
	UserSearch ActiveDirectoryIdentityProviderUserSearch `json:"userSearch,omitempty"`

	// GroupSearch contains the configuration for searching for a user's group membership in ActiveDirectory.
	GroupSearch ActiveDirectoryIdentityProviderGroupSearch `json:"groupSearch,omitempty"`
}

// ActiveDirectoryIdentityProvider describes the configuration of an upstream Microsoft Active Directory identity provider.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=pinniped;pinniped-idp;pinniped-idps
// +kubebuilder:printcolumn:name="Host",type=string,JSONPath=`.spec.host`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:subresource:status
type ActiveDirectoryIdentityProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec for configuring the identity provider.
	Spec ActiveDirectoryIdentityProviderSpec `json:"spec"`

	// Status of the identity provider.
	Status ActiveDirectoryIdentityProviderStatus `json:"status,omitempty"`
}

// List of ActiveDirectoryIdentityProvider objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ActiveDirectoryIdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ActiveDirectoryIdentityProvider `json:"items"`
}
