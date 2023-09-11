// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
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

	// Represents the observations of an identity provider's current state.
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

type LDAPIdentityProviderBind struct {
	// SecretName contains the name of a namespace-local Secret object that provides the username and
	// password for an LDAP bind user. This account will be used to perform LDAP searches. The Secret should be
	// of type "kubernetes.io/basic-auth" which includes "username" and "password" keys. The username value
	// should be the full dn (distinguished name) of your bind account, e.g. "cn=bind-account,ou=users,dc=example,dc=com".
	// The password must be non-empty.
	// +kubebuilder:validation:MinLength=1
	SecretName string `json:"secretName"`
}

type LDAPIdentityProviderUserSearchAttributes struct {
	// Username specifies the name of the attribute in the LDAP entry whose value shall become the username
	// of the user after a successful authentication. This would typically be the same attribute name used in
	// the user search filter, although it can be different. E.g. "mail" or "uid" or "userPrincipalName".
	// The value of this field is case-sensitive and must match the case of the attribute name returned by the LDAP
	// server in the user's entry. Distinguished names can be used by specifying lower-case "dn". When this field
	// is set to "dn" then the LDAPIdentityProviderUserSearch's Filter field cannot be blank, since the default
	// value of "dn={}" would not work.
	// +kubebuilder:validation:MinLength=1
	Username string `json:"username,omitempty"`

	// UID specifies the name of the attribute in the LDAP entry which whose value shall be used to uniquely
	// identify the user within this LDAP provider after a successful authentication. E.g. "uidNumber" or "objectGUID".
	// The value of this field is case-sensitive and must match the case of the attribute name returned by the LDAP
	// server in the user's entry. Distinguished names can be used by specifying lower-case "dn".
	// +kubebuilder:validation:MinLength=1
	UID string `json:"uid,omitempty"`
}

type LDAPIdentityProviderGroupSearchAttributes struct {
	// GroupName specifies the name of the attribute in the LDAP entries whose value shall become a group name
	// in the user's list of groups after a successful authentication.
	// The value of this field is case-sensitive and must match the case of the attribute name returned by the LDAP
	// server in the user's entry. E.g. "cn" for common name. Distinguished names can be used by specifying lower-case "dn".
	// Optional. When not specified, the default will act as if the GroupName were specified as "dn" (distinguished name).
	// +optional
	GroupName string `json:"groupName,omitempty"`
}

type LDAPIdentityProviderUserSearch struct {
	// Base is the dn (distinguished name) that should be used as the search base when searching for users.
	// E.g. "ou=users,dc=example,dc=com".
	// +kubebuilder:validation:MinLength=1
	Base string `json:"base,omitempty"`

	// Filter is the LDAP search filter which should be applied when searching for users. The pattern "{}" must occur
	// in the filter at least once and will be dynamically replaced by the username for which the search is being run.
	// E.g. "mail={}" or "&(objectClass=person)(uid={})". For more information about LDAP filters, see
	// https://ldap.com/ldap-filters.
	// Note that the dn (distinguished name) is not an attribute of an entry, so "dn={}" cannot be used.
	// Optional. When not specified, the default will act as if the Filter were specified as the value from
	// Attributes.Username appended by "={}". When the Attributes.Username is set to "dn" then the Filter must be
	// explicitly specified, since the default value of "dn={}" would not work.
	// +optional
	Filter string `json:"filter,omitempty"`

	// Attributes specifies how the user's information should be read from the LDAP entry which was found as
	// the result of the user search.
	// +optional
	Attributes LDAPIdentityProviderUserSearchAttributes `json:"attributes,omitempty"`
}

type LDAPIdentityProviderGroupSearch struct {
	// Base is the dn (distinguished name) that should be used as the search base when searching for groups. E.g.
	// "ou=groups,dc=example,dc=com". When not specified, no group search will be performed and
	// authenticated users will not belong to any groups from the LDAP provider. Also, when not specified,
	// the values of Filter, UserAttributeForFilter, Attributes, and SkipGroupRefresh are ignored.
	// +optional
	Base string `json:"base,omitempty"`

	// Filter is the LDAP search filter which should be applied when searching for groups for a user.
	// The pattern "{}" must occur in the filter at least once and will be dynamically replaced by the
	// value of an attribute of the user entry found as a result of the user search. Which attribute's
	// value is used to replace the placeholder(s) depends on the value of UserAttributeForFilter.
	// For more information about LDAP filters, see https://ldap.com/ldap-filters.
	// Note that the dn (distinguished name) is not an attribute of an entry, so "dn={}" cannot be used.
	// Optional. When not specified, the default will act as if the Filter were specified as "member={}".
	// +optional
	Filter string `json:"filter,omitempty"`

	// UserAttributeForFilter specifies which attribute's value from the user entry found as a result of
	// the user search will be used to replace the "{}" placeholder(s) in the group search Filter.
	// For example, specifying "uid" as the UserAttributeForFilter while specifying
	// "&(objectClass=posixGroup)(memberUid={})" as the Filter would search for groups by replacing
	// the "{}" placeholder in the Filter with the value of the user's "uid" attribute.
	// Optional. When not specified, the default will act as if "dn" were specified. For example, leaving
	// UserAttributeForFilter unspecified while specifying "&(objectClass=groupOfNames)(member={})" as the Filter
	// would search for groups by replacing the "{}" placeholder(s) with the dn (distinguished name) of the user.
	// +optional
	UserAttributeForFilter string `json:"userAttributeForFilter,omitempty"`

	// Attributes specifies how the group's information should be read from each LDAP entry which was found as
	// the result of the group search.
	// +optional
	Attributes LDAPIdentityProviderGroupSearchAttributes `json:"attributes,omitempty"`

	// The user's group membership is refreshed as they interact with the supervisor
	// to obtain new credentials (as their old credentials expire).  This allows group
	// membership changes to be quickly reflected into Kubernetes clusters.  Since
	// group membership is often used to bind authorization policies, it is important
	// to keep the groups observed in Kubernetes clusters in-sync with the identity
	// provider.
	//
	// In some environments, frequent group membership queries may result in a
	// significant performance impact on the identity provider and/or the supervisor.
	// The best approach to handle performance impacts is to tweak the group query
	// to be more performant, for example by disabling nested group search or by
	// using a more targeted group search base.
	//
	// If the group search query cannot be made performant and you are willing to
	// have group memberships remain static for approximately a day, then set
	// skipGroupRefresh to true.  This is an insecure configuration as authorization
	// policies that are bound to group membership will not notice if a user has
	// been removed from a particular group until their next login.
	//
	// This is an experimental feature that may be removed or significantly altered
	// in the future.  Consumers of this configuration should carefully read all
	// release notes before upgrading to ensure that the meaning of this field has
	// not changed.
	SkipGroupRefresh bool `json:"skipGroupRefresh,omitempty"`
}

// Spec for configuring an LDAP identity provider.
type LDAPIdentityProviderSpec struct {
	// Host is the hostname of this LDAP identity provider, i.e., where to connect. For example: ldap.example.com:636.
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`

	// TLS contains the connection settings for how to establish the connection to the Host.
	TLS *TLSSpec `json:"tls,omitempty"`

	// Bind contains the configuration for how to provide access credentials during an initial bind to the LDAP server
	// to be allowed to perform searches and binds to validate a user's credentials during a user's authentication attempt.
	Bind LDAPIdentityProviderBind `json:"bind,omitempty"`

	// UserSearch contains the configuration for searching for a user by name in the LDAP provider.
	UserSearch LDAPIdentityProviderUserSearch `json:"userSearch,omitempty"`

	// GroupSearch contains the configuration for searching for a user's group membership in the LDAP provider.
	GroupSearch LDAPIdentityProviderGroupSearch `json:"groupSearch,omitempty"`
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
