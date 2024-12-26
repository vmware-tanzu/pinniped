// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type FederationDomainPhase string

const (
	// FederationDomainPhasePending is the default phase for newly-created FederationDomain resources.
	FederationDomainPhasePending FederationDomainPhase = "Pending"

	// FederationDomainPhaseReady is the phase for an FederationDomain resource in a healthy state.
	FederationDomainPhaseReady FederationDomainPhase = "Ready"

	// FederationDomainPhaseError is the phase for an FederationDomain in an unhealthy state.
	FederationDomainPhaseError FederationDomainPhase = "Error"
)

// FederationDomainTLSSpec is a struct that describes the TLS configuration for an OIDC Provider.
type FederationDomainTLSSpec struct {
	// SecretName is an optional name of a Secret in the same namespace, of type `kubernetes.io/tls`, which contains
	// the TLS serving certificate for the HTTPS endpoints served by this FederationDomain. When provided, the TLS Secret
	// named here must contain keys named `tls.crt` and `tls.key` that contain the certificate and private key to use
	// for TLS.
	//
	// Server Name Indication (SNI) is an extension to the Transport Layer Security (TLS) supported by all major browsers.
	//
	// SecretName is required if you would like to use different TLS certificates for issuers of different hostnames.
	// SNI requests do not include port numbers, so all issuers with the same DNS hostname must use the same
	// SecretName value even if they have different port numbers.
	//
	// SecretName is not required when you would like to use only the HTTP endpoints (e.g. when the HTTP listener is
	// configured to listen on loopback interfaces or UNIX domain sockets for traffic from a service mesh sidecar).
	// It is also not required when you would like all requests to this OIDC Provider's HTTPS endpoints to
	// use the default TLS certificate, which is configured elsewhere.
	//
	// When your Issuer URL's host is an IP address, then this field is ignored. SNI does not work for IP addresses.
	//
	// +optional
	SecretName string `json:"secretName,omitempty"`
}

// FederationDomainTransformsConstant defines a constant variable and its value which will be made available to
// the transform expressions. This is a union type, and Type is the discriminator field.
type FederationDomainTransformsConstant struct {
	// Name determines the name of the constant. It must be a valid identifier name.
	// +kubebuilder:validation:Pattern=`^[a-zA-Z][_a-zA-Z0-9]*$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	Name string `json:"name"`

	// Type determines the type of the constant, and indicates which other field should be non-empty.
	// Allowed values are "string" or "stringList".
	// +kubebuilder:validation:Enum=string;stringList
	Type string `json:"type"`

	// StringValue should hold the value when Type is "string", and is otherwise ignored.
	// +optional
	StringValue string `json:"stringValue,omitempty"`

	// StringListValue should hold the value when Type is "stringList", and is otherwise ignored.
	// +optional
	StringListValue []string `json:"stringListValue,omitempty"`
}

// FederationDomainTransformsExpression defines a transform expression.
type FederationDomainTransformsExpression struct {
	// Type determines the type of the expression. It must be one of the supported types.
	// Allowed values are "policy/v1", "username/v1", or "groups/v1".
	// +kubebuilder:validation:Enum=policy/v1;username/v1;groups/v1
	Type string `json:"type"`

	// Expression is a CEL expression that will be evaluated based on the Type during an authentication.
	// +kubebuilder:validation:MinLength=1
	Expression string `json:"expression"`

	// Message is only used when Type is policy/v1. It defines an error message to be used when the policy rejects
	// an authentication attempt. When empty, a default message will be used.
	// +optional
	Message string `json:"message,omitempty"`
}

// FederationDomainTransformsExample defines a transform example.
type FederationDomainTransformsExample struct {
	// Username is the input username.
	// +kubebuilder:validation:MinLength=1
	Username string `json:"username"`

	// Groups is the input list of group names.
	// +optional
	Groups []string `json:"groups,omitempty"`

	// Expects is the expected output of the entire sequence of transforms when they are run against the
	// input Username and Groups.
	Expects FederationDomainTransformsExampleExpects `json:"expects"`
}

// FederationDomainTransformsExampleExpects defines the expected result for a transforms example.
type FederationDomainTransformsExampleExpects struct {
	// Username is the expected username after the transformations have been applied.
	// +optional
	Username string `json:"username,omitempty"`

	// Groups is the expected list of group names after the transformations have been applied.
	// +optional
	Groups []string `json:"groups,omitempty"`

	// Rejected is a boolean that indicates whether authentication is expected to be rejected by a policy expression
	// after the transformations have been applied. True means that it is expected that the authentication would be
	// rejected. The default value of false means that it is expected that the authentication would not be rejected
	// by any policy expression.
	// +optional
	Rejected bool `json:"rejected,omitempty"`

	// Message is the expected error message of the transforms. When Rejected is true, then Message is the expected
	// message for the policy which rejected the authentication attempt. When Rejected is true and Message is blank,
	// then Message will be treated as the default error message for authentication attempts which are rejected by a
	// policy. When Rejected is false, then Message is the expected error message for some other non-policy
	// transformation error, such as a runtime error. When Rejected is false, there is no default expected Message.
	// +optional
	Message string `json:"message,omitempty"`
}

// FederationDomainTransforms defines identity transformations for an identity provider's usage on a FederationDomain.
type FederationDomainTransforms struct {
	// Constants defines constant variables and their values which will be made available to the transform expressions.
	// +patchMergeKey=name
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=name
	// +optional
	Constants []FederationDomainTransformsConstant `json:"constants,omitempty"`

	// Expressions are an optional list of transforms and policies to be executed in the order given during every
	// authentication attempt, including during every session refresh.
	// Each is a CEL expression. It may use the basic CEL language as defined in
	// https://github.com/google/cel-spec/blob/master/doc/langdef.md plus the CEL string extensions defined in
	// https://github.com/google/cel-go/tree/master/ext#strings.
	//
	// The username and groups extracted from the identity provider, and the constants defined in this CR, are
	// available as variables in all expressions. The username is provided via a variable called `username` and
	// the list of group names is provided via a variable called `groups` (which may be an empty list).
	// Each user-provided constants is provided via a variable named `strConst.varName` for string constants
	// and `strListConst.varName` for string list constants.
	//
	// The only allowed types for expressions are currently policy/v1, username/v1, and groups/v1.
	// Each policy/v1 must return a boolean, and when it returns false, no more expressions from the list are evaluated
	// and the authentication attempt is rejected.
	// Transformations of type policy/v1 do not return usernames or group names, and therefore cannot change the
	// username or group names.
	// Each username/v1 transform must return the new username (a string), which can be the same as the old username.
	// Transformations of type username/v1 do not return group names, and therefore cannot change the group names.
	// Each groups/v1 transform must return the new groups list (list of strings), which can be the same as the old
	// groups list.
	// Transformations of type groups/v1 do not return usernames, and therefore cannot change the usernames.
	// After each expression, the new (potentially changed) username or groups get passed to the following expression.
	//
	// Any compilation or static type-checking failure of any expression will cause an error status on the FederationDomain.
	// During an authentication attempt, any unexpected runtime evaluation errors (e.g. division by zero) cause the
	// authentication attempt to fail. When all expressions evaluate successfully, then the (potentially changed) username
	// and group names have been decided for that authentication attempt.
	//
	// +optional
	Expressions []FederationDomainTransformsExpression `json:"expressions,omitempty"`

	// Examples can optionally be used to ensure that the sequence of transformation expressions are working as
	// expected. Examples define sample input identities which are then run through the expression list, and the
	// results are compared to the expected results. If any example in this list fails, then this
	// identity provider will not be available for use within this FederationDomain, and the error(s) will be
	// added to the FederationDomain status. This can be used to help guard against programming mistakes in the
	// expressions, and also act as living documentation for other administrators to better understand the expressions.
	// +optional
	Examples []FederationDomainTransformsExample `json:"examples,omitempty"`
}

// FederationDomainIdentityProvider describes how an identity provider is made available in this FederationDomain.
type FederationDomainIdentityProvider struct {
	// DisplayName is the name of this identity provider as it will appear to clients. This name ends up in the
	// kubeconfig of end users, so changing the name of an identity provider that is in use by end users will be a
	// disruptive change for those users.
	// +kubebuilder:validation:MinLength=1
	DisplayName string `json:"displayName"`

	// ObjectRef is a reference to a Pinniped identity provider resource. A valid reference is required.
	// If the reference cannot be resolved then the identity provider will not be made available.
	// Must refer to a resource of one of the Pinniped identity provider types, e.g. OIDCIdentityProvider,
	// LDAPIdentityProvider, ActiveDirectoryIdentityProvider.
	ObjectRef corev1.TypedLocalObjectReference `json:"objectRef"`

	// Transforms is an optional way to specify transformations to be applied during user authentication and
	// session refresh.
	// +optional
	Transforms FederationDomainTransforms `json:"transforms,omitempty"`
}

// FederationDomainSpec is a struct that describes an OIDC Provider.
type FederationDomainSpec struct {
	// Issuer is the OIDC Provider's issuer, per the OIDC Discovery Metadata document, as well as the
	// identifier that it will use for the iss claim in issued JWTs. This field will also be used as
	// the base URL for any endpoints used by the OIDC Provider (e.g., if your issuer is
	// https://example.com/foo, then your authorization endpoint will look like
	// https://example.com/foo/some/path/to/auth/endpoint).
	//
	// See
	// https://openid.net/specs/openid-connect-discovery-1_0.html#rfc.section.3 for more information.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:XValidation:message="issuer must be an HTTPS URL",rule="isURL(self) && url(self).getScheme() == 'https'"
	Issuer string `json:"issuer"`

	// TLS specifies a secret which will contain Transport Layer Security (TLS) configuration for the FederationDomain.
	// +optional
	TLS *FederationDomainTLSSpec `json:"tls,omitempty"`

	// IdentityProviders is the list of identity providers available for use by this FederationDomain.
	//
	// An identity provider CR (e.g. OIDCIdentityProvider or LDAPIdentityProvider) describes how to connect to a server,
	// how to talk in a specific protocol for authentication, and how to use the schema of that server/protocol to
	// extract a normalized user identity. Normalized user identities include a username and a list of group names.
	// In contrast, IdentityProviders describes how to use that normalized identity in those Kubernetes clusters which
	// belong to this FederationDomain. Each entry in IdentityProviders can be configured with arbitrary transformations
	// on that normalized identity. For example, a transformation can add a prefix to all usernames to help avoid
	// accidental conflicts when multiple identity providers have different users with the same username (e.g.
	// "idp1:ryan" versus "idp2:ryan"). Each entry in IdentityProviders can also implement arbitrary authentication
	// rejection policies. Even though a user was able to authenticate with the identity provider, a policy can disallow
	// the authentication to the Kubernetes clusters that belong to this FederationDomain. For example, a policy could
	// disallow the authentication unless the user belongs to a specific group in the identity provider.
	//
	// For backwards compatibility with versions of Pinniped which predate support for multiple identity providers,
	// an empty IdentityProviders list will cause the FederationDomain to use all available identity providers which
	// exist in the same namespace, but also to reject all authentication requests when there is more than one identity
	// provider currently defined. In this backwards compatibility mode, the name of the identity provider resource
	// (e.g. the Name of an OIDCIdentityProvider resource) will be used as the name of the identity provider in this
	// FederationDomain. This mode is provided to make upgrading from older versions easier. However, instead of
	// relying on this backwards compatibility mode, please consider this mode to be deprecated and please instead
	// explicitly list the identity provider using this IdentityProviders field.
	//
	// +optional
	IdentityProviders []FederationDomainIdentityProvider `json:"identityProviders,omitempty"`
}

// FederationDomainSecrets holds information about this OIDC Provider's secrets.
type FederationDomainSecrets struct {
	// JWKS holds the name of the corev1.Secret in which this OIDC Provider's signing/verification keys are
	// stored. If it is empty, then the signing/verification keys are either unknown or they don't
	// exist.
	// +optional
	JWKS corev1.LocalObjectReference `json:"jwks,omitempty"`

	// TokenSigningKey holds the name of the corev1.Secret in which this OIDC Provider's key for
	// signing tokens is stored.
	// +optional
	TokenSigningKey corev1.LocalObjectReference `json:"tokenSigningKey,omitempty"`

	// StateSigningKey holds the name of the corev1.Secret in which this OIDC Provider's key for
	// signing state parameters is stored.
	// +optional
	StateSigningKey corev1.LocalObjectReference `json:"stateSigningKey,omitempty"`

	// StateSigningKey holds the name of the corev1.Secret in which this OIDC Provider's key for
	// encrypting state parameters is stored.
	// +optional
	StateEncryptionKey corev1.LocalObjectReference `json:"stateEncryptionKey,omitempty"`
}

// FederationDomainStatus is a struct that describes the actual state of an OIDC Provider.
type FederationDomainStatus struct {
	// Phase summarizes the overall status of the FederationDomain.
	// +kubebuilder:default=Pending
	// +kubebuilder:validation:Enum=Pending;Ready;Error
	Phase FederationDomainPhase `json:"phase,omitempty"`

	// Conditions represent the observations of an FederationDomain's current state.
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// Secrets contains information about this OIDC Provider's secrets.
	// +optional
	Secrets FederationDomainSecrets `json:"secrets,omitempty"`
}

// FederationDomain describes the configuration of an OIDC provider.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=pinniped
// +kubebuilder:printcolumn:name="Issuer",type=string,JSONPath=`.spec.issuer`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:subresource:status
type FederationDomain struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec of the OIDC provider.
	Spec FederationDomainSpec `json:"spec"`

	// Status of the OIDC provider.
	Status FederationDomainStatus `json:"status,omitempty"`
}

// List of FederationDomain objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type FederationDomainList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []FederationDomain `json:"items"`
}
