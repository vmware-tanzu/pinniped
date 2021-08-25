// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:validation:Enum=Success;Duplicate;Invalid;SameIssuerHostMustUseSameSecret
type FederationDomainStatusCondition string

const (
	SuccessFederationDomainStatusCondition                         = FederationDomainStatusCondition("Success")
	DuplicateFederationDomainStatusCondition                       = FederationDomainStatusCondition("Duplicate")
	SameIssuerHostMustUseSameSecretFederationDomainStatusCondition = FederationDomainStatusCondition("SameIssuerHostMustUseSameSecret")
	InvalidFederationDomainStatusCondition                         = FederationDomainStatusCondition("Invalid")
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
	// SecretName is not required when you would like to use only the HTTP endpoints (e.g. when terminating TLS at an
	// Ingress). It is also not required when you would like all requests to this OIDC Provider's HTTPS endpoints to
	// use the default TLS certificate, which is configured elsewhere.
	//
	// When your Issuer URL's host is an IP address, then this field is ignored. SNI does not work for IP addresses.
	//
	// +optional
	SecretName string `json:"secretName,omitempty"`
}

// FederationDomainTransformParam is used to pass a typed param value to a transformation function.
type FederationDomainTransformParam struct {
	// Type determines the type of the param, and indicates which other field should be non-empty.
	// +kubebuilder:validation:Enum=string;bool;int
	Type string `json:"type"`

	// StringValue should hold the value when Type is "string", and is otherwise ignored.
	// +optional
	StringValue string `json:"stringValue"`

	// BoolValue should hold the value when Type is "bool", and is otherwise ignored.
	// +optional
	BoolValue bool `json:"boolValue"`

	// IntValue should hold the value when Type is "int", and is otherwise ignored.
	// +optional
	IntValue int64 `json:"intValue"`
}

type FederationDomainTransform struct {
	// ObjectRef is a reference to a transformation function. Currently, this must be a resource of kind StarlarkFunction.
	// This must refer to function resource with type usernameAndGroups.transform.pinniped.dev/v1, which
	// specifies the contract for calling the function, passing arguments to it, and reading the result from it.
	// A valid reference is required. If the reference cannot be resolved, or if it is of an unsupported kind or type,
	// then the identity provider will not be made available.
	ObjectRef corev1.TypedLocalObjectReference `json:"objectRef"`

	// Params are additional parameters that will be passed to the transformation function beyond the default parameters
	// determined by the function's type (e.g. usernameAndGroups.transform.pinniped.dev/v1). It is a map of param names
	// to param values. To be valid, a param's value must be of the type declared by the referenced StarlarkFunction
	// resource for that param name, and all of the param names declared by the StarlarkFunction resource must be present
	// here. Extra params which are listed here but are not defined by the StarlarkFunction resource will be ignored.
	// If any params are invalid, then the identity provider will not be made available.
	// +optional
	Params map[string]FederationDomainTransformParam `json:"params,omitempty"`
}

// FederationDomainIdentityProvider describes how an identity provider is made available in this FederationDomain.
// An identity provider (e.g. OIDCIdentityProvider or LDAPIdentityProvider) describes how to connect to a server,
// how to talk in a specific protocol for authentication, and how to use the schema of that server/protocol to
// extract a normalized user identity. Normalized user identities include a username and a list of group names.
// In contrast, the FederationDomainIdentityProvider describes how to use that normalized identity in a group of
// Kubernetes clusters. It can perform arbitrary transformations on that normalized identity. For example, a
// transformation can add a prefix to all usernames to help avoid accidental conflicts when multiple identity
// providers have different users with the same username (e.g. "idp1:ryan" versus "idp2:ryan").
// A FederationDomainIdentityProvider can also implement arbitrary authentication rejection policies.
// For example, even though a user was able to authenticate with the identity provider, disallow the authentication
// to the Kubernetes clusters that belong to this FederationDomain unless the user also belongs to a specific
// group in the identity provider.
type FederationDomainIdentityProvider struct {
	// Name is the name of this identity provider as it will appear to clients. This name ends up in the kubeconfig
	// of end users, so changing the name of an identity provider that is in use by end users will be a disruptive
	// change for those users.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// ObjectRef is a reference to a Pinniped identity provider resource. A valid reference is required.
	// If the reference cannot be resolved then the identity provider will not be made available.
	ObjectRef corev1.TypedLocalObjectReference `json:"objectRef"`

	// Transforms is an optional list of transformations to be applied during user authentication
	// in the order which they are listed.
	// +optional
	Transforms []FederationDomainTransform `json:"transforms,omitempty"`
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
	Issuer string `json:"issuer"`

	// TLS configures how this FederationDomain is served over Transport Layer Security (TLS).
	// +optional
	TLS *FederationDomainTLSSpec `json:"tls,omitempty"`

	// IdentityProviders is the list of identity providers available for use by this FederationDomain.
	// For backwards compatibility with versions of Pinniped which predate support for multiple identity providers,
	// an empty IdentityProviders list will cause the FederationDomain to use all available identity providers which
	// exist in the same namespace, but also to reject all authentication requests when there is more than one identity
	// provider currently defined. In this backwards compatibility mode, the name of the identity provider resource
	// (e.g. the Name of an OIDCIdentityProvider resource) will be used as the name of the identity provider in this
	// FederationDomain. This mode is provided to make upgrading from older versions easier. However, instead of
	// relying on this backwards compatibility mode, please consider this mode to be deprecated and please instead
	// explicitly list the identity provider using this IdentityProviders field.
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
	// Status holds an enum that describes the state of this OIDC Provider. Note that this Status can
	// represent success or failure.
	// +optional
	Status FederationDomainStatusCondition `json:"status,omitempty"`

	// Message provides human-readable details about the Status.
	// +optional
	Message string `json:"message,omitempty"`

	// LastUpdateTime holds the time at which the Status was last updated. It is a pointer to get
	// around some undesirable behavior with respect to the empty metav1.Time value (see
	// https://github.com/kubernetes/kubernetes/issues/86811).
	// +optional
	LastUpdateTime *metav1.Time `json:"lastUpdateTime,omitempty"`

	// Secrets contains information about this OIDC Provider's secrets.
	// +optional
	Secrets FederationDomainSecrets `json:"secrets,omitempty"`
}

// FederationDomain describes the configuration of an OIDC provider.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=pinniped
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
