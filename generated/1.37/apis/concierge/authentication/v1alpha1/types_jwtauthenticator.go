// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
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

// JWTAuthenticatorStatus is the status of a JWT authenticator.
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

// JWTAuthenticatorSpec is the spec for configuring a JWT authenticator.
type JWTAuthenticatorSpec struct {
	// issuer is the OIDC issuer URL that will be used to discover public signing keys. Issuer is
	// also used to validate the "iss" JWT claim.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://`
	Issuer string `json:"issuer"`

	// audience is the required value of the "aud" JWT claim.
	// +kubebuilder:validation:MinLength=1
	Audience string `json:"audience"`

	// claims allows customization of the claims that will be mapped to user identity
	// for Kubernetes access.
	// +optional
	Claims JWTTokenClaims `json:"claims"`

	// claimValidationRules are rules that are applied to validate token claims to authenticate users.
	// This is similar to claimValidationRules from Kubernetes AuthenticationConfiguration as documented in
	// https://kubernetes.io/docs/reference/access-authn-authz/authentication.
	// This is an advanced configuration option. During an end-user login flow, mistakes in this
	// configuration will cause the user's login to fail.
	// +optional
	ClaimValidationRules []ClaimValidationRule `json:"claimValidationRules,omitempty"`

	// userValidationRules are rules that are applied to final user before completing authentication.
	// These allow invariants to be applied to incoming identities such as preventing the
	// use of the system: prefix that is commonly used by Kubernetes components.
	// The validation rules are logically ANDed together and must all return true for the validation to pass.
	// This is similar to claimValidationRules from Kubernetes AuthenticationConfiguration as documented in
	// https://kubernetes.io/docs/reference/access-authn-authz/authentication.
	// This is an advanced configuration option. During an end-user login flow, mistakes in this
	// configuration will cause the user's login to fail.
	// +optional
	UserValidationRules []UserValidationRule `json:"userValidationRules,omitempty"`

	// tls is the configuration for communicating with the OIDC provider via TLS.
	// +optional
	TLS *TLSSpec `json:"tls,omitempty"`
}

// ClaimValidationRule provides the configuration for a single claim validation rule.
type ClaimValidationRule struct {
	// claim is the name of a required claim.
	// Only string claim keys are supported.
	// Mutually exclusive with expression and message.
	// +optional
	Claim string `json:"claim,omitempty"`

	// requiredValue is the value of a required claim.
	// Only string claim values are supported.
	// If claim is set and requiredValue is not set, the claim must be present with a value set to the empty string.
	// Mutually exclusive with expression and message.
	// +optional
	RequiredValue string `json:"requiredValue,omitempty"`

	// expression represents the expression which will be evaluated by CEL.
	// Must produce a boolean.
	//
	// CEL expressions have access to the contents of the token claims, organized into CEL variable:
	// - 'claims' is a map of claim names to claim values.
	//   For example, a variable named 'sub' can be accessed as 'claims.sub'.
	//   Nested claims can be accessed using dot notation, e.g. 'claims.foo.bar'.
	// Must return true for the validation to pass.
	//
	// Documentation on CEL: https://kubernetes.io/docs/reference/using-api/cel/
	//
	// Mutually exclusive with claim and requiredValue.
	// +optional
	Expression string `json:"expression,omitempty"`

	// message customizes the returned error message when expression returns false.
	// message is a literal string.
	// Mutually exclusive with claim and requiredValue.
	// +optional
	Message string `json:"message,omitempty"`
}

// UserValidationRule provides the configuration for a single user info validation rule.
type UserValidationRule struct {
	// expression represents the expression which will be evaluated by CEL.
	// Must return true for the validation to pass.
	//
	// CEL expressions have access to the contents of UserInfo, organized into CEL variable:
	// - 'user' - authentication.k8s.io/v1, Kind=UserInfo object
	//    Refer to https://github.com/kubernetes/api/blob/release-1.28/authentication/v1/types.go#L105-L122 for the definition.
	//    API documentation: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#userinfo-v1-authentication-k8s-io
	//
	// Documentation on CEL: https://kubernetes.io/docs/reference/using-api/cel/
	//
	// +required
	Expression string `json:"expression"`

	// message customizes the returned error message when rule returns false.
	// message is a literal string.
	// +optional
	Message string `json:"message,omitempty"`
}

// JWTTokenClaims allows customization of the claims that will be mapped to user identity
// for Kubernetes access.
type JWTTokenClaims struct {
	// username is the name of the claim which should be read to extract the
	// username from the JWT token. When not specified, it will default to "username",
	// unless usernameExpression is specified.
	//
	// Mutually exclusive with usernameExpression. Use either username or usernameExpression to
	// determine the user's username from the JWT token.
	// +optional
	Username string `json:"username"`

	// usernameExpression represents an expression which will be evaluated by CEL.
	// The expression's result will become the user's username.
	//
	// usernameExpression is similar to claimMappings.username.expression from Kubernetes AuthenticationConfiguration
	// as documented in https://kubernetes.io/docs/reference/access-authn-authz/authentication.
	// This is an advanced configuration option. During an end-user login flow, each of these CEL expressions
	// must evaluate to the expected type without errors, or else the user's login will fail.
	// Additionally, mistakes in this configuration can cause the users to have unintended usernames.
	//
	// The expression must produce a non-empty string value.
	// If the expression uses 'claims.email', then 'claims.email_verified' must be used in
	// the expression or extra[*].valueExpression or claimValidationRules[*].expression.
	// An example claim validation rule expression that matches the validation automatically
	// applied when username.claim is set to 'email' is 'claims.?email_verified.orValue(true) == true'.
	// By explicitly comparing the value to true, we let type-checking see the result will be a boolean,
	// and to make sure a non-boolean email_verified claim will be caught at runtime.
	//
	// CEL expressions have access to the contents of the token claims, organized into CEL variable:
	// - 'claims' is a map of claim names to claim values.
	//   For example, a variable named 'sub' can be accessed as 'claims.sub'.
	//   Nested claims can be accessed using dot notation, e.g. 'claims.foo.bar'.
	//
	// Documentation on CEL: https://kubernetes.io/docs/reference/using-api/cel/
	//
	// Mutually exclusive with username. Use either username or usernameExpression to
	// determine the user's username from the JWT token.
	// +optional
	UsernameExpression string `json:"usernameExpression,omitempty"`

	// groups is the name of the claim which should be read to extract the user's
	// group membership from the JWT token. When not specified, it will default to "groups",
	// unless groupsExpression is specified.
	//
	// Mutually exclusive with groupsExpression. Use either groups or groupsExpression to
	// determine the user's group membership from the JWT token.
	// +optional
	Groups string `json:"groups"`

	// groupsExpression represents an expression which will be evaluated by CEL.
	// The expression's result will become the user's group memberships.
	//
	// groupsExpression is similar to claimMappings.groups.expression from Kubernetes AuthenticationConfiguration
	// as documented in https://kubernetes.io/docs/reference/access-authn-authz/authentication.
	// This is an advanced configuration option. During an end-user login flow, each of these CEL expressions
	// must evaluate to one of the expected types without errors, or else the user's login will fail.
	// Additionally, mistakes in this configuration can cause the users to have unintended group memberships.
	//
	// The expression must produce a string or string array value.
	//  "", [], and null values are treated as the group mapping not being present.
	//
	// CEL expressions have access to the contents of the token claims, organized into CEL variable:
	// - 'claims' is a map of claim names to claim values.
	//   For example, a variable named 'sub' can be accessed as 'claims.sub'.
	//   Nested claims can be accessed using dot notation, e.g. 'claims.foo.bar'.
	//
	// Documentation on CEL: https://kubernetes.io/docs/reference/using-api/cel/
	//
	// Mutually exclusive with groups. Use either groups or groupsExpression to
	// determine the user's group membership from the JWT token.
	// +optional
	GroupsExpression string `json:"groupsExpression,omitempty"`

	// extra is similar to claimMappings.extra from Kubernetes AuthenticationConfiguration
	// as documented in https://kubernetes.io/docs/reference/access-authn-authz/authentication.
	//
	// However, note that the Pinniped Concierge issues client certificates to users for the purpose
	// of authenticating, and the Kubernetes API server does not have any mechanism for transmitting
	// auth extras via client certificates. When configured, these extras will appear in client
	// certificates issued by the Pinniped Supervisor in the x509 Subject field as Organizational
	// Units (OU). However, when this client certificate is presented to Kubernetes for authentication,
	// Kubernetes will ignore these extras. This is probably only useful if you are using a custom
	// authenticating proxy in front of your Kubernetes API server which can translate these OUs into
	// auth extras, as described by
	// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#authenticating-proxy.
	// This is an advanced configuration option. During an end-user login flow, each of these CEL expressions
	// must evaluate to either a string or an array of strings, or else the user's login will fail.
	//
	// These keys must be a domain-prefixed path (such as "acme.io/foo") and must not contain an equals sign ("=").
	//
	// expression must produce a string or string array value.
	// If the value is empty, the extra mapping will not be present.
	//
	// Documentation on CEL: https://kubernetes.io/docs/reference/using-api/cel/
	//
	// hard-coded extra key/value
	// - key: "acme.io/foo"
	//   valueExpression: "'bar'"
	// This will result in an extra attribute - acme.io/foo: ["bar"]
	//
	// hard-coded key, value copying claim value
	// - key: "acme.io/foo"
	//   valueExpression: "claims.some_claim"
	// This will result in an extra attribute - acme.io/foo: [value of some_claim]
	//
	// hard-coded key, value derived from claim value
	// - key: "acme.io/admin"
	//   valueExpression: '(has(claims.is_admin) && claims.is_admin) ? "true":""'
	// This will result in:
	//  - if is_admin claim is present and true, extra attribute - acme.io/admin: ["true"]
	//  - if is_admin claim is present and false or is_admin claim is not present, no extra attribute will be added
	//
	// +optional
	Extra []ExtraMapping `json:"extra,omitempty"`
}

// ExtraMapping provides the configuration for a single extra mapping.
type ExtraMapping struct {
	// key is a string to use as the extra attribute key.
	// key must be a domain-prefix path (e.g. example.org/foo). All characters before the first "/" must be a valid
	// subdomain as defined by RFC 1123. All characters trailing the first "/" must
	// be valid HTTP Path characters as defined by RFC 3986.
	// key must be lowercase.
	// Required to be unique.
	// Additionally, the key must not contain an equals sign ("=").
	// +required
	Key string `json:"key"`

	// valueExpression is a CEL expression to extract extra attribute value.
	// valueExpression must produce a string or string array value.
	// "", [], and null values are treated as the extra mapping not being present.
	// Empty string values contained within a string array are filtered out.
	//
	// CEL expressions have access to the contents of the token claims, organized into CEL variable:
	// - 'claims' is a map of claim names to claim values.
	//   For example, a variable named 'sub' can be accessed as 'claims.sub'.
	//   Nested claims can be accessed using dot notation, e.g. 'claims.foo.bar'.
	//
	// Documentation on CEL: https://kubernetes.io/docs/reference/using-api/cel/
	//
	// +required
	ValueExpression string `json:"valueExpression"`
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

	// spec for configuring the authenticator.
	Spec JWTAuthenticatorSpec `json:"spec"`

	// status of the authenticator.
	Status JWTAuthenticatorStatus `json:"status,omitempty"`
}

// JWTAuthenticatorList is a list of JWTAuthenticator objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type JWTAuthenticatorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []JWTAuthenticator `json:"items"`
}
