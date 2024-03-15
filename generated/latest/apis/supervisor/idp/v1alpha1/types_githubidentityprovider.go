// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type GitHubIdentityProviderPhase string

const (
	// GitHubPhasePending is the default phase for newly-created GitHubIdentityProvider resources.
	GitHubPhasePending GitHubIdentityProviderPhase = "Pending"

	// GitHubPhaseReady is the phase for an GitHubIdentityProvider resource in a healthy state.
	GitHubPhaseReady GitHubIdentityProviderPhase = "Ready"

	// GitHubPhaseError is the phase for an GitHubIdentityProvider in an unhealthy state.
	GitHubPhaseError GitHubIdentityProviderPhase = "Error"
)

type GitHubAllowAllUsersToLoginSpec string

const (
	// GitHubAllowAllUsersToLogin means any GitHub user is allowed to log in to this Pinniped,
	// regardless of their organization membership or lack thereof.
	GitHubAllowAllUsersToLogin GitHubAllowAllUsersToLoginSpec = "Allow"

	// GitHubDoNotAllowAllUsersToLogin means only those users with membership in specified GitHub
	// organizations are allowed to log in.
	GitHubDoNotAllowAllUsersToLogin GitHubAllowAllUsersToLoginSpec = "Deny"
)

// GitHubIdentityProviderStatus is the status of an GitHub identity provider.
type GitHubIdentityProviderStatus struct {
	// Phase summarizes the overall status of the GitHubIdentityProvider.
	//
	// +kubebuilder:default=Pending
	// +kubebuilder:validation:Enum=Pending;Ready;Error
	Phase GitHubIdentityProviderPhase `json:"phase,omitempty"`

	// Conditions represents the observations of an identity provider's current state.
	//
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// GitHubApiConfig allows configuration for GitHub Enterprise Server
type GitHubApiConfig struct {
	// Host is required only for GitHub Enterprise Server.
	// Defaults to using GitHub's public API (github.com).
	// +optional
	Host string `json:"host,omitempty"`

	// TLS configuration for GitHub Enterprise Server.
	// +optional
	TLS *TLSSpec `json:"tls,omitempty"`
}

// GitHubUsernameClaimSpec allows the user to specify which attribute(s) from GitHub to use for the downstream username.
// See the response for https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28#get-the-authenticated-user.
type GitHubUsernameClaimSpec string

const (
	// GitHubUsernameId specifies using the `id` attribute from GitHub as the downstream username.
	GitHubUsernameId GitHubUsernameClaimSpec = "id"

	// GitHubUsernameLogin specifies using the `login` attribute from GitHub as the downstream username.
	GitHubUsernameLogin GitHubUsernameClaimSpec = "login"

	// GitHubUsernameLoginAndId specifies combining the `login` and `id` attributes from GitHub as the
	// downstream username, separated by a colon. Example: "my-login:1234"
	GitHubUsernameLoginAndId GitHubUsernameClaimSpec = "login:id"
)

// GitHubGroupNamesSpec allows the user to specify which attribute from GitHub to use for the downstream groups.
// See the response for https://docs.github.com/en/rest/teams/teams?apiVersion=2022-11-28#list-teams-for-the-authenticated-user.
type GitHubGroupNamesSpec string

const (
	// GitHubGroupsAsNames specifies using the `name` attribute from GitHub as the downstream group names
	GitHubGroupsAsNames GitHubGroupNamesSpec = "name"

	// GitHubGroupsAsSlugs specifies using the `slug` attribute from GitHub as the downstream group names
	GitHubGroupsAsSlugs GitHubGroupNamesSpec = "slug"
)

// GitHubClaims allows customization of the username and groups claims
type GitHubClaims struct {
	// Username configures which property of the GitHub user record shall determine the username in Kubernetes.
	//
	// Can be either "id", "login", or "login:id". Defaults to "login:id".
	//
	// GitHub's user login attributes can only contain alphanumeric characters and non-repeating hyphens,
	// and may not start or end with hyphens. GitHub users are allowed to change their login name,
	// although it is inconvenient. If a GitHub user changed their login name from "foo" to "bar",
	// then a second user might change their name from "baz" to "foo" in order to take the old
	// username of the first user. For this reason, it is not as safe to make authorization decisions
	// based only on the user's login attribute.
	//
	// If desired, an admin could configure identity transformation expressions on a FederationDomain to
	// further customize how these usernames are presented to Kubernetes.
	//
	// Defaults to "login:id", which is the user login attribute, followed by a colon, followed by the unique and
	// unchanging integer ID number attribute. This blends human-readable login names with the unchanging ID value
	// from GitHub. Note that colons are not allowed in GitHub login attributes or ID numbers, so the colon in the
	// "login:id" name will always be the login:id separator colon.
	//
	// +kubebuilder:default="login:id"
	// +kubebuilder:validation:Enum={"id","login","login:id"}
	Username GitHubUsernameClaimSpec `json:"username"`

	// Groups configures which property of the GitHub team record shall determine the group names in Kubernetes.
	//
	// Can be either "name" or "slug". Defaults to "slug".
	//
	// GitHub team names can contain upper and lower case characters, whitespace, and punctuation (e.g. "Kube admins!").
	//
	// GitHub team slugs are lower case alphanumeric characters and may contain dashes (e.g. "kube-admins").
	//
	// Either way, group names as presented to Kubernetes will always be prefixed by the GitHub organization
	// name followed by a forward slash (e.g. "my-org/my-team"). GitHub organization login names can only contain
	// alphanumeric characters or single hyphens, so the first forward slash `/` will be the separator between
	// the organization login name and the team name or slug.
	//
	// If desired, an admin could configure identity transformation expressions on a FederationDomain to
	// further customize how these group names are presented to Kubernetes.
	//
	// +kubebuilder:default=slug
	// +kubebuilder:validation:Enum=name;slug
	Groups GitHubGroupNamesSpec `json:"groups"`
}

// GitHubClientSpec contains information about the GitHub client that this identity provider will use
// for web-based login flows.
type GitHubClientSpec struct {
	// SecretName contains the name of a namespace-local Secret object that provides the clientID and
	// clientSecret for an GitHub App or GitHub OAuth2 client.
	//
	// This secret must be of type "secrets.pinniped.dev/github-client" with keys "clientID" and "clientSecret".
	SecretName string `json:"secretName"`
}

// GitHubIdentityProviderSpec is the spec for configuring an GitHub identity provider.
type GitHubIdentityProviderSpec struct {
	// GitHubApi allows configuration for GitHub Enterprise Server
	//
	// +optional
	GitHubApi GitHubApiConfig `json:"github_api,omitempty"`

	// Claims allows customization of the username and groups claims
	//
	// +optional
	Claims GitHubClaims `json:"claims,omitempty"`

	// AllowedOrganizations, when specified, indicates that only users with membership in at least one of the listed
	// GitHub organizations may log in. In addition, the group membership presented to Kubernetes
	// will only include teams within the listed GitHub organizations. Additional login rules or group filtering
	// can optionally be provided as policy expression on any FederationDomain that includes this IDP.
	//
	// The configured GitHub App or GitHub OAuth App must be allowed to see membership in the listed organizations,
	// otherwise Pinniped will not be aware that the user belongs to the listed organization or any teams
	// within that organization.
	//
	// If no organizations are listed, you must set allowAllUsersToLogin to "Allow".
	//
	// +optional
	AllowedOrganizations []string `json:"allowedOrganizations"`

	// AllowAllUsersToLogin must be set to "Allow" if allowedOrganizations is empty.
	//
	// This field only exists to ensure that Pinniped administrators are aware that an empty list of
	// allowedOrganizations means all GitHub users are allowed to log in.
	//
	// +kubebuilder:default=Deny
	// +kubebuilder:validation:Enum=Allow;Deny
	AllowAllUsersToLogin GitHubAllowAllUsersToLoginSpec `json:"allowAllUsersToLogin"`

	// Client identifies the secret with credentials for a GitHub App or GitHub OAuth2 App (a GitHub client).
	Client GitHubClientSpec `json:"client"`
}

// GitHubIdentityProvider describes the configuration of an upstream GitHub identity provider.
// This upstream provider can be configured with either a GitHub App or a GitHub OAuth2 App.
//
// Right now, only web-based logins are supported, for both the pinniped-cli client and dynamic clients.
//
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=pinniped;pinniped-idp;pinniped-idps
// +kubebuilder:printcolumn:name="Issuer",type=string,JSONPath=`.spec.issuer`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:subresource:status
type GitHubIdentityProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec for configuring the identity provider.
	Spec GitHubIdentityProviderSpec `json:"spec"`

	// Status of the identity provider.
	Status GitHubIdentityProviderStatus `json:"status,omitempty"`
}

// GitHubIdentityProviderList lists GitHubIdentityProvider objects.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type GitHubIdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []GitHubIdentityProvider `json:"items"`
}
