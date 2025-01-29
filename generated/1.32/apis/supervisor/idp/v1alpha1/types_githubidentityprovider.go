// Copyright 2024-2025 the Pinniped contributors. All Rights Reserved.
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

type GitHubAllowedAuthOrganizationsPolicy string

const (
	// GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers means any GitHub user is allowed to log in using this identity
	// provider, regardless of their organization membership or lack thereof.
	GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers GitHubAllowedAuthOrganizationsPolicy = "AllGitHubUsers"

	// GitHubAllowedAuthOrganizationsPolicyOnlyUsersFromAllowedOrganizations means only those users with membership in
	// the listed GitHub organizations are allowed to log in.
	GitHubAllowedAuthOrganizationsPolicyOnlyUsersFromAllowedOrganizations GitHubAllowedAuthOrganizationsPolicy = "OnlyUsersFromAllowedOrganizations"
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

// GitHubAPIConfig allows configuration for GitHub Enterprise Server
type GitHubAPIConfig struct {
	// Host is required only for GitHub Enterprise Server.
	// Defaults to using GitHub's public API ("github.com").
	// For convenience, specifying "github.com" is equivalent to specifying "api.github.com".
	// Do not specify a protocol or scheme since "https://" will always be used.
	// Port is optional. Do not specify a path, query, fragment, or userinfo.
	// Only specify domain name or IP address, subdomains (optional), and port (optional).
	// IPv4 and IPv6 are supported. If using an IPv6 address with a port, you must enclose the IPv6 address
	// in square brackets. Example: "[::1]:443".
	//
	// +kubebuilder:default="github.com"
	// +kubebuilder:validation:MinLength=1
	// +optional
	Host *string `json:"host"`

	// TLS configuration for GitHub Enterprise Server.
	// Note that this field should not be needed when using GitHub's public API ("github.com").
	// However, if you choose to specify this field when using GitHub's public API, you must
	// specify a CA bundle that will verify connections to "api.github.com".
	//
	// +optional
	TLS *TLSSpec `json:"tls,omitempty"`
}

// GitHubUsernameAttribute allows the user to specify which attribute(s) from GitHub to use for the username to present
// to Kubernetes. See the response schema for
// [Get the authenticated user](https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28#get-the-authenticated-user).
type GitHubUsernameAttribute string

const (
	// GitHubUsernameID specifies using the `id` attribute from the GitHub user for the username to present to Kubernetes.
	GitHubUsernameID GitHubUsernameAttribute = "id"

	// GitHubUsernameLogin specifies using the `login` attribute from the GitHub user as the username to present to Kubernetes.
	GitHubUsernameLogin GitHubUsernameAttribute = "login"

	// GitHubUsernameLoginAndID specifies combining the `login` and `id` attributes from the GitHub user as the
	// username to present to Kubernetes, separated by a colon. Example: "my-login:1234"
	GitHubUsernameLoginAndID GitHubUsernameAttribute = "login:id"
)

// GitHubGroupNameAttribute allows the user to specify which attribute from GitHub to use for the group
// names to present to Kubernetes. See the response schema for
// [List teams for the authenticated user](https://docs.github.com/en/rest/teams/teams?apiVersion=2022-11-28#list-teams-for-the-authenticated-user).
type GitHubGroupNameAttribute string

const (
	// GitHubUseTeamNameForGroupName specifies using the GitHub team's `name` attribute as the group name to present to Kubernetes.
	GitHubUseTeamNameForGroupName GitHubGroupNameAttribute = "name"

	// GitHubUseTeamSlugForGroupName specifies using the GitHub team's `slug` attribute as the group name to present to Kubernetes.
	GitHubUseTeamSlugForGroupName GitHubGroupNameAttribute = "slug"
)

// GitHubClaims allows customization of the username and groups claims.
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
	// If desired, an admin could configure identity transformation expressions on the Pinniped Supervisor's
	// FederationDomain to further customize how these usernames are presented to Kubernetes.
	//
	// Defaults to "login:id", which is the user login attribute, followed by a colon, followed by the unique and
	// unchanging integer ID number attribute. This blends human-readable login names with the unchanging ID value
	// from GitHub. Colons are not allowed in GitHub login attributes or ID numbers, so this is a reasonable
	// choice to concatenate the two values.
	//
	// See the response schema for
	// [Get the authenticated user](https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28#get-the-authenticated-user).
	//
	// +kubebuilder:default="login:id"
	// +kubebuilder:validation:Enum={"id","login","login:id"}
	// +optional
	Username *GitHubUsernameAttribute `json:"username"`

	// Groups configures which property of the GitHub team record shall determine the group names in Kubernetes.
	//
	// Can be either "name" or "slug". Defaults to "slug".
	//
	// GitHub team names can contain upper and lower case characters, whitespace, and punctuation (e.g. "Kube admins!").
	//
	// GitHub team slugs are lower case alphanumeric characters and may contain dashes and underscores (e.g. "kube-admins").
	//
	// Group names as presented to Kubernetes will always be prefixed by the GitHub organization name followed by a
	// forward slash (e.g. "my-org/my-team"). GitHub organization login names can only contain alphanumeric characters
	// or single hyphens, so the first forward slash `/` will be the separator between the organization login name and
	// the team name or slug.
	//
	// If desired, an admin could configure identity transformation expressions on the Pinniped Supervisor's
	// FederationDomain to further customize how these group names are presented to Kubernetes.
	//
	// See the response schema for
	// [List teams for the authenticated user](https://docs.github.com/en/rest/teams/teams?apiVersion=2022-11-28#list-teams-for-the-authenticated-user).
	//
	// +kubebuilder:default=slug
	// +kubebuilder:validation:Enum=name;slug
	// +optional
	Groups *GitHubGroupNameAttribute `json:"groups"`
}

// GitHubClientSpec contains information about the GitHub client that this identity provider will use
// for web-based login flows.
type GitHubClientSpec struct {
	// SecretName contains the name of a namespace-local Secret object that provides the clientID and
	// clientSecret for an GitHub App or GitHub OAuth2 client.
	//
	// This secret must be of type "secrets.pinniped.dev/github-client" with keys "clientID" and "clientSecret".
	//
	// +kubebuilder:validation:MinLength=1
	SecretName string `json:"secretName"`
}

type GitHubOrganizationsSpec struct {
	// Allowed values are "OnlyUsersFromAllowedOrganizations" or "AllGitHubUsers".
	// Defaults to "OnlyUsersFromAllowedOrganizations".
	//
	// Must be set to "AllGitHubUsers" if the allowed field is empty.
	//
	// This field only exists to ensure that Pinniped administrators are aware that an empty list of
	// allowedOrganizations means all GitHub users are allowed to log in.
	//
	// +kubebuilder:default=OnlyUsersFromAllowedOrganizations
	// +kubebuilder:validation:Enum=OnlyUsersFromAllowedOrganizations;AllGitHubUsers
	// +optional
	Policy *GitHubAllowedAuthOrganizationsPolicy `json:"policy"`

	// Allowed, when specified, indicates that only users with membership in at least one of the listed
	// GitHub organizations may log in. In addition, the group membership presented to Kubernetes will only include
	// teams within the listed GitHub organizations. Additional login rules or group filtering can optionally be
	// provided as policy expression on any Pinniped Supervisor FederationDomain that includes this IDP.
	//
	// The configured GitHub App or GitHub OAuth App must be allowed to see membership in the listed organizations,
	// otherwise Pinniped will not be aware that the user belongs to the listed organization or any teams
	// within that organization.
	//
	// If no organizations are listed, you must set organizations: AllGitHubUsers.
	//
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	// +optional
	Allowed []string `json:"allowed,omitempty"`
}

// GitHubAllowAuthenticationSpec allows customization of who can authenticate using this IDP and how.
type GitHubAllowAuthenticationSpec struct {
	// Organizations allows customization of which organizations can authenticate using this IDP.
	// +kubebuilder:validation:XValidation:message="spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed",rule="!(has(self.allowed) && size(self.allowed) > 0 && self.policy == 'AllGitHubUsers')"
	// +kubebuilder:validation:XValidation:message="spec.allowAuthentication.organizations.policy must be 'AllGitHubUsers' when spec.allowAuthentication.organizations.allowed is empty",rule="!((!has(self.allowed) || size(self.allowed) == 0) && self.policy == 'OnlyUsersFromAllowedOrganizations')"
	Organizations GitHubOrganizationsSpec `json:"organizations"`
}

// GitHubIdentityProviderSpec is the spec for configuring an GitHub identity provider.
type GitHubIdentityProviderSpec struct {
	// GitHubAPI allows configuration for GitHub Enterprise Server
	//
	// +kubebuilder:default={}
	GitHubAPI GitHubAPIConfig `json:"githubAPI,omitempty"`

	// Claims allows customization of the username and groups claims.
	//
	// +kubebuilder:default={}
	Claims GitHubClaims `json:"claims,omitempty"`

	// AllowAuthentication allows customization of who can authenticate using this IDP and how.
	AllowAuthentication GitHubAllowAuthenticationSpec `json:"allowAuthentication"`

	// Client identifies the secret with credentials for a GitHub App or GitHub OAuth2 App (a GitHub client).
	Client GitHubClientSpec `json:"client"`
}

// GitHubIdentityProvider describes the configuration of an upstream GitHub identity provider.
// This upstream provider can be configured with either a GitHub App or a GitHub OAuth2 App.
//
// Right now, only web-based logins are supported, for both the pinniped-cli client and clients configured
// as OIDCClients.
//
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=pinniped;pinniped-idp;pinniped-idps
// +kubebuilder:printcolumn:name="Host",type=string,JSONPath=`.spec.githubAPI.host`
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
