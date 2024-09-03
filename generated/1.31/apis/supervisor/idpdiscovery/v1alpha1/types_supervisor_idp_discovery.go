// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// IDPType are the strings that can be returned by the Supervisor identity provider discovery endpoint
// as the "type" of each returned identity provider.
type IDPType string

// IDPFlow are the strings that can be returned by the Supervisor identity provider discovery endpoint
// in the array of allowed client "flows" for each returned identity provider.
type IDPFlow string

const (
	IDPTypeOIDC            IDPType = "oidc"
	IDPTypeLDAP            IDPType = "ldap"
	IDPTypeActiveDirectory IDPType = "activedirectory"
	IDPTypeGitHub          IDPType = "github"

	IDPFlowCLIPassword     IDPFlow = "cli_password"
	IDPFlowBrowserAuthcode IDPFlow = "browser_authcode"
)

// Equals is a convenience function for comparing an IDPType to a string.
func (r IDPType) Equals(s string) bool {
	return string(r) == s
}

// String is a convenience function to convert an IDPType to a string.
func (r IDPType) String() string {
	return string(r)
}

// Equals is a convenience function for comparing an IDPFlow to a string.
func (r IDPFlow) Equals(s string) bool {
	return string(r) == s
}

// String is a convenience function to convert an IDPFlow to a string.
func (r IDPFlow) String() string {
	return string(r)
}

// OIDCDiscoveryResponse is part of the response from a FederationDomain's OpenID Provider Configuration
// Document returned by the .well-known/openid-configuration endpoint. It ignores all the standard OpenID Provider
// configuration metadata and only picks out the portion related to Supervisor identity provider discovery.
type OIDCDiscoveryResponse struct {
	SupervisorDiscovery OIDCDiscoveryResponseIDPEndpoint `json:"discovery.supervisor.pinniped.dev/v1alpha1"`
}

// OIDCDiscoveryResponseIDPEndpoint contains the URL for the identity provider discovery endpoint.
type OIDCDiscoveryResponseIDPEndpoint struct {
	PinnipedIDPsEndpoint string `json:"pinniped_identity_providers_endpoint"`
}

// IDPDiscoveryResponse is the response of a FederationDomain's identity provider discovery endpoint.
type IDPDiscoveryResponse struct {
	PinnipedIDPs              []PinnipedIDP              `json:"pinniped_identity_providers"`
	PinnipedSupportedIDPTypes []PinnipedSupportedIDPType `json:"pinniped_supported_identity_provider_types"`
}

// PinnipedIDP describes a single identity provider as included in the response of a FederationDomain's
// identity provider discovery endpoint.
type PinnipedIDP struct {
	Name  string    `json:"name"`
	Type  IDPType   `json:"type"`
	Flows []IDPFlow `json:"flows,omitempty"`
}

// PinnipedSupportedIDPType describes a single identity provider type.
type PinnipedSupportedIDPType struct {
	Type IDPType `json:"type"`
}
