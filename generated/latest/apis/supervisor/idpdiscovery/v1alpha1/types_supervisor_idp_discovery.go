// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// SupervisorOIDCDiscoveryResponse is part of the response from a FederationDomain's OpenID Provider Configuration
// Document returned by the .well-known/openid-configuration endpoint. It ignores all the standard OpenID Provider
// configuration metadata and only picks out the portion related to Supervisor identity provider discovery.
type SupervisorOIDCDiscoveryResponse struct {
	SupervisorDiscovery SupervisorOIDCDiscoveryResponseIDPEndpoint `json:"discovery.supervisor.pinniped.dev/v1alpha1"`
}

// SupervisorOIDCDiscoveryResponseIDPEndpoint contains the URL for the identity provider discovery endpoint.
type SupervisorOIDCDiscoveryResponseIDPEndpoint struct {
	PinnipedIDPsEndpoint string `json:"pinniped_identity_providers_endpoint"`
}

// SupervisorIDPDiscoveryResponse is the response of a FederationDomain's identity provider discovery endpoint.
type SupervisorIDPDiscoveryResponse struct {
	PinnipedIDPs []SupervisorPinnipedIDP `json:"pinniped_identity_providers"`
}

// SupervisorPinnipedIDP describes a single identity provider as included in the response of a FederationDomain's
// identity provider discovery endpoint.
type SupervisorPinnipedIDP struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Flows []string `json:"flows,omitempty"`
}
