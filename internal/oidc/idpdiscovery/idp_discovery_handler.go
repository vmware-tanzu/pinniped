// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package idpdiscovery provides a handler for the upstream IDP discovery endpoint.
package idpdiscovery

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sort"

	"go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	"go.pinniped.dev/internal/oidc/provider"
)

// NewHandler returns an http.Handler that serves the upstream IDP discovery endpoint.
func NewHandler(upstreamIDPs provider.FederationDomainIdentityProvidersListerI) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `Method not allowed (try GET)`, http.StatusMethodNotAllowed)
			return
		}

		encodedMetadata, encodeErr := responseAsJSON(upstreamIDPs)
		if encodeErr != nil {
			http.Error(w, encodeErr.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(encodedMetadata); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func responseAsJSON(upstreamIDPs provider.FederationDomainIdentityProvidersListerI) ([]byte, error) {
	r := v1alpha1.IDPDiscoveryResponse{PinnipedIDPs: []v1alpha1.PinnipedIDP{}}

	// The cache of IDPs could change at any time, so always recalculate the list.
	for _, federationDomainIdentityProvider := range upstreamIDPs.GetLDAPIdentityProviders() {
		r.PinnipedIDPs = append(r.PinnipedIDPs, v1alpha1.PinnipedIDP{
			Name:  federationDomainIdentityProvider.DisplayName,
			Type:  v1alpha1.IDPTypeLDAP,
			Flows: []v1alpha1.IDPFlow{v1alpha1.IDPFlowCLIPassword, v1alpha1.IDPFlowBrowserAuthcode},
		})
	}
	for _, federationDomainIdentityProvider := range upstreamIDPs.GetActiveDirectoryIdentityProviders() {
		r.PinnipedIDPs = append(r.PinnipedIDPs, v1alpha1.PinnipedIDP{
			Name:  federationDomainIdentityProvider.DisplayName,
			Type:  v1alpha1.IDPTypeActiveDirectory,
			Flows: []v1alpha1.IDPFlow{v1alpha1.IDPFlowCLIPassword, v1alpha1.IDPFlowBrowserAuthcode},
		})
	}
	for _, federationDomainIdentityProvider := range upstreamIDPs.GetOIDCIdentityProviders() {
		flows := []v1alpha1.IDPFlow{v1alpha1.IDPFlowBrowserAuthcode}
		if federationDomainIdentityProvider.Provider.AllowsPasswordGrant() {
			flows = append(flows, v1alpha1.IDPFlowCLIPassword)
		}
		r.PinnipedIDPs = append(r.PinnipedIDPs, v1alpha1.PinnipedIDP{
			Name:  federationDomainIdentityProvider.DisplayName,
			Type:  v1alpha1.IDPTypeOIDC,
			Flows: flows,
		})
	}

	// Nobody like an API that changes the results unnecessarily. :)
	sort.SliceStable(r.PinnipedIDPs, func(i, j int) bool {
		return r.PinnipedIDPs[i].Name < r.PinnipedIDPs[j].Name
	})

	var b bytes.Buffer
	encodeErr := json.NewEncoder(&b).Encode(&r)
	encodedMetadata := b.Bytes()

	return encodedMetadata, encodeErr
}
