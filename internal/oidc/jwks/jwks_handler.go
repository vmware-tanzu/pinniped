// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package discovery provides a handler for the OIDC discovery endpoint.
package jwks

import (
	"encoding/json"
	"net/http"
)

// NewHandler returns an http.Handler that serves an OIDC JWKS endpoint for a specific issuer.
func NewHandler(issuerName string, provider DynamicJWKSProvider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodGet {
			http.Error(w, `Method not allowed (try GET)`, http.StatusMethodNotAllowed)
			return
		}

		jwks, _ := provider.GetJWKS(issuerName)

		if jwks == nil {
			http.Error(w, "JWKS not found for requested issuer", http.StatusNotFound)
			return
		}

		if err := json.NewEncoder(w).Encode(&jwks); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}
