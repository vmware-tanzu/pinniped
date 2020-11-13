// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package callback provides a handler for the OIDC callback endpoint.
package callback

import (
	"net/http"
	"path"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/provider"
)

func NewHandler(
	idpListGetter oidc.IDPListGetter,
) http.Handler {
	return httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != http.MethodGet {
			return httperr.Newf(http.StatusMethodNotAllowed, "%s (try GET)", r.Method)
		}

		if r.FormValue("code") == "" {
			return httperr.New(http.StatusBadRequest, "code param not found")
		}

		if r.FormValue("state") == "" {
			return httperr.New(http.StatusBadRequest, "state param not found")
		}

		if findUpstreamIDPConfig(r, idpListGetter) == nil {
			return httperr.New(http.StatusUnprocessableEntity, "upstream provider not found")
		}

		return httperr.New(http.StatusBadRequest, "state param not valid")
	})
}

func findUpstreamIDPConfig(r *http.Request, idpListGetter oidc.IDPListGetter) *provider.UpstreamOIDCIdentityProvider {
	_, lastPathComponent := path.Split(r.URL.Path)
	for _, p := range idpListGetter.GetIDPList() {
		if p.Name == lastPathComponent {
			return &p
		}
	}
	return nil
}
