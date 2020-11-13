// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package callback provides a handler for the OIDC callback endpoint.
package callback

import (
	"net/http"

	"go.pinniped.dev/internal/httputil/httperr"
)

func NewHandler() http.Handler {
	return httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != http.MethodGet {
			return httperr.Newf(http.StatusMethodNotAllowed, "%s (try GET)", r.Method)
		}

		return nil
	})
}
