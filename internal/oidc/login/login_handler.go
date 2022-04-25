// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"net/http"
)

// NewHandler returns an http.Handler that serves the login endpoint for IDPs that
//  don't have their own Web UI.
func NewHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `Method not allowed (try GET)`, http.StatusMethodNotAllowed)
			return
		}
		_, err := w.Write([]byte("<p>hello world</p>"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}
