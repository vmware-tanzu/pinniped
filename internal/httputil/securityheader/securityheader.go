// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package securityheader implements an HTTP middleware for setting security-related response headers.
package securityheader

import "net/http"

// Wrap the provided http.Handler so it sets appropriate security-related response headers.
func Wrap(wrapped http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "1; mode=block")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-DNS-Prefetch-Control", "off")

		// first overwrite existing Cache-Control header with Set, then append more headers with Add
		h.Set("Cache-Control", "no-cache")
		h.Add("Cache-Control", "no-store")
		h.Add("Cache-Control", "max-age=0")
		h.Add("Cache-Control", "must-revalidate")

		h.Set("Pragma", "no-cache")
		h.Set("Expires", "0")

		wrapped.ServeHTTP(w, r)
	})
}
