// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"net/http"

	"go.pinniped.dev/internal/httputil/roundtripper"
	"go.pinniped.dev/internal/plog"
)

func LogAuditIDTransportWrapper(rt http.RoundTripper) http.RoundTripper {
	return roundtripper.WrapFunc(rt, func(r *http.Request) (*http.Response, error) {
		response, responseErr := rt.RoundTrip(r)
		if response != nil && response.Header.Get("audit-ID") != "" {
			plog.Info("Received auditID for request",
				// Use the request path from the response's request, in case the
				// original request was modified by any other roudtrippers in the chain.
				"path", response.Request.URL.Path,
				"statusCode", response.StatusCode,
				"auditID", response.Header.Get("audit-ID"))
		}
		return response, responseErr
	})
}
