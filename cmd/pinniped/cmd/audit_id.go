// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"net/http"

	"go.pinniped.dev/internal/httputil/roundtripper"
	"go.pinniped.dev/internal/plog"
)

type auditIDLoggerFunc func(path string, statusCode int, auditID string)

func logAuditID(path string, statusCode int, auditID string) {
	plog.Info("Received auditID for failed request",
		"path", path,
		"statusCode", statusCode,
		"auditID", auditID)
}

func LogAuditIDTransportWrapper(rt http.RoundTripper) http.RoundTripper {
	return logAuditIDTransportWrapper(rt, logAuditID)
}

func logAuditIDTransportWrapper(rt http.RoundTripper, auditIDLoggerFunc auditIDLoggerFunc) http.RoundTripper {
	return roundtripper.WrapFunc(rt, func(r *http.Request) (*http.Response, error) {
		response, responseErr := rt.RoundTrip(r)

		if responseErr != nil ||
			response == nil ||
			response.Header.Get("audit-ID") == "" ||
			response.Request == nil ||
			response.Request.URL == nil {
			return response, responseErr
		}

		// Use the request path from the response's request, in case the
		// original request was modified by any other roudtrippers in the chain.
		auditIDLoggerFunc(response.Request.URL.Path,
			response.StatusCode,
			response.Header.Get("audit-ID"))

		return response, responseErr
	})
}
