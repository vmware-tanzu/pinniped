// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"net/http"

	idpdiscoveryv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	"go.pinniped.dev/internal/federationdomain/endpoints/login/loginhtml"
	"go.pinniped.dev/internal/federationdomain/formposthtml"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/stateparam"
	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/httputil/securityheader"
	"go.pinniped.dev/internal/plog"
)

// HandlerFunc is a function that can handle either a GET or POST request for the login endpoint.
type HandlerFunc func(
	w http.ResponseWriter,
	r *http.Request,
	encodedState stateparam.Encoded,
	decodedState *oidc.UpstreamStateParamData,
) error

// NewHandler returns a http.Handler that serves the login endpoint for IDPs that don't have their own web UI for login.
//
// This handler takes care of the shared concerns between the GET and POST methods of the login endpoint:
// checking the method, checking the CSRF cookie, decoding the state param, and adding security headers.
// Then it defers the rest of the handling to the passed in handler functions for GET and POST requests.
// Note that CSRF protection isn't needed on GET requests, but it doesn't hurt. Putting it here
// keeps the implementations and tests of HandlerFunc simpler since they won't need to deal with any decoders.
// Users should always initially get redirected to this page from the authorization endpoint, and never need
// to navigate directly to this page in their browser without going through the authorization endpoint first.
// Once their browser has landed on this page, it should be okay for the user to refresh the browser.
func NewHandler(
	stateDecoder oidc.Decoder,
	cookieDecoder oidc.Decoder,
	getHandler HandlerFunc, // use NewGetHandler() for production
	postHandler HandlerFunc, // use NewPostHandler() for production
	auditLogger plog.AuditLogger,
) http.Handler {
	loginHandler := httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		var handler HandlerFunc
		switch r.Method {
		case http.MethodGet:
			handler = getHandler
		case http.MethodPost:
			handler = postHandler
		default:
			return httperr.Newf(http.StatusMethodNotAllowed, "%s (try GET or POST)", r.Method)
		}

		encodedState, decodedState, err := oidc.ReadStateParamAndValidateCSRFCookie(r, cookieDecoder, stateDecoder)
		if err != nil {
			plog.InfoErr("state or CSRF error", err)
			return err
		}

		auditLogger.Audit(plog.AuditEventAuthorizeIDFromParameters, r.Context(), plog.NoSessionPersisted(),
			"authorizeID", encodedState.AuthorizeID())

		switch decodedState.UpstreamType {
		case string(idpdiscoveryv1alpha1.IDPTypeLDAP), string(idpdiscoveryv1alpha1.IDPTypeActiveDirectory):
			// these are the types supported by this endpoint, so no error here
		default:
			return httperr.Newf(http.StatusBadRequest, "not a supported upstream IDP type for this endpoint: %q", decodedState.UpstreamType)
		}

		return handler(w, r, encodedState, decodedState)
	})

	return wrapSecurityHeaders(loginHandler)
}

func wrapSecurityHeaders(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := securityheader.WrapWithCustomCSP(handler, loginhtml.ContentSecurityPolicy())
		if r.Method == http.MethodPost {
			// POST requests can result in the form_post html page, so allow it with CSP headers.
			wrapped = securityheader.WrapWithCustomCSP(handler, formposthtml.ContentSecurityPolicy())
		}
		wrapped.ServeHTTP(w, r)
	})
}
