// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package callback provides a handler for the OIDC callback endpoint.
package callback

import (
	"net/http"
	"path"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
)

func NewHandler(
	idpListGetter oidc.IDPListGetter,
	stateDecoder, cookieDecoder oidc.Decoder,
) http.Handler {
	return httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if err := validateRequest(r, stateDecoder, cookieDecoder); err != nil {
			return err
		}

		if findUpstreamIDPConfig(r, idpListGetter) == nil {
			plog.Warning("upstream provider not found")
			return httperr.New(http.StatusUnprocessableEntity, "upstream provider not found")
		}

		return nil
	})
}

func validateRequest(r *http.Request, stateDecoder, cookieDecoder oidc.Decoder) error {
	if r.Method != http.MethodGet {
		return httperr.Newf(http.StatusMethodNotAllowed, "%s (try GET)", r.Method)
	}

	csrfValue, err := readCSRFCookie(r, cookieDecoder)
	if err != nil {
		plog.InfoErr("error reading CSRF cookie", err)
		return err
	}

	if r.FormValue("code") == "" {
		plog.Info("code param not found")
		return httperr.New(http.StatusBadRequest, "code param not found")
	}

	if r.FormValue("state") == "" {
		plog.Info("state param not found")
		return httperr.New(http.StatusBadRequest, "state param not found")
	}

	state, err := readState(r, stateDecoder)
	if err != nil {
		plog.InfoErr("error reading state", err)
		return err
	}

	if state.CSRFToken != csrfValue {
		plog.InfoErr("CSRF value does not match", err)
		return httperr.Wrap(http.StatusForbidden, "CSRF value does not match", err)
	}

	return nil
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

func readCSRFCookie(r *http.Request, cookieDecoder oidc.Decoder) (csrftoken.CSRFToken, error) {
	receivedCSRFCookie, err := r.Cookie(oidc.CSRFCookieName)
	if err != nil {
		// Error means that the cookie was not found
		return "", httperr.Wrap(http.StatusForbidden, "CSRF cookie is missing", err)
	}

	var csrfFromCookie csrftoken.CSRFToken
	err = cookieDecoder.Decode(oidc.CSRFCookieEncodingName, receivedCSRFCookie.Value, &csrfFromCookie)
	if err != nil {
		return "", httperr.Wrap(http.StatusForbidden, "error reading CSRF cookie", err)
	}

	return csrfFromCookie, nil
}

func readState(r *http.Request, stateDecoder oidc.Decoder) (*oidc.UpstreamStateParamData, error) {
	var state oidc.UpstreamStateParamData
	if err := stateDecoder.Decode(
		oidc.UpstreamStateParamEncodingName,
		r.FormValue("state"),
		&state,
	); err != nil {
		return nil, httperr.New(http.StatusBadRequest, "error reading state")
	}

	if state.FormatVersion != oidc.UpstreamStateParamFormatVersion {
		return nil, httperr.New(http.StatusUnprocessableEntity, "state format version is invalid")
	}

	return &state, nil
}
