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
)

// Decoder is the decoding side of the securecookie.Codec interface.
type Decoder interface {
	Decode(name, value string, into interface{}) error
}

func NewHandler(
	idpListGetter oidc.IDPListGetter,
	cookieDecoder Decoder,
) http.Handler {
	return httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != http.MethodGet {
			return httperr.Newf(http.StatusMethodNotAllowed, "%s (try GET)", r.Method)
		}

		_, err := readCSRFCookie(r, cookieDecoder)
		if err != nil {
			return err
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

func readCSRFCookie(r *http.Request, cookieDecoder Decoder) (csrftoken.CSRFToken, error) {
	receivedCSRFCookie, err := r.Cookie(oidc.CSRFCookieName)
	if err != nil {
		// Error means that the cookie was not found
		return "", httperr.Wrap(http.StatusForbidden, "unauthorized request", err)
	}

	var csrfFromCookie csrftoken.CSRFToken
	err = cookieDecoder.Decode(oidc.CSRFCookieEncodingName, receivedCSRFCookie.Value, &csrfFromCookie)
	if err != nil {
		return "", httperr.Wrap(http.StatusForbidden, "unauthorized request", err)
	}

	return csrfFromCookie, nil
}
