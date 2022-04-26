// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"net/http"

	"go.pinniped.dev/internal/oidc"
)

func NewGetHandler(upstreamIDPs oidc.UpstreamIdentityProvidersLister) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, encodedState string, decodedState *oidc.UpstreamStateParamData) error {
		// TODO
		return nil
	}
}
