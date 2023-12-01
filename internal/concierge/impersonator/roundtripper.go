// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonator

import (
	"errors"
	"fmt"
	"net/http"

	utilnet "k8s.io/apimachinery/pkg/util/net"

	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/tokenclient"
)

type authorizationRoundTripper struct {
	cache tokenclient.ExpiringSingletonTokenCacheGet
	base  http.RoundTripper
}

var _ utilnet.RoundTripperWrapper = (*authorizationRoundTripper)(nil)

func (rt *authorizationRoundTripper) WrappedRoundTripper() http.RoundTripper {
	return rt.base
}

func (rt *authorizationRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = utilnet.CloneRequest(req)

	token := rt.cache.Get()

	if token == "" {
		plog.Error("could not RoundTrip impersonation proxy request to API server",
			errors.New("no service account token available in in-memory cache"))

		return nil, fmt.Errorf("no impersonator service account token available")
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	return rt.base.RoundTrip(req)
}
