// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package callback

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCallbackEndpoint(t *testing.T) {
	tests := []struct {
		name string

		method string

		wantStatus int
		wantBody   string
	}{
		// Happy path
		// TODO: GET with good state and cookie and successful upstream token exchange and 302 to downstream client callback with its state and code

		// Pre-upstream-exchange verification
		{
			name:       "PUT method is invalid",
			method:     http.MethodPut,
			wantStatus: http.StatusMethodNotAllowed,
			wantBody:   "Method Not Allowed: PUT (try GET)\n",
		},
		// TODO: POST/PATCH/DELETE is invalid
		// TODO: request has body? maybe we don't need to do anything...
		// TODO: code does not exist
		// TODO: we got called twice with the same state and cookie...is this bad? might be ok if the client's first roundtrip failed
		// TODO: we got called twice with the same state and cookie and the UpstreamOIDCProvider CRD has been deleted
		// TODO: state does not exist
		// TODO: invalid signature on state
		// TODO: state is expired (the expiration is encoded in the state itself)
		// TODO: state csrf value does not match csrf cookie
		// TODO: cookie does not exist
		// TODO: invalid signature on cookie
		// TODO: state version does not match what we want

		// Upstream exchange
		// TODO: we can't figure out what the upstream token endpoint is (do we get this UpstreamOIDCProvider name from the path?)
		// TODO: network call to upstream token endpoint fails
		// TODO: the upstream token endpoint returns an error

		// Post-upstream-exchange verification
		// TODO: returned tokens are invalid (all the stuff from the spec...)
		// TODO: there
		// TODO: are
		// TODO: probably
		// TODO: a
		// TODO: lot
		// TODO: of
		// TODO: test
		// TODO: cases
		// TODO: here (e.g., id jwt cannot be verified, nonce is wrong, we didn't get refresh token, we didn't get access token, we didn't get id token, access token expires too quickly)

		// Downstream redirect
		// TODO: cannot generate auth code
		// TODO: cannot persist downstream state
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			subject := NewHandler()
			req := httptest.NewRequest(test.method, "/path-is-not-yet-tested", nil /* body not yet tested */)
			rsp := httptest.NewRecorder()
			subject.ServeHTTP(rsp, req)

			require.Equal(t, test.wantStatus, rsp.Code)
			require.Equal(t, test.wantBody, rsp.Body.String())
		})
	}
}
