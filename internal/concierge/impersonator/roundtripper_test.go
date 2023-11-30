// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonator

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"go.pinniped.dev/internal/tokenclient"
)

func TestWrappedRoundTripper(t *testing.T) {
	var base = new(oauth2.Transport)

	roundTripper := authorizationRoundTripper{
		base: base,
	}

	require.Equal(t, base, roundTripper.WrappedRoundTripper())
}

type fakeRoundTripper struct {
	request  *http.Request
	response *http.Response
	err      error
}

func (t *fakeRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	t.request = request
	return t.response, t.err
}

var _ http.RoundTripper = (*fakeRoundTripper)(nil)

type fakeCache struct {
	token string
}

func (c *fakeCache) Get() string {
	return c.token
}

var _ tokenclient.ExpiringSingletonTokenCacheGet = (*fakeCache)(nil)

func TestRoundTrip(t *testing.T) {
	fakeResponse := new(http.Response)
	for _, tt := range []struct {
		name         string
		token        string
		baseResponse *http.Response
		baseError    string
		wantResponse *http.Response
		wantError    string
	}{
		{
			name:         "happy path - mutate the request and return whatever the base returns",
			token:        "token",
			baseResponse: fakeResponse,
			baseError:    "error from base",
			wantResponse: fakeResponse,
			wantError:    "error from base",
		},
		{
			name:      "no token available",
			token:     "", // since the cache always returns a non-pointer string, this indicates empty
			wantError: "no impersonator service account token available",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			base := &fakeRoundTripper{
				response: new(http.Response),
				err:      errors.New(tt.baseError),
			}

			cache := &fakeCache{
				token: tt.token,
			}

			roundTripper := &authorizationRoundTripper{
				cache: cache,
				base:  base,
			}

			request, err := http.NewRequestWithContext(context.Background(), "GET", "https://example.com", http.NoBody)
			require.NoError(t, err)

			//nolint:bodyclose // response.Body is nil so you can't call .Close() on it
			response, err := roundTripper.RoundTrip(request)
			require.Equal(t, tt.wantResponse, response)
			require.ErrorContains(t, err, tt.wantError)

			if tt.token != "" {
				require.Equal(t, "Bearer "+tt.token, base.request.Header.Get("Authorization"))
			} else {
				require.Empty(t, base.request)
			}
		})
	}
}
