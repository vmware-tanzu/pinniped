/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"context"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func startTestServer(t *testing.T, handler http.HandlerFunc) (string, string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	caBundle := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.TLS.Certificates[0].Certificate[0],
	}))
	return caBundle, server.URL
}

func TestExchangeToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("invalid configuration", func(t *testing.T) {
		t.Parallel()
		for _, tt := range []struct {
			name        string
			caBundle    string
			apiEndpoint string
			wantErr     string
		}{
			{
				name:        "bad URL",
				apiEndpoint: "%@Q$!",
				wantErr:     `invalid API endpoint: parse "%@Q$!": invalid URL escape "%@Q"`,
			},
			{
				name:        "plain HTTP URL",
				apiEndpoint: "http://example.com",
				wantErr:     `invalid API endpoint: protocol must be "https", not "http"`,
			},
			{
				name:        "no CA certs",
				apiEndpoint: "https://example.com",
				caBundle:    "",
				wantErr:     `invalid CA bundle: no certificates found`,
			},
		} {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				got, err := ExchangeToken(ctx, "", tt.caBundle, tt.apiEndpoint)
				require.EqualError(t, err, tt.wantErr)
				require.Nil(t, got)
			})
		}
	})

	t.Run("request creation failure", func(t *testing.T) {
		t.Parallel()
		// Start a test server that doesn't do anything.
		caBundle, endpoint := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {})

		//nolint:staticcheck // ignore "do not pass a nil Context" linter error since that's what we're testing here.
		got, err := ExchangeToken(nil, "", caBundle, endpoint)
		require.EqualError(t, err, `could not build request: net/http: nil Context`)
		require.Nil(t, got)
	})

	t.Run("server error", func(t *testing.T) {
		t.Parallel()
		// Start a test server that returns only 500 errors.
		caBundle, endpoint := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("some server error"))
		})

		got, err := ExchangeToken(ctx, "", caBundle, endpoint)
		require.EqualError(t, err, `login failed: server returned status 500`)
		require.Nil(t, got)
	})

	t.Run("request failure", func(t *testing.T) {
		t.Parallel()

		clientTimeout := 500 * time.Millisecond

		// Start a test server that is slow to respond.
		caBundle, endpoint := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			time.Sleep(2 * clientTimeout)
			_, _ = w.Write([]byte("slow response"))
		})

		// Make a request using short timeout.
		ctx, cancel := context.WithTimeout(ctx, clientTimeout)
		defer cancel()

		got, err := ExchangeToken(ctx, "", caBundle, endpoint)
		require.Error(t, err)
		require.Contains(t, err.Error(), "context deadline exceeded")
		require.Contains(t, err.Error(), "could not login:")
		require.Nil(t, got)
	})

	t.Run("server invalid JSON", func(t *testing.T) {
		t.Parallel()
		// Start a test server that returns only 500 errors.
		caBundle, endpoint := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("not valid json"))
		})

		got, err := ExchangeToken(ctx, "", caBundle, endpoint)
		require.EqualError(t, err, `invalid login response: invalid character 'o' in literal null (expecting 'u')`)
		require.Nil(t, got)
	})

	t.Run("login failure", func(t *testing.T) {
		t.Parallel()
		// Start a test server that returns success but with an error message
		caBundle, endpoint := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`
				{
				  "kind": "LoginRequest",
				  "apiVersion": "placeholder.suzerain-io.github.io/v1alpha1",
				  "metadata": {
					"creationTimestamp": null
				  },
				  "spec": {},
				  "status": {
					"message": "some login failure"
				  }
				}`))
		})

		got, err := ExchangeToken(ctx, "", caBundle, endpoint)
		require.EqualError(t, err, `login failed: some login failure`)
		require.Nil(t, got)
	})

	t.Run("invalid timestamp failure", func(t *testing.T) {
		t.Parallel()
		// Start a test server that returns success but with an error message
		caBundle, endpoint := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`
				{
				  "kind": "LoginRequest",
				  "apiVersion": "placeholder.suzerain-io.github.io/v1alpha1",
				  "metadata": {
					"creationTimestamp": null
				  },
				  "spec": {},
				  "status": {
					"credential": {
					  "expirationTimestamp": "invalid"
					}
				  }
				}`))
		})

		got, err := ExchangeToken(ctx, "", caBundle, endpoint)
		require.EqualError(t, err, `invalid login response: parsing time "invalid" as "2006-01-02T15:04:05Z07:00": cannot parse "invalid" as "2006"`)
		require.Nil(t, got)
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		// Start a test server that returns successfully and asserts various properties of the request.
		caBundle, endpoint := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, "/apis/placeholder.suzerain-io.github.io/v1alpha1/loginrequests", r.URL.Path)
			require.Equal(t, "application/json", r.Header.Get("content-type"))

			body, err := ioutil.ReadAll(r.Body)
			require.NoError(t, err)
			require.JSONEq(t,
				`{
				  "kind": "LoginRequest",
				  "apiVersion": "placeholder.suzerain-io.github.io/v1alpha1",
				  "metadata": {
					"creationTimestamp": null
				  },
				  "spec": {
					"type": "token",
					"token": {
					  "value": "test-token"
					}
				  },
				  "status": {}
				}`,
				string(body),
			)

			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`
				{
				  "kind": "LoginRequest",
				  "apiVersion": "placeholder.suzerain-io.github.io/v1alpha1",
				  "metadata": {
					"creationTimestamp": null
				  },
				  "spec": {},
				  "status": {
					"credential": {
					  "expirationTimestamp": "2020-07-30T15:52:01Z",
					  "token": "test-token",
					  "clientCertificateData": "test-certificate",
					  "clientKeyData": "test-key"
					}
				  }
				}`))
		})

		got, err := ExchangeToken(ctx, "test-token", caBundle, endpoint)
		require.NoError(t, err)
		expires := time.Date(2020, 07, 30, 15, 52, 1, 0, time.UTC)
		require.Equal(t, &Credential{
			ExpirationTimestamp:   &expires,
			Token:                 "test-token",
			ClientCertificateData: "test-certificate",
			ClientKeyData:         "test-key",
		}, got)
	})
}
