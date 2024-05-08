// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package securityheader

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrap(t *testing.T) {
	for _, tt := range []struct {
		name          string
		wrapFunc      func(http.Handler) http.Handler
		expectHeaders http.Header
	}{
		{
			name:     "wrap",
			wrapFunc: Wrap,
			expectHeaders: http.Header{
				"X-Test-Header":           []string{"test value"},
				"Content-Security-Policy": []string{"default-src 'none'; frame-ancestors 'none'"},
				"Content-Type":            []string{"text/plain; charset=utf-8"},
				"Referrer-Policy":         []string{"no-referrer"},
				"X-Content-Type-Options":  []string{"nosniff"},
				"X-Frame-Options":         []string{"DENY"},
				"X-Xss-Protection":        []string{"1; mode=block"},
				"X-Dns-Prefetch-Control":  []string{"off"},
				"Cache-Control":           []string{"no-cache,no-store,max-age=0,must-revalidate"},
				"Pragma":                  []string{"no-cache"},
				"Expires":                 []string{"0"},
			},
		},
		{
			name:     "custom CSP",
			wrapFunc: func(h http.Handler) http.Handler { return WrapWithCustomCSP(h, "my-custom-csp-header") },
			expectHeaders: http.Header{
				"X-Test-Header":           []string{"test value"},
				"Content-Security-Policy": []string{"my-custom-csp-header"},
				"Content-Type":            []string{"text/plain; charset=utf-8"},
				"Referrer-Policy":         []string{"no-referrer"},
				"X-Content-Type-Options":  []string{"nosniff"},
				"X-Frame-Options":         []string{"DENY"},
				"X-Xss-Protection":        []string{"1; mode=block"},
				"X-Dns-Prefetch-Control":  []string{"off"},
				"Cache-Control":           []string{"no-cache,no-store,max-age=0,must-revalidate"},
				"Pragma":                  []string{"no-cache"},
				"Expires":                 []string{"0"},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testServer := httptest.NewServer(tt.wrapFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Test-Header", "test value")
				_, _ = w.Write([]byte("hello world"))
			})))
			t.Cleanup(testServer.Close)

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, testServer.URL, nil)
			require.NoError(t, err)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)

			respBody, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, "hello world", string(respBody))

			for key, values := range tt.expectHeaders {
				assert.Equalf(t, values, resp.Header.Values(key), "unexpected values for header %s", key)
			}
		})
	}
}
