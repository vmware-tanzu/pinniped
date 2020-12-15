// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package securityheader

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWrap(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello world"))
	})
	rec := httptest.NewRecorder()
	Wrap(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "hello world", rec.Body.String())
	require.EqualValues(t, http.Header{
		"Content-Security-Policy": []string{"default-src 'none'; frame-ancestors 'none'"},
		"Content-Type":            []string{"text/plain; charset=utf-8"},
		"Referrer-Policy":         []string{"no-referrer"},
		"X-Content-Type-Options":  []string{"nosniff"},
		"X-Frame-Options":         []string{"DENY"},
		"X-Xss-Protection":        []string{"1; mode=block"},
		"X-Dns-Prefetch-Control":  []string{"off"},
		"Cache-Control":           []string{"no-cache", "no-store", "max-age=0", "must-revalidate"},
		"Pragma":                  []string{"no-cache"},
		"Expires":                 []string{"0"},
	}, rec.Header())
}
