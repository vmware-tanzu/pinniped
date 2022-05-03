// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"context"
	"mime"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

func RequireTimeInDelta(t *testing.T, t1 time.Time, t2 time.Time, delta time.Duration) {
	require.InDeltaf(t,
		float64(t1.UnixNano()),
		float64(t2.UnixNano()),
		float64(delta.Nanoseconds()),
		"expected %s and %s to be < %s apart, but they are %s apart",
		t1.Format(time.RFC3339Nano),
		t2.Format(time.RFC3339Nano),
		delta.String(),
		t1.Sub(t2).String(),
	)
}

func RequireEqualContentType(t *testing.T, actual string, expected string) {
	t.Helper()

	if expected == "" {
		require.Empty(t, actual)
		return
	}

	actualContentType, actualContentTypeParams, err := mime.ParseMediaType(expected)
	require.NoError(t, err)
	expectedContentType, expectedContentTypeParams, err := mime.ParseMediaType(expected)
	require.NoError(t, err)
	require.Equal(t, actualContentType, expectedContentType)
	require.Equal(t, actualContentTypeParams, expectedContentTypeParams)
}

func RequireNumberOfSecretsMatchingLabelSelector(t *testing.T, secrets v1.SecretInterface, labelSet labels.Set, expectedNumberOfSecrets int) {
	t.Helper()
	storedAuthcodeSecrets, err := secrets.List(context.Background(), v12.ListOptions{
		LabelSelector: labelSet.String(),
	})
	require.NoError(t, err)
	require.Len(t, storedAuthcodeSecrets.Items, expectedNumberOfSecrets)
}

func RequireSecurityHeadersWithFormPostCSPs(t *testing.T, response *httptest.ResponseRecorder) {
	// Loosely confirm that the unique CSPs needed for the form_post page were used.
	cspHeader := response.Header().Get("Content-Security-Policy")
	require.Contains(t, cspHeader, "script-src '") // loose assertion
	require.Contains(t, cspHeader, "style-src '")  // loose assertion
	require.Contains(t, cspHeader, "img-src data:")
	require.Contains(t, cspHeader, "connect-src *")

	// Also require all the usual security headers.
	requireSecurityHeaders(t, response)
}

func RequireSecurityHeadersWithoutFormPostCSPs(t *testing.T, response *httptest.ResponseRecorder) {
	// Confirm that the unique CSPs needed for the form_post page were NOT used.
	cspHeader := response.Header().Get("Content-Security-Policy")
	require.NotContains(t, cspHeader, "script-src")
	require.NotContains(t, cspHeader, "style-src")
	require.NotContains(t, cspHeader, "img-src data:")
	require.NotContains(t, cspHeader, "connect-src *")

	// Also require all the usual security headers.
	requireSecurityHeaders(t, response)
}

func requireSecurityHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	// Loosely confirm that the generic CSPs were used.
	cspHeader := response.Header().Get("Content-Security-Policy")
	require.Contains(t, cspHeader, "default-src 'none'")
	require.Contains(t, cspHeader, "frame-ancestors 'none'")

	require.Equal(t, "DENY", response.Header().Get("X-Frame-Options"))
	require.Equal(t, "1; mode=block", response.Header().Get("X-XSS-Protection"))
	require.Equal(t, "nosniff", response.Header().Get("X-Content-Type-Options"))
	require.Equal(t, "no-referrer", response.Header().Get("Referrer-Policy"))
	require.Equal(t, "off", response.Header().Get("X-DNS-Prefetch-Control"))
	require.Equal(t, "no-cache", response.Header().Get("Pragma"))
	require.Equal(t, "0", response.Header().Get("Expires"))

	// This check is more relaxed since Fosite can override the base header we set.
	require.Contains(t, response.Header().Get("Cache-Control"), "no-store")
}
