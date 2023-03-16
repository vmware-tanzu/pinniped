// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"context"
	"fmt"
	"mime"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"

	"go.pinniped.dev/internal/testutil/tlsassertions"
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

func RequireNumberOfSecretsExcludingLabelSelector(t *testing.T, secrets v1.SecretInterface, labelSet labels.Set, expectedNumberOfSecrets int) {
	t.Helper()

	selector := labels.Everything()
	for k, v := range labelSet {
		requirement, err := labels.NewRequirement(k, selection.NotEquals, []string{v})
		require.NoError(t, err)
		selector = selector.Add(*requirement)
	}

	storedAuthcodeSecrets, err := secrets.List(context.Background(), v12.ListOptions{
		LabelSelector: selector.String(),
	})
	require.NoError(t, err)
	require.Len(t, storedAuthcodeSecrets.Items, expectedNumberOfSecrets)
}

func RequireSecurityHeadersWithFormPostPageCSPs(t *testing.T, response *httptest.ResponseRecorder) {
	// Loosely confirm that the unique CSPs needed for the form_post page were used.
	cspHeader := response.Header().Get("Content-Security-Policy")
	require.Contains(t, cspHeader, "script-src '") // loose assertion
	require.Contains(t, cspHeader, "style-src '")  // loose assertion
	require.Contains(t, cspHeader, "img-src data:")
	require.Contains(t, cspHeader, "connect-src *")

	// Also require all the usual security headers.
	requireSecurityHeaders(t, response)
}

func RequireSecurityHeadersWithLoginPageCSPs(t *testing.T, response *httptest.ResponseRecorder) {
	// Loosely confirm that the unique CSPs needed for the login page were used.
	cspHeader := response.Header().Get("Content-Security-Policy")
	require.Contains(t, cspHeader, "style-src '")      // loose assertion
	require.NotContains(t, cspHeader, "script-src")    // only needed by form_post page
	require.NotContains(t, cspHeader, "img-src data:") // only needed by form_post page
	require.NotContains(t, cspHeader, "connect-src *") // only needed by form_post page

	// Also require all the usual security headers.
	requireSecurityHeaders(t, response)
}

func RequireSecurityHeadersWithoutCustomCSPs(t *testing.T, response *httptest.ResponseRecorder) {
	// Confirm that the unique CSPs needed for the form_post or login page were NOT used.
	cspHeader := response.Header().Get("Content-Security-Policy")
	require.NotContains(t, cspHeader, "script-src")
	require.NotContains(t, cspHeader, "style-src")
	require.NotContains(t, cspHeader, "img-src data:")
	require.NotContains(t, cspHeader, "connect-src *")

	// Also require all the usual security headers.
	requireSecurityHeaders(t, response)
}

func requireSecurityHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	// Loosely confirm that the generic default CSPs were used.
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

type RequireErrorStringFunc func(t *testing.T, actualErrorStr string)

// RequireErrorStringFromErr can be used to make assertions about errors in tests.
func RequireErrorStringFromErr(t *testing.T, actualError error, requireFunc RequireErrorStringFunc) {
	require.Error(t, actualError)
	requireFunc(t, actualError.Error())
}

// RequireErrorString can be used to make assertions about error strings in tests.
func RequireErrorString(t *testing.T, actualErrorStr string, requireFunc RequireErrorStringFunc) {
	requireFunc(t, actualErrorStr)
}

// WantExactErrorString can be used to set up an expected value for an error string in a test table.
// Use when you want to express that the expected string must be an exact match.
func WantExactErrorString(wantErrStr string) RequireErrorStringFunc {
	return func(t *testing.T, actualErrorStr string) {
		require.Equal(t, wantErrStr, actualErrorStr)
	}
}

// WantSprintfErrorString can be used to set up an expected value for an error string in a test table.
// Use when you want to express that an expected string built using fmt.Sprintf semantics must be an exact match.
func WantSprintfErrorString(wantErrSprintfSpecifier string, a ...interface{}) RequireErrorStringFunc {
	wantErrStr := fmt.Sprintf(wantErrSprintfSpecifier, a...)
	return func(t *testing.T, actualErrorStr string) {
		require.Equal(t, wantErrStr, actualErrorStr)
	}
}

// WantMatchingErrorString can be used to set up an expected value for an error string in a test table.
// Use when you want to express that the expected regexp must be a match.
func WantMatchingErrorString(wantErrRegexp string) RequireErrorStringFunc {
	return func(t *testing.T, actualErrorStr string) {
		require.Regexp(t, wantErrRegexp, actualErrorStr)
	}
}

// WantX509UntrustedCertErrorString can be used to set up an expected value for an error string in a test table.
// expectedErrorFormatString must contain exactly one formatting verb, which should usually be %s, which will
// be replaced by the platform-specific X509 untrusted certs error string and then compared against expectedCommonName.
func WantX509UntrustedCertErrorString(expectedErrorFormatSpecifier string, expectedCommonName string) RequireErrorStringFunc {
	// Starting in Go 1.18.1, and until it was fixed in Go 1.19.5, Go on MacOS had an incorrect error string.
	// We don't care which error string was returned, as long as it is either the normal error string from
	// the Go x509 library, or the error string that was accidentally returned from the Go x509 library in
	// those versions of Go on MacOS which had the bug.
	return func(t *testing.T, actualErrorStr string) {
		// This is the MacOS error string starting in Go 1.18.1, and until it was fixed in Go 1.19.5.
		macOSErr := fmt.Sprintf(`x509: “%s” certificate is not trusted`, expectedCommonName)
		// This is the normal Go x509 library error string.
		standardErr := `x509: certificate signed by unknown authority`
		allowedErrorStrings := []string{
			fmt.Sprintf(expectedErrorFormatSpecifier, tlsassertions.GetTLSErrorPrefix()+macOSErr),
			fmt.Sprintf(expectedErrorFormatSpecifier, tlsassertions.GetTLSErrorPrefix()+standardErr),
		}
		// Allow either.
		require.Contains(t, allowedErrorStrings, actualErrorStr)
	}
}
