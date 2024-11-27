// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/httputil/roundtripper"
)

func TestLogAuditIDTransportWrapper(t *testing.T) {
	canonicalAuditIdHeaderName := "Audit-Id"

	tests := []struct {
		name        string
		response    *http.Response
		responseErr error
		want        func(t *testing.T, called func()) auditIDLoggerFunc
		wantCalled  bool
	}{
		{
			name: "happy HTTP response - no error and no log",
			response: &http.Response{ // no headers
				StatusCode: http.StatusOK,
				Request: &http.Request{
					URL: &url.URL{
						Path: "some-path-from-response-request",
					},
				},
			},
			responseErr: nil,
			want: func(t *testing.T, called func()) auditIDLoggerFunc {
				return func(_ string, _ int, _ string) {
					called()
				}
			},
			wantCalled: false, // make it obvious
		},
		{
			name:        "nil HTTP response - no error and no log",
			response:    nil,
			responseErr: nil,
			want: func(t *testing.T, called func()) auditIDLoggerFunc {
				return func(_ string, _ int, _ string) {
					called()
				}
			},
			wantCalled: false, // make it obvious
		},
		{
			name:        "err HTTP response - no error and no log",
			response:    nil,
			responseErr: errors.New("some error"),
			want: func(t *testing.T, called func()) auditIDLoggerFunc {
				return func(_ string, _ int, _ string) {
					called()
				}
			},
			wantCalled: false, // make it obvious
		},
		{
			name: "happy HTTP response with audit-ID - logs",
			response: &http.Response{
				Header: http.Header{
					canonicalAuditIdHeaderName: []string{"some-audit-id", "some-other-audit-id-that-will-never-be-seen"},
				},
				StatusCode: http.StatusBadGateway, // statusCode does not matter
				Request: &http.Request{
					URL: &url.URL{
						Path: "some-path-from-response-request",
					},
				},
			},
			want: func(t *testing.T, called func()) auditIDLoggerFunc {
				return func(path string, statusCode int, auditID string) {
					called()
					require.Equal(t, "some-path-from-response-request", path)
					require.Equal(t, http.StatusBadGateway, statusCode)
					require.Equal(t, "some-audit-id", auditID)
				}
			},
			wantCalled: true, // make it obvious
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NotNil(t, test.want)

			mockRequest := &http.Request{
				URL: &url.URL{
					Path: "should-never-use-this-path",
				},
			}
			var mockRt roundtripper.Func = func(r *http.Request) (*http.Response, error) {
				require.Equal(t, mockRequest, r)
				return test.response, test.responseErr
			}
			called := false
			subjectRt := logAuditIDTransportWrapper(mockRt, test.want(t, func() {
				called = true
			}))
			actualResponse, err := subjectRt.RoundTrip(mockRequest) //nolint:bodyclose // there is no Body.
			require.Equal(t, test.responseErr, err)                 // This roundtripper only returns mocked errors.
			require.Equal(t, test.response, actualResponse)
			require.Equal(t, test.wantCalled, called,
				"want logFunc to be called: %t, actually was called: %t", test.wantCalled, called)
		})
	}
}
