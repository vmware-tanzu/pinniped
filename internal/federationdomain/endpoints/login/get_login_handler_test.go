// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/federationdomain/endpoints/login/loginhtml"
	"go.pinniped.dev/internal/federationdomain/idplister"
	"go.pinniped.dev/internal/federationdomain/oidc"
	"go.pinniped.dev/internal/federationdomain/stateparam"
	"go.pinniped.dev/internal/testutil"
)

func TestGetLogin(t *testing.T) {
	const (
		testPath         = "/some/path/login"
		testUpstreamName = "some-ldap-idp"
		testUpstreamType = "ldap"
		testEncodedState = "fake-encoded-state-value"
	)

	tests := []struct {
		name            string
		decodedState    *oidc.UpstreamStateParamData
		encodedState    stateparam.Encoded
		errParam        string
		idps            idplister.UpstreamIdentityProvidersLister
		wantStatus      int
		wantContentType string
		wantBody        string
	}{
		{
			name: "Happy path ldap",
			decodedState: &oidc.UpstreamStateParamData{
				UpstreamName: testUpstreamName,
				UpstreamType: testUpstreamType,
			},
			encodedState:    testEncodedState, // the encoded and decoded state don't match, but that verification is handled one level up.
			wantStatus:      http.StatusOK,
			wantContentType: htmlContentType,
			wantBody:        testutil.ExpectedLoginPageHTML(loginhtml.CSS(), testUpstreamName, testPath, testEncodedState, ""), // no alert message
		},
		{
			name: "displays error banner when err=login_error param is sent",
			decodedState: &oidc.UpstreamStateParamData{
				UpstreamName: testUpstreamName,
				UpstreamType: testUpstreamType,
			},
			encodedState:    testEncodedState,
			errParam:        "login_error",
			wantStatus:      http.StatusOK,
			wantContentType: htmlContentType,
			wantBody: testutil.ExpectedLoginPageHTML(loginhtml.CSS(), testUpstreamName, testPath, testEncodedState,
				"Incorrect username or password.",
			),
		},
		{
			name: "displays error banner when err=internal_error param is sent",
			decodedState: &oidc.UpstreamStateParamData{
				UpstreamName: testUpstreamName,
				UpstreamType: testUpstreamType,
			},
			encodedState:    testEncodedState,
			errParam:        "internal_error",
			wantStatus:      http.StatusOK,
			wantContentType: htmlContentType,
			wantBody: testutil.ExpectedLoginPageHTML(loginhtml.CSS(), testUpstreamName, testPath, testEncodedState,
				"An internal error occurred. Please contact your administrator for help.",
			),
		},
		{
			// If we get an error that we don't recognize, that's also an error, so we
			// should probably just tell you to contact your administrator...
			name: "displays generic error banner when unrecognized err param is sent",
			decodedState: &oidc.UpstreamStateParamData{
				UpstreamName: testUpstreamName,
				UpstreamType: testUpstreamType,
			},
			encodedState:    testEncodedState,
			errParam:        "some_other_error",
			wantStatus:      http.StatusOK,
			wantContentType: htmlContentType,
			wantBody: testutil.ExpectedLoginPageHTML(loginhtml.CSS(), testUpstreamName, testPath, testEncodedState,
				"An internal error occurred. Please contact your administrator for help.",
			),
		},
	}

	for _, test := range tests {
		tt := test

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := NewGetHandler(testPath)
			target := testPath + "?state=" + tt.encodedState.String()
			if tt.errParam != "" {
				target += "&err=" + tt.errParam
			}
			req := httptest.NewRequest(http.MethodGet, target, nil)
			rsp := httptest.NewRecorder()
			err := handler(rsp, req, tt.encodedState, tt.decodedState)
			require.NoError(t, err)

			require.Equal(t, tt.wantStatus, rsp.Code)
			testutil.RequireEqualContentType(t, rsp.Header().Get("Content-Type"), tt.wantContentType)
			body := rsp.Body.String()
			// t.Log("actual body:", body) // useful when updating expected values
			require.Equal(t, tt.wantBody, body)
		})
	}
}
