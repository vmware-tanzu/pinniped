// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.pinniped.dev/internal/testutil"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/oidc"
)

func TestGetLogin(t *testing.T) {
	const (
		happyLdapIDPName = "some-ldap-idp"
	)

	tests := []struct {
		name            string
		decodedState    *oidc.UpstreamStateParamData
		encodedState    string
		errParam        string
		idps            oidc.UpstreamIdentityProvidersLister
		wantStatus      int
		wantContentType string
		wantBody        string
	}{
		{
			name: "Happy path ldap",
			decodedState: &oidc.UpstreamStateParamData{
				UpstreamName: happyLdapIDPName,
				UpstreamType: "ldap",
			},
			encodedState:    "foo", // the encoded and decoded state don't match, but that verification is handled one level up.
			wantStatus:      http.StatusOK,
			wantContentType: htmlContentType,
			wantBody:        getHTMLResult(""),
		},
		{
			name: "displays error banner when err=login_error param is sent",
			decodedState: &oidc.UpstreamStateParamData{
				UpstreamName: happyLdapIDPName,
				UpstreamType: "ldap",
			},
			encodedState:    "foo",
			errParam:        "login_error",
			wantStatus:      http.StatusOK,
			wantContentType: htmlContentType,
			wantBody: getHTMLResult(`
    <div class="alert">
        <span>Incorrect username or password.</span>
    </div>
`),
		},
		{
			name: "displays error banner when err=internal_error param is sent",
			decodedState: &oidc.UpstreamStateParamData{
				UpstreamName: happyLdapIDPName,
				UpstreamType: "ldap",
			},
			encodedState:    "foo",
			errParam:        "internal_error",
			wantStatus:      http.StatusOK,
			wantContentType: htmlContentType,
			wantBody: getHTMLResult(`
    <div class="alert">
        <span>An internal error occurred. Please contact your administrator for help.</span>
    </div>
`),
		},
		// If we get an error that we don't recognize, that's also an error, so we
		// should probably just tell you to contact your administrator...
		{
			name: "displays generic error banner when unrecognized err param is sent",
			decodedState: &oidc.UpstreamStateParamData{
				UpstreamName: happyLdapIDPName,
				UpstreamType: "ldap",
			},
			encodedState:    "foo",
			errParam:        "some_other_error",
			wantStatus:      http.StatusOK,
			wantContentType: htmlContentType,
			wantBody: getHTMLResult(`
    <div class="alert">
        <span>An internal error occurred. Please contact your administrator for help.</span>
    </div>
`),
		},
	}

	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			handler := NewGetHandler(tt.idps)
			target := "/some/path/login?state=" + tt.encodedState
			if tt.errParam != "" {
				target += "&err=" + tt.errParam
			}
			req := httptest.NewRequest(http.MethodGet, target, nil)
			rsp := httptest.NewRecorder()
			err := handler(rsp, req, tt.encodedState, tt.decodedState)
			require.NoError(t, err)

			require.Equal(t, test.wantStatus, rsp.Code)
			testutil.RequireEqualContentType(t, rsp.Header().Get("Content-Type"), tt.wantContentType)
			body := rsp.Body.String()
			require.Equal(t, tt.wantBody, body)
		})
	}
}

func getHTMLResult(errorBanner string) string {
	happyGetResult := `<!DOCTYPE html>
<html>
<head>
    <title>Pinniped</title>
</head>
<body>

<h1>Pinniped</h1>
<p>some-ldap-idp</p>
%s
<form action="/some/path/login" method="post" target="_parent">

    <div>
        <label for="username"><b>Username</b></label>
        <input type="text" name="username" id="username" autocomplete="username" required>
    </div>

    <div>
        <label for="password"><b>Password</b></label>
        <input type="password" name="password" id="password current-password" autocomplete="current-password" required>
    </div>

    <div>
        <input type="hidden" name="state" id="state" value="foo">
    </div>

    <button type="submit" name="submit" id="submit">Log in</button>

</form>

</body>
</html>
`
	return fmt.Sprintf(happyGetResult, errorBanner)
}
