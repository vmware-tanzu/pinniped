package login

import (
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
		happyGetResult   = `<!DOCTYPE html>
<html>
<body>

<h1>Pinniped</h1>
<p>some-ldap-idp</p>

<form action="/login?state=foo" method="post">

    <div>
        <label for="uname"><b>Username</b></label>
        <input type="text" placeholder="Username" name="uname" required>
    </div>

    <div>
        <label for="psw"><b>Password</b></label>
        <input type="password" placeholder="Password" name="psw" required>
    </div>

    <button type="submit">Login</button>

</form>

</body>
</html>`
	)
	tests := []struct {
		name            string
		decodedState    *oidc.UpstreamStateParamData
		encodedState    string
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
			wantBody:        happyGetResult,
		},
	}

	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			handler := NewGetHandler(tt.idps)
			req := httptest.NewRequest(http.MethodGet, "/login", nil)
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
