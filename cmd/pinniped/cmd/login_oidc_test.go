// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/oidc/pkce"
	"go.pinniped.dev/internal/oidc/state"
)

func TestLoginOIDCCommand(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		args       []string
		wantError  bool
		wantStdout string
		wantStderr string
	}{
		{
			name: "help flag passed",
			args: []string{"--help"},
			wantStdout: here.Doc(`
				Login using an OpenID Connect provider

				Usage:
				  oidc --issuer ISSUER --client-id CLIENT_ID [flags]

				Flags:
					  --client-id string     OpenID Connect client ID.
				  -h, --help                 help for oidc
					  --issuer string        OpenID Connect issuer URL.
					  --listen-port uint16   TCP port for localhost listener (authorization code flow only). (default 48095)
					  --scopes strings       OIDC scopes to request during login. (default [offline_access,openid,email,profile])
					  --skip-browser         Skip opening the browser (just print the URL).
			`),
		},
		{
			name:      "missing required flags",
			args:      []string{},
			wantError: true,
			wantStdout: here.Doc(`
				Error: required flag(s) "client-id", "issuer" not set
			`),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cmd := (&oidcLoginParams{}).cmd()
			require.NotNil(t, cmd)

			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantStdout, stdout.String(), "unexpected stdout")
			require.Equal(t, tt.wantStderr, stderr.String(), "unexpected stderr")
		})
	}
}

func TestOIDCLoginRunE(t *testing.T) {
	t.Parallel()

	// Start a server that returns 500 errors.
	brokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}))
	t.Cleanup(brokenServer.Close)

	// Start a server that returns successfully.
	var validResponse string
	validServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(validResponse))
	}))
	t.Cleanup(validServer.Close)
	validResponse = strings.ReplaceAll(here.Docf(`
		{
		  "issuer": "${ISSUER}",
		  "authorization_endpoint": "${ISSUER}/auth",
		  "token_endpoint": "${ISSUER}/token",
		  "jwks_uri": "${ISSUER}/keys",
		  "userinfo_endpoint": "${ISSUER}/userinfo",
		  "grant_types_supported": ["authorization_code","refresh_token"],
		  "response_types_supported": ["code"],
		  "id_token_signing_alg_values_supported": ["RS256"],
		  "scopes_supported": ["openid","email","groups","profile","offline_access"],
		  "token_endpoint_auth_methods_supported": ["client_secret_basic"],
		  "claims_supported": ["aud","email","email_verified","exp","iat","iss","locale","name","sub"]
		}
	`), "${ISSUER}", validServer.URL)
	validServerURL, err := url.Parse(validServer.URL)
	require.NoError(t, err)

	tests := []struct {
		name              string
		params            oidcLoginParams
		wantError         string
		wantStdout        string
		wantStderr        string
		wantStderrAuthURL func(*testing.T, *url.URL)
	}{
		{
			name: "broken discovery",
			params: oidcLoginParams{
				issuer: brokenServer.URL,
			},
			wantError: fmt.Sprintf("could not perform OIDC discovery for %q: 500 Internal Server Error: Internal Server Error\n", brokenServer.URL),
		},
		{
			name: "broken state generation",
			params: oidcLoginParams{
				issuer:        validServer.URL,
				generateState: func() (state.State, error) { return "", fmt.Errorf("some error generating a state value") },
			},
			wantError: "could not generate OIDC state parameter: some error generating a state value",
		},
		{
			name: "broken PKCE generation",
			params: oidcLoginParams{
				issuer:        validServer.URL,
				generateState: func() (state.State, error) { return "test-state", nil },
				generatePKCE:  func() (pkce.Code, error) { return "", fmt.Errorf("some error generating a PKCE code") },
			},
			wantError: "could not generate OIDC PKCE parameter: some error generating a PKCE code",
		},
		{
			name: "broken browser open",
			params: oidcLoginParams{
				issuer:        validServer.URL,
				generateState: func() (state.State, error) { return "test-state", nil },
				generatePKCE:  func() (pkce.Code, error) { return "test-pkce", nil },
				openURL:       func(_ string) error { return fmt.Errorf("some browser open error") },
			},
			wantError: "could not open browser (run again with --skip-browser?): some browser open error",
		},
		{
			name: "success",
			params: oidcLoginParams{
				issuer:        validServer.URL,
				clientID:      "test-client-id",
				generateState: func() (state.State, error) { return "test-state", nil },
				generatePKCE:  func() (pkce.Code, error) { return "test-pkce", nil },
				listenPort:    12345,
				skipBrowser:   true,
			},
			wantStderrAuthURL: func(t *testing.T, actual *url.URL) {
				require.Equal(t, validServerURL.Host, actual.Host)
				require.Equal(t, "/auth", actual.Path)
				require.Equal(t, "", actual.Fragment)

				require.Equal(t, url.Values{
					"access_type":           []string{"offline"},
					"client_id":             []string{"test-client-id"},
					"redirect_uri":          []string{"http://localhost:12345/callback"},
					"response_type":         []string{"code"},
					"state":                 []string{"test-state"},
					"code_challenge_method": []string{"S256"},
					// This is the PKCE challenge which is calculated as base64(sha256("test-pkce")). For example:
					// $ echo -n test-pkce | shasum -a 256 | cut -d" " -f1 | xxd -r -p | base64 | cut -d"=" -f1
					// VVaezYqum7reIhoavCHD1n2d+piN3r/mywoYj7fCR7g
					"code_challenge": []string{"VVaezYqum7reIhoavCHD1n2d-piN3r_mywoYj7fCR7g"},
				}, actual.Query())
			},
			wantStderr: "Please log in: <URL>\n",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			cmd := cobra.Command{RunE: tt.params.runE, SilenceUsage: true, SilenceErrors: true}
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			err := cmd.Execute()
			if tt.wantError != "" {
				require.EqualError(t, err, tt.wantError)
			} else {
				require.NoError(t, err)
			}

			if tt.wantStderrAuthURL != nil {
				var urls []string
				redacted := regexp.MustCompile(`http://\S+`).ReplaceAllStringFunc(stderr.String(), func(url string) string {
					urls = append(urls, url)
					return "<URL>"
				})
				require.Lenf(t, urls, 1, "expected to find authorization URL in stderr:\n%s", stderr.String())
				authURL, err := url.Parse(urls[0])
				require.NoError(t, err, "invalid authorization URL")
				tt.wantStderrAuthURL(t, authURL)

				// Replace the stderr buffer with the redacted version.
				stderr.Reset()
				stderr.WriteString(redacted)
			}

			require.Equal(t, tt.wantStdout, stdout.String(), "unexpected stdout")
			require.Equal(t, tt.wantStderr, stderr.String(), "unexpected stderr")
		})
	}
}
