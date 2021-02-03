// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/conciergeclient"
	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
)

func TestLoginOIDCCommand(t *testing.T) {
	cfgDir := mustGetConfigDir()

	testCA, err := certauthority.New(pkix.Name{CommonName: "Test CA"}, 1*time.Hour)
	require.NoError(t, err)
	tmpdir := testutil.TempDir(t)
	testCABundlePath := filepath.Join(tmpdir, "testca.pem")
	require.NoError(t, ioutil.WriteFile(testCABundlePath, testCA.Bundle(), 0600))

	time1 := time.Date(3020, 10, 12, 13, 14, 15, 16, time.UTC)

	tests := []struct {
		name             string
		args             []string
		loginErr         error
		conciergeErr     error
		wantError        bool
		wantStdout       string
		wantStderr       string
		wantOptionsCount int
	}{
		{
			name: "help flag passed",
			args: []string{"--help"},
			wantStdout: here.Doc(`
				Login using an OpenID Connect provider

				Usage:
				  oidc --issuer ISSUER [flags]

				Flags:
				      --ca-bundle strings                     Path to TLS certificate authority bundle (PEM format, optional, can be repeated)
				      --ca-bundle-data strings                Base64 endcoded TLS certificate authority bundle (base64 encoded PEM format, optional, can be repeated)
				      --client-id string                      OpenID Connect client ID (default "pinniped-cli")
				      --concierge-api-group-suffix string     Concierge API group suffix (default "pinniped.dev")
				      --concierge-authenticator-name string   Concierge authenticator name
				      --concierge-authenticator-type string   Concierge authenticator type (e.g., 'webhook', 'jwt')
				      --concierge-ca-bundle-data string       CA bundle to use when connecting to the concierge
				      --concierge-endpoint string             API base for the Pinniped concierge endpoint
				      --concierge-namespace string            Namespace in which the concierge was installed (default "pinniped-concierge")
				      --enable-concierge                      Exchange the OIDC ID token with the Pinniped concierge during login
				  -h, --help                                  help for oidc
				      --issuer string                         OpenID Connect issuer URL
				      --listen-port uint16                    TCP port for localhost listener (authorization code flow only)
				      --request-audience string               Request a token with an alternate audience using RFC8693 token exchange
				      --scopes strings                        OIDC scopes to request during login (default [offline_access,openid,pinniped:request-audience])
				      --session-cache string                  Path to session cache file (default "` + cfgDir + `/sessions.yaml")
				      --skip-browser                          Skip opening the browser (just print the URL)
			`),
		},
		{
			name:      "missing required flags",
			args:      []string{},
			wantError: true,
			wantStderr: here.Doc(`
				Error: required flag(s) "issuer" not set
			`),
		},
		{
			name: "missing concierge flags",
			args: []string{
				"--client-id", "test-client-id",
				"--issuer", "test-issuer",
				"--enable-concierge",
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: invalid concierge parameters: endpoint must not be empty
			`),
		},
		{
			name: "invalid CA bundle path",
			args: []string{
				"--client-id", "test-client-id",
				"--issuer", "test-issuer",
				"--ca-bundle", "./does/not/exist",
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: could not read --ca-bundle: open ./does/not/exist: no such file or directory
			`),
		},
		{
			name: "invalid CA bundle data",
			args: []string{
				"--client-id", "test-client-id",
				"--issuer", "test-issuer",
				"--ca-bundle-data", "invalid-base64",
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: could not read --ca-bundle-data: illegal base64 data at input byte 7
			`),
		},
		{
			name: "invalid api group suffix",
			args: []string{
				"--issuer", "test-issuer",
				"--enable-concierge",
				"--concierge-api-group-suffix", ".starts.with.dot",
				"--concierge-authenticator-type", "jwt",
				"--concierge-authenticator-name", "test-authenticator",
				"--concierge-endpoint", "https://127.0.0.1:1234/",
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: invalid concierge parameters: invalid api group suffix: 1 error(s):
				- a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')
			`),
		},
		{
			name: "login error",
			args: []string{
				"--client-id", "test-client-id",
				"--issuer", "test-issuer",
			},
			loginErr:         fmt.Errorf("some login error"),
			wantOptionsCount: 3,
			wantError:        true,
			wantStderr: here.Doc(`
				Error: could not complete Pinniped login: some login error
			`),
		},
		{
			name: "concierge token exchange error",
			args: []string{
				"--client-id", "test-client-id",
				"--issuer", "test-issuer",
				"--enable-concierge",
				"--concierge-authenticator-type", "jwt",
				"--concierge-authenticator-name", "test-authenticator",
				"--concierge-endpoint", "https://127.0.0.1:1234/",
			},
			conciergeErr:     fmt.Errorf("some concierge error"),
			wantOptionsCount: 3,
			wantError:        true,
			wantStderr: here.Doc(`
				Error: could not complete concierge credential exchange: some concierge error
			`),
		},
		{
			name: "success with minimal options",
			args: []string{
				"--client-id", "test-client-id",
				"--issuer", "test-issuer",
			},
			wantOptionsCount: 3,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "success with all options",
			args: []string{
				"--client-id", "test-client-id",
				"--issuer", "test-issuer",
				"--skip-browser",
				"--listen-port", "1234",
				"--debug-session-cache",
				"--request-audience", "cluster-1234",
				"--ca-bundle-data", base64.StdEncoding.EncodeToString(testCA.Bundle()),
				"--ca-bundle", testCABundlePath,
				"--enable-concierge",
				"--concierge-namespace", "test-namespace",
				"--concierge-authenticator-type", "webhook",
				"--concierge-authenticator-name", "test-authenticator",
				"--concierge-endpoint", "https://127.0.0.1:1234/",
				"--concierge-ca-bundle-data", base64.StdEncoding.EncodeToString(testCA.Bundle()),
				"--concierge-api-group-suffix", "some.suffix.com",
			},
			wantOptionsCount: 7,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{},"status":{"token":"exchanged-token"}}` + "\n",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var (
				gotOptions []oidcclient.Option
			)
			cmd := oidcLoginCommand(oidcLoginCommandDeps{
				login: func(issuer string, clientID string, opts ...oidcclient.Option) (*oidctypes.Token, error) {
					require.Equal(t, "test-issuer", issuer)
					require.Equal(t, "test-client-id", clientID)
					gotOptions = opts
					if tt.loginErr != nil {
						return nil, tt.loginErr
					}
					return &oidctypes.Token{
						IDToken: &oidctypes.IDToken{
							Token:  "test-id-token",
							Expiry: metav1.NewTime(time1),
						},
					}, nil
				},
				exchangeToken: func(ctx context.Context, client *conciergeclient.Client, token string) (*clientauthv1beta1.ExecCredential, error) {
					require.Equal(t, token, "test-id-token")
					if tt.conciergeErr != nil {
						return nil, tt.conciergeErr
					}
					return &clientauthv1beta1.ExecCredential{
						TypeMeta: metav1.TypeMeta{
							Kind:       "ExecCredential",
							APIVersion: "client.authentication.k8s.io/v1beta1",
						},
						Status: &clientauthv1beta1.ExecCredentialStatus{
							Token: "exchanged-token",
						},
					}, nil
				},
			})
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
			require.Len(t, gotOptions, tt.wantOptionsCount)
		})
	}
}
