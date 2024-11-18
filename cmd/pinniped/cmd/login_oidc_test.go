// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	clocktesting "k8s.io/utils/clock/testing"

	idpdiscoveryv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/mocks/mockoidcclientoptions"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/pkg/conciergeclient"
	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
)

func TestLoginOIDCCommand(t *testing.T) {
	cfgDir := mustGetConfigDir()

	testCA, err := certauthority.New("Test CA", 1*time.Hour)
	require.NoError(t, err)
	tmpdir := t.TempDir()
	testCABundlePath := filepath.Join(tmpdir, "testca.pem")
	require.NoError(t, os.WriteFile(testCABundlePath, testCA.Bundle(), 0600))

	time1 := time.Date(3020, 10, 12, 13, 14, 15, 16, time.UTC)

	now, err := time.Parse(time.RFC3339Nano, "2028-10-11T23:37:26.953313745Z")
	require.NoError(t, err)
	nowStr := now.Local().Format(time.RFC1123)

	defaultWantedOptions := func(f *mockoidcclientoptions.MockOIDCClientOptions) {
		f.EXPECT().WithContext(gomock.Any())
		f.EXPECT().WithLoginLogger(gomock.Any())
		f.EXPECT().WithScopes([]string{oidcapi.ScopeOfflineAccess, oidcapi.ScopeOpenID, oidcapi.ScopeRequestAudience, oidcapi.ScopeUsername, oidcapi.ScopeGroups})
		f.EXPECT().WithSessionCache(gomock.Any())
	}

	tests := []struct {
		name             string
		args             []string
		loginErr         error
		conciergeErr     error
		env              map[string]string
		wantError        bool
		wantStdout       string
		wantStderr       string
		wantOptions      func(f *mockoidcclientoptions.MockOIDCClientOptions)
		wantOptionsCount int
		wantLogs         []string
	}{
		{
			name: "help flag passed",
			args: []string{"--help"},
			wantStdout: here.Doc(`
				Login using an OpenID Connect provider

				Use "pinniped get kubeconfig" to generate a kubeconfig file which includes this
				login command in its configuration. This login command is not meant to be
				invoked directly by a user.

				This login command is a Kubernetes client-go credential plugin which is meant to
				be configured inside a kubeconfig file. (See the Kubernetes authentication
				documentation for more information about client-go credential plugins.)

				Usage:
				  oidc --issuer ISSUER [flags]

				Flags:
				      --ca-bundle strings                        Path to TLS certificate authority bundle (PEM format, optional, can be repeated)
				      --ca-bundle-data strings                   Base64 encoded TLS certificate authority bundle (base64 encoded PEM format, optional, can be repeated)
				      --client-id string                         OpenID Connect client ID (default "pinniped-cli")
				      --concierge-api-group-suffix string        Concierge API group suffix (default "pinniped.dev")
				      --concierge-authenticator-name string      Concierge authenticator name
				      --concierge-authenticator-type string      Concierge authenticator type (e.g., 'webhook', 'jwt')
				      --concierge-ca-bundle-data string          CA bundle to use when connecting to the Concierge
				      --concierge-endpoint string                API base for the Concierge endpoint
				      --credential-cache string                  Path to cluster-specific credentials cache ("" disables the cache) (default "` + cfgDir + `/credentials.yaml")
				      --enable-concierge                         Use the Concierge to login
				  -h, --help                                     help for oidc
				      --issuer string                            OpenID Connect issuer URL
				      --listen-port uint16                       TCP port for localhost listener (authorization code flow only)
				      --request-audience string                  Request a token with an alternate audience using RFC8693 token exchange
				      --scopes strings                           OIDC scopes to request during login (default [offline_access,openid,pinniped:request-audience,username,groups])
				      --session-cache string                     Path to session cache file (default "` + cfgDir + `/sessions.yaml")
				      --skip-browser                             Skip opening the browser (just print the URL)
					  --upstream-identity-provider-flow string   The type of client flow to use with the upstream identity provider during login with a Supervisor (e.g. 'browser_authcode', 'cli_password')
					  --upstream-identity-provider-name string   The name of the upstream identity provider used during login with a Supervisor
					  --upstream-identity-provider-type string   The type of the upstream identity provider used during login with a Supervisor (e.g. 'oidc', 'ldap', 'activedirectory', 'github') (default "oidc")
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
			wantOptions: defaultWantedOptions,
			wantError:   true,
			wantStderr: here.Doc(`
				Error: invalid Concierge parameters: endpoint must not be empty
			`),
		},
		{
			name: "invalid CA bundle path",
			args: []string{
				"--client-id", "test-client-id",
				"--issuer", "test-issuer",
				"--ca-bundle", "./does/not/exist",
			},
			wantOptions: defaultWantedOptions,
			wantError:   true,
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
			wantOptions: defaultWantedOptions,
			wantError:   true,
			wantStderr: here.Doc(`
				Error: could not read --ca-bundle-data: illegal base64 data at input byte 7
			`),
		},
		{
			name: "invalid API group suffix",
			args: []string{
				"--issuer", "test-issuer",
				"--enable-concierge",
				"--concierge-api-group-suffix", ".starts.with.dot",
				"--concierge-authenticator-type", "jwt",
				"--concierge-authenticator-name", "test-authenticator",
				"--concierge-endpoint", "https://127.0.0.1:1234/",
			},
			wantOptions: defaultWantedOptions,
			wantError:   true,
			wantStderr: here.Doc(`
				Error: invalid Concierge parameters: invalid API group suffix: a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')
			`),
		},
		{
			name: "oidc upstream type with default flow is allowed",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "oidc",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			wantOptions:      defaultWantedOptions,
			wantOptionsCount: 4,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "PINNIPED_SKIP_PRINT_LOGIN_URL adds an option",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "oidc",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			env: map[string]string{"PINNIPED_SKIP_PRINT_LOGIN_URL": "true"},
			wantOptions: func(f *mockoidcclientoptions.MockOIDCClientOptions) {
				defaultWantedOptions(f)
				f.EXPECT().WithSkipPrintLoginURL()
			},
			wantOptionsCount: 5,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "--upstream-identity-provider-flow adds an option",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-flow", "cli_password",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			wantOptions: func(f *mockoidcclientoptions.MockOIDCClientOptions) {
				defaultWantedOptions(f)
				f.EXPECT().WithLoginFlow(idpdiscoveryv1alpha1.IDPFlowCLIPassword, "--upstream-identity-provider-flow")
			},
			wantOptionsCount: 5,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW adds an option that overrides --upstream-identity-provider-flow",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-flow", "ignored-value-from-param",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			env: map[string]string{"PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW": "actual-value-from-env"},
			wantOptions: func(f *mockoidcclientoptions.MockOIDCClientOptions) {
				defaultWantedOptions(f)
				f.EXPECT().WithLoginFlow(idpdiscoveryv1alpha1.IDPFlow("actual-value-from-env"), "PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW")
			},
			wantOptionsCount: 5,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "login error",
			args: []string{
				"--client-id", "test-client-id",
				"--issuer", "test-issuer",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			loginErr:         fmt.Errorf("some login error"),
			wantOptions:      defaultWantedOptions,
			wantOptionsCount: 4,
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
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			conciergeErr:     fmt.Errorf("some concierge error"),
			wantOptions:      defaultWantedOptions,
			wantOptionsCount: 4,
			wantError:        true,
			wantStderr: here.Doc(`
				Error: could not complete Concierge credential exchange: some concierge error
			`),
		},
		{
			name: "success with minimal options",
			args: []string{
				"--client-id", "test-client-id",
				"--issuer", "test-issuer",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			env:              map[string]string{"PINNIPED_DEBUG": "true"},
			wantOptions:      defaultWantedOptions,
			wantOptionsCount: 4,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
			wantLogs: []string{
				nowStr + `  cmd/login_oidc.go:268  Performing OIDC login  {"issuer": "test-issuer", "client id": "test-client-id"}`,
				nowStr + `  cmd/login_oidc.go:288  No concierge configured, skipping token credential exchange`,
			},
		},
		{
			name: "success with all options",
			args: []string{
				"--client-id", "test-client-id",
				"--issuer", "test-issuer",
				"--skip-browser",
				"--skip-listen",
				"--listen-port", "1234",
				"--debug-session-cache",
				"--request-audience", "cluster-1234",
				"--ca-bundle-data", base64.StdEncoding.EncodeToString(testCA.Bundle()),
				"--ca-bundle", testCABundlePath,
				"--enable-concierge",
				"--concierge-authenticator-type", "webhook",
				"--concierge-authenticator-name", "test-authenticator",
				"--concierge-endpoint", "https://127.0.0.1:1234/",
				"--concierge-ca-bundle-data", base64.StdEncoding.EncodeToString(testCA.Bundle()),
				"--concierge-api-group-suffix", "some.suffix.com",
				"--credential-cache", t.TempDir() + "/credentials.yaml", // must specify --credential-cache or else the cache file on disk causes test pollution
				"--upstream-identity-provider-name", "some-upstream-name",
				"--upstream-identity-provider-type", "ldap",
				"--upstream-identity-provider-flow", "some-flow-type",
			},
			env: map[string]string{"PINNIPED_DEBUG": "true", "PINNIPED_SKIP_PRINT_LOGIN_URL": "true"},
			wantOptions: func(f *mockoidcclientoptions.MockOIDCClientOptions) {
				f.EXPECT().WithContext(gomock.Any())
				f.EXPECT().WithLoginLogger(gomock.Any())
				f.EXPECT().WithScopes([]string{oidcapi.ScopeOfflineAccess, oidcapi.ScopeOpenID, oidcapi.ScopeRequestAudience, oidcapi.ScopeUsername, oidcapi.ScopeGroups})
				f.EXPECT().WithSessionCache(gomock.Any())
				f.EXPECT().WithListenPort(uint16(1234))
				f.EXPECT().WithSkipBrowserOpen()
				f.EXPECT().WithSkipListen()
				f.EXPECT().WithSkipPrintLoginURL()
				f.EXPECT().WithClient(gomock.Any())
				f.EXPECT().WithRequestAudience("cluster-1234")
				f.EXPECT().WithLoginFlow(idpdiscoveryv1alpha1.IDPFlow("some-flow-type"), "--upstream-identity-provider-flow")
				f.EXPECT().WithUpstreamIdentityProvider("some-upstream-name", "ldap")
			},
			wantOptionsCount: 12,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"token":"exchanged-token"}}` + "\n",
			wantLogs: []string{
				nowStr + `  cmd/login_oidc.go:268  Performing OIDC login  {"issuer": "test-issuer", "client id": "test-client-id"}`,
				nowStr + `  cmd/login_oidc.go:278  Exchanging token for cluster credential  {"endpoint": "https://127.0.0.1:1234/", "authenticator type": "webhook", "authenticator name": "test-authenticator"}`,
				nowStr + `  cmd/login_oidc.go:286  Successfully exchanged token for cluster credential.`,
				nowStr + `  cmd/login_oidc.go:293  caching cluster credential for future use.`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			ctx := plog.AddZapOverridesToContext(context.Background(), t, &buf, nil, clocktesting.NewFakeClock(now))

			ctrl := gomock.NewController(t)
			t.Cleanup(ctrl.Finish)
			optionsFactory := mockoidcclientoptions.NewMockOIDCClientOptions(ctrl)
			if tt.wantOptions != nil {
				tt.wantOptions(optionsFactory)
			}

			var gotOptions []oidcclient.Option
			cmd := oidcLoginCommand(oidcLoginCommandDeps{
				lookupEnv: func(s string) (string, bool) {
					v, ok := tt.env[s]
					return v, ok
				},
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
				optionsFactory: optionsFactory,
			})
			require.NotNil(t, cmd)

			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			cmd.SetArgs(tt.args)
			err = cmd.ExecuteContext(ctx)
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantStdout, stdout.String(), "unexpected stdout")
			require.Equal(t, tt.wantStderr, stderr.String(), "unexpected stderr")
			require.Len(t, gotOptions, tt.wantOptionsCount)

			require.Equal(t, tt.wantLogs, testutil.SplitByNewline(buf.String()))
		})
	}
}
