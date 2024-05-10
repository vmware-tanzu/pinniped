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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	clocktesting "k8s.io/utils/clock/testing"

	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/here"
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

	tests := []struct {
		name             string
		args             []string
		loginErr         error
		conciergeErr     error
		env              map[string]string
		wantError        bool
		wantStdout       string
		wantStderr       string
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
					  --upstream-identity-provider-type string   The type of the upstream identity provider used during login with a Supervisor (e.g. 'oidc', 'ldap', 'activedirectory') (default "oidc")
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
			name: "invalid API group suffix",
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
				Error: invalid Concierge parameters: invalid API group suffix: a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')
			`),
		},
		{
			name: "invalid upstream type is an error",
			args: []string{
				"--issuer", "test-issuer",
				"--upstream-identity-provider-type", "invalid",
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: --upstream-identity-provider-type value not recognized: invalid (supported values: oidc, ldap, activedirectory, github)
			`),
		},
		{
			name: "invalid upstream type when flow override env var is used is still an error",
			args: []string{
				"--issuer", "test-issuer",
				"--upstream-identity-provider-type", "invalid",
			},
			env:       map[string]string{"PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW": "browser_authcode"},
			wantError: true,
			wantStderr: here.Doc(`
				Error: --upstream-identity-provider-type value not recognized: invalid (supported values: oidc, ldap, activedirectory, github)
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
			env:              map[string]string{"PINNIPED_SKIP_PRINT_LOGIN_URL": "true"},
			wantOptionsCount: 5,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "oidc upstream type with CLI flow is allowed",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "oidc",
				"--upstream-identity-provider-flow", "cli_password",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			wantOptionsCount: 5,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "oidc upstream type with browser flow is allowed",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "oidc",
				"--upstream-identity-provider-flow", "browser_authcode",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			wantOptionsCount: 4,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "oidc upstream type with CLI flow in flow override env var is allowed",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "oidc",
				"--upstream-identity-provider-flow", "browser_authcode",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			env:              map[string]string{"PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW": "cli_password"},
			wantOptionsCount: 5,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "oidc upstream type with with browser flow in flow override env var is allowed",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "oidc",
				"--upstream-identity-provider-flow", "cli_password",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			env:              map[string]string{"PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW": "browser_authcode"},
			wantOptionsCount: 4,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "oidc upstream type with unsupported flow is an error",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "oidc",
				"--upstream-identity-provider-flow", "foobar",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: --upstream-identity-provider-flow value not recognized for identity provider type "oidc": foobar (supported values: browser_authcode, cli_password)
			`),
		},
		{
			name: "oidc upstream type with unsupported flow in flow override env var is an error",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "oidc",
				"--upstream-identity-provider-flow", "browser_authcode",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			env:       map[string]string{"PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW": "foo"},
			wantError: true,
			wantStderr: here.Doc(`
				Error: PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW value not recognized for identity provider type "oidc": foo (supported values: browser_authcode, cli_password)
			`),
		},
		{
			name: "ldap upstream type with default flow is allowed",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "ldap",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			wantOptionsCount: 5,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "activedirectory upstream type with default flow is allowed",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "activedirectory",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			wantOptionsCount: 5,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "ldap upstream type with CLI flow is allowed",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "ldap",
				"--upstream-identity-provider-flow", "cli_password",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			wantOptionsCount: 5,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "ldap upstream type with browser_authcode flow is allowed",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "ldap",
				"--upstream-identity-provider-flow", "browser_authcode",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			wantOptionsCount: 4,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "ldap upstream type with CLI flow in flow override env var is allowed",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "ldap",
				"--upstream-identity-provider-flow", "browser_authcode",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			env:              map[string]string{"PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW": "cli_password"},
			wantOptionsCount: 5,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "ldap upstream type with browser_authcode flow in flow override env var is allowed",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "ldap",
				"--upstream-identity-provider-flow", "cli_password",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			env:              map[string]string{"PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW": "browser_authcode"},
			wantOptionsCount: 4,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "ldap upstream type with unsupported flow is an error",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "ldap",
				"--upstream-identity-provider-flow", "foo",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: --upstream-identity-provider-flow value not recognized for identity provider type "ldap": foo (supported values: cli_password, browser_authcode)
			`),
		},
		{
			name: "ldap upstream type with unsupported flow in flow override env var is an error",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "ldap",
				"--upstream-identity-provider-flow", "browser_authcode",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			env:       map[string]string{"PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW": "foo"},
			wantError: true,
			wantStderr: here.Doc(`
				Error: PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW value not recognized for identity provider type "ldap": foo (supported values: cli_password, browser_authcode)
			`),
		},
		{
			name: "active directory upstream type with CLI flow is allowed",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "activedirectory",
				"--upstream-identity-provider-flow", "cli_password",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			wantOptionsCount: 5,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "active directory upstream type with browser_authcode is allowed",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "activedirectory",
				"--upstream-identity-provider-flow", "browser_authcode",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			wantOptionsCount: 4,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "active directory upstream type with CLI flow in flow override env var is allowed",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "activedirectory",
				"--upstream-identity-provider-flow", "browser_authcode",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			env:              map[string]string{"PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW": "cli_password"},
			wantOptionsCount: 5,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "active directory upstream type with browser_authcode in flow override env var is allowed",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "activedirectory",
				"--upstream-identity-provider-flow", "cli_password",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			env:              map[string]string{"PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW": "browser_authcode"},
			wantOptionsCount: 4,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "active directory upstream type with unsupported flow is an error",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "activedirectory",
				"--upstream-identity-provider-flow", "foo",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: --upstream-identity-provider-flow value not recognized for identity provider type "activedirectory": foo (supported values: cli_password, browser_authcode)
			`),
		},
		{
			name: "active directory upstream type with unsupported flow in flow override env var is an error",
			args: []string{
				"--issuer", "test-issuer",
				"--client-id", "test-client-id",
				"--upstream-identity-provider-type", "activedirectory",
				"--upstream-identity-provider-flow", "browser_authcode",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			env:       map[string]string{"PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW": "foo"},
			wantError: true,
			wantStderr: here.Doc(`
				Error: PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW value not recognized for identity provider type "activedirectory": foo (supported values: cli_password, browser_authcode)
			`),
		},
		{
			name: "login error",
			args: []string{
				"--client-id", "test-client-id",
				"--issuer", "test-issuer",
				"--credential-cache", "", // must specify --credential-cache or else the cache file on disk causes test pollution
			},
			loginErr:         fmt.Errorf("some login error"),
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
			wantOptionsCount: 4,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
			wantLogs: []string{
				nowStr + `  pinniped-login  cmd/login_oidc.go:260  Performing OIDC login  {"issuer": "test-issuer", "client id": "test-client-id"}`,
				nowStr + `  pinniped-login  cmd/login_oidc.go:280  No concierge configured, skipping token credential exchange`,
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
			},
			env:              map[string]string{"PINNIPED_DEBUG": "true", "PINNIPED_SKIP_PRINT_LOGIN_URL": "true"},
			wantOptionsCount: 12,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false},"status":{"token":"exchanged-token"}}` + "\n",
			wantLogs: []string{
				nowStr + `  pinniped-login  cmd/login_oidc.go:260  Performing OIDC login  {"issuer": "test-issuer", "client id": "test-client-id"}`,
				nowStr + `  pinniped-login  cmd/login_oidc.go:270  Exchanging token for cluster credential  {"endpoint": "https://127.0.0.1:1234/", "authenticator type": "webhook", "authenticator name": "test-authenticator"}`,
				nowStr + `  pinniped-login  cmd/login_oidc.go:278  Successfully exchanged token for cluster credential.`,
				nowStr + `  pinniped-login  cmd/login_oidc.go:285  caching cluster credential for future use.`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			ctx := plog.AddZapOverridesToContext(context.Background(), t, &buf, nil, clocktesting.NewFakeClock(now))

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
