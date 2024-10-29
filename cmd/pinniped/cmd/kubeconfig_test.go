// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	conciergeconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	conciergefake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/tlsserver"
)

func TestGetKubeconfig(t *testing.T) {
	testOIDCCA, err := certauthority.New("Test CA", 1*time.Hour)
	require.NoError(t, err)
	tmpdir := t.TempDir()
	testOIDCCABundlePath := filepath.Join(tmpdir, "testca.pem")
	require.NoError(t, os.WriteFile(testOIDCCABundlePath, testOIDCCA.Bundle(), 0600))

	testConciergeCA, err := certauthority.New("Test Concierge CA", 1*time.Hour)
	require.NoError(t, err)
	testConciergeCABundlePath := filepath.Join(tmpdir, "testconciergeca.pem")
	require.NoError(t, os.WriteFile(testConciergeCABundlePath, testConciergeCA.Bundle(), 0600))

	credentialIssuer := func() runtime.Object {
		return &conciergeconfigv1alpha1.CredentialIssuer{
			ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"},
			Status: conciergeconfigv1alpha1.CredentialIssuerStatus{
				Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{{
					Type:   conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
					Status: conciergeconfigv1alpha1.SuccessStrategyStatus,
					Reason: conciergeconfigv1alpha1.FetchedKeyStrategyReason,
					Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
						Type: conciergeconfigv1alpha1.TokenCredentialRequestAPIFrontendType,
						TokenCredentialRequestAPIInfo: &conciergeconfigv1alpha1.TokenCredentialRequestAPIInfo{
							Server:                   "https://concierge-endpoint.example.com",
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(testConciergeCA.Bundle()),
						},
					},
				}},
			},
		}
	}

	jwtAuthenticator := func(issuerCABundle string, issuerURL string) runtime.Object {
		return &authenticationv1alpha1.JWTAuthenticator{
			ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"},
			Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
				Issuer:   issuerURL,
				Audience: "test-audience",
				TLS: &authenticationv1alpha1.TLSSpec{
					CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(issuerCABundle)),
				},
			},
		}
	}

	happyOIDCDiscoveryResponse := func(issuerURL string) string {
		return here.Docf(`{
			"issuer": "%s",
			"other-key": "other-value",
			"discovery.supervisor.pinniped.dev/v1alpha1": {
				"pinniped_identity_providers_endpoint": "%s/v1alpha1/pinniped_identity_providers"
			},
			"scopes_supported": ["openid", "offline_access", "pinniped:request-audience", "username", "groups"],
			"another-key": "another-value"
		}`, issuerURL, issuerURL)
	}

	onlyIssuerOIDCDiscoveryResponse := func(issuerURL string) string {
		return here.Docf(`{
			"issuer": "%s",
			"other-key": "other-value"
		}`, issuerURL)
	}

	helpOutputFormatString := here.Doc(`
		Generate a Pinniped-based kubeconfig for a cluster

		Usage:
		  kubeconfig [flags]

		Flags:
			  --concierge-api-group-suffix string        Concierge API group suffix (default "pinniped.dev")
			  --concierge-authenticator-name string      Concierge authenticator name (default: autodiscover)
			  --concierge-authenticator-type string      Concierge authenticator type (e.g., 'webhook', 'jwt') (default: autodiscover)
			  --concierge-ca-bundle path                 Path to TLS certificate authority bundle (PEM format, optional, can be repeated) to use when connecting to the Concierge
			  --concierge-credential-issuer string       Concierge CredentialIssuer object to use for autodiscovery (default: autodiscover)
			  --concierge-endpoint string                API base for the Concierge endpoint
			  --concierge-mode mode                      Concierge mode of operation (default TokenCredentialRequestAPI)
			  --concierge-skip-wait                      Skip waiting for any pending Concierge strategies to become ready (default: false)
			  --credential-cache string                  Path to cluster-specific credentials cache
			  --generated-name-suffix string             Suffix to append to generated cluster, context, user kubeconfig entries (default "-pinniped")
		  -h, --help                                     help for kubeconfig
			  --install-hint string                      This text is shown to the user when the pinniped CLI is not installed. (default "The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli for more details")
			  --kubeconfig string                        Path to kubeconfig file%s
			  --kubeconfig-context string                Kubeconfig context name (default: current active context)
			  --no-concierge                             Generate a configuration which does not use the Concierge, but sends the credential to the cluster directly
			  --oidc-ca-bundle path                      Path to TLS certificate authority bundle (PEM format, optional, can be repeated)
			  --oidc-client-id string                    OpenID Connect client ID (default: autodiscover) (default "pinniped-cli")
			  --oidc-issuer string                       OpenID Connect issuer URL (default: autodiscover)
			  --oidc-listen-port uint16                  TCP port for localhost listener (authorization code flow only)
			  --oidc-request-audience string             Request a token with an alternate audience using RFC8693 token exchange
			  --oidc-scopes strings                      OpenID Connect scopes to request during login (default [offline_access,openid,pinniped:request-audience,username,groups])
			  --oidc-session-cache string                Path to OpenID Connect session cache file
			  --oidc-skip-browser                        During OpenID Connect login, skip opening the browser (just print the URL)
		  -o, --output string                            Output file path (default: stdout)
			  --pinniped-cli-path string                 Full path or executable name for the Pinniped CLI binary to be embedded in the resulting kubeconfig output (e.g. 'pinniped') (default: full path of the binary used to execute this command)
			  --skip-validation                          Skip final validation of the kubeconfig (default: false)
			  --static-token string                      Instead of doing an OIDC-based login, specify a static token
			  --static-token-env string                  Instead of doing an OIDC-based login, read a static token from the environment
			  --timeout duration                         Timeout for autodiscovery and validation (default 10m0s)
			  --upstream-identity-provider-flow string   The type of client flow to use with the upstream identity provider during login with a Supervisor (e.g. 'cli_password', 'browser_authcode')
			  --upstream-identity-provider-name string   The name of the upstream identity provider used during login with a Supervisor
			  --upstream-identity-provider-type string   The type of the upstream identity provider used during login with a Supervisor (e.g. 'oidc', 'ldap', 'activedirectory', 'github')
	`)

	tests := []struct {
		name                    string
		args                    func(string, string) []string
		env                     map[string]string
		getPathToSelfErr        error
		getClientsetErr         error
		conciergeObjects        func(string, string) []runtime.Object
		conciergeReactions      []kubetesting.Reactor
		oidcDiscoveryResponse   func(string) string
		oidcDiscoveryStatusCode int
		idpsDiscoveryResponse   string
		idpsDiscoveryStatusCode int
		wantLogs                func(string, string) []string
		wantError               bool
		wantStdout              func(string, string) string
		wantStderr              func(string, string) testutil.RequireErrorStringFunc
		wantOptionsCount        int
		wantAPIGroupSuffix      string
	}{
		{
			name: "help flag passed",
			args: func(issuerCABundle string, issuerURL string) []string { return []string{"--help"} },
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return fmt.Sprintf(helpOutputFormatString, "")
			},
		},
		{
			name: "help flag passed with KUBECONFIG env var set",
			env: map[string]string{
				"KUBECONFIG": "/path/to/kubeconfig",
			},
			args: func(issuerCABundle string, issuerURL string) []string { return []string{"--help"} },
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return fmt.Sprintf(helpOutputFormatString, ` (default "/path/to/kubeconfig")`)
			},
		},
		{
			name: "invalid OIDC CA bundle path",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--oidc-ca-bundle", "./does/not/exist",
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: invalid argument "./does/not/exist" for "--oidc-ca-bundle" flag: could not read CA bundle path: open ./does/not/exist: no such file or directory` + "\n")
			},
		},
		{
			name: "invalid Concierge CA bundle",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--concierge-ca-bundle", "./does/not/exist",
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: invalid argument "./does/not/exist" for "--concierge-ca-bundle" flag: could not read CA bundle path: open ./does/not/exist: no such file or directory` + "\n")
			},
		},
		{
			name: "invalid kubeconfig path",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./does/not/exist",
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: could not load --kubeconfig: stat ./does/not/exist: no such file or directory` + "\n")
			},
		},
		{
			name: "invalid kubeconfig context, missing",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--kubeconfig-context", "invalid",
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: could not load --kubeconfig/--kubeconfig-context: no such context "invalid"` + "\n")
			},
		},
		{
			name: "invalid kubeconfig context, missing cluster",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--kubeconfig-context", "invalid-context-no-such-cluster",
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: could not load --kubeconfig/--kubeconfig-context: no such cluster "invalid-cluster"` + "\n")
			},
		},
		{
			name: "invalid kubeconfig context, missing user",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--kubeconfig-context", "invalid-context-no-such-user",
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: could not load --kubeconfig/--kubeconfig-context: no such user "invalid-user"` + "\n")
			},
		},
		{
			name: "clientset creation failure",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
				}
			},
			getClientsetErr: fmt.Errorf("some kube error"),
			wantError:       true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: could not configure Kubernetes client: some kube error` + "\n")
			},
		},
		{
			name: "no credentialissuers",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: no CredentialIssuers were found` + "\n")
			},
		},
		{
			name: "credentialissuer not found",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--concierge-credential-issuer", "does-not-exist",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					&conciergeconfigv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: credentialissuers.config.concierge.pinniped.dev "does-not-exist" not found` + "\n")
			},
		},
		{
			name: "webhook authenticator not found",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--concierge-authenticator-type", "webhook",
					"--concierge-authenticator-name", "test-authenticator",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					&conciergeconfigv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: webhookauthenticators.authentication.concierge.pinniped.dev "test-authenticator" not found` + "\n")
			},
		},
		{
			name: "JWT authenticator not found",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--concierge-authenticator-type", "jwt",
					"--concierge-authenticator-name", "test-authenticator",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					&conciergeconfigv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: jwtauthenticators.authentication.concierge.pinniped.dev "test-authenticator" not found` + "\n")
			},
		},
		{
			name: "invalid authenticator type",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--concierge-authenticator-type", "invalid",
					"--concierge-authenticator-name", "test-authenticator",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					&conciergeconfigv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: invalid authenticator type "invalid", supported values are "webhook" and "jwt"` + "\n")
			},
		},
		{
			name: "fail to autodetect authenticator, listing jwtauthenticators fails",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					&conciergeconfigv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
				}
			},
			conciergeReactions: []kubetesting.Reactor{
				&kubetesting.SimpleReactor{
					Verb:     "*",
					Resource: "jwtauthenticators",
					Reaction: func(kubetesting.Action) (bool, runtime.Object, error) {
						return true, nil, fmt.Errorf("some list error")
					},
				},
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: failed to list JWTAuthenticator objects for autodiscovery: some list error` + "\n")
			},
		},
		{
			name: "fail to autodetect authenticator, listing webhookauthenticators fails",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					&conciergeconfigv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
				}
			},
			conciergeReactions: []kubetesting.Reactor{
				&kubetesting.SimpleReactor{
					Verb:     "*",
					Resource: "webhookauthenticators",
					Reaction: func(kubetesting.Action) (bool, runtime.Object, error) {
						return true, nil, fmt.Errorf("some list error")
					},
				},
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: failed to list WebhookAuthenticator objects for autodiscovery: some list error` + "\n")
			},
		},
		{
			name: "fail to autodetect authenticator, none found",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					&conciergeconfigv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: no authenticators were found` + "\n")
			},
		},
		{
			name: "fail to autodetect authenticator, multiple found",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					&conciergeconfigv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
					&authenticationv1alpha1.JWTAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator-1"}},
					&authenticationv1alpha1.JWTAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator-2"}},
					&authenticationv1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator-3"}},
					&authenticationv1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator-4"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  found JWTAuthenticator  {"name": "test-authenticator-1"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  found JWTAuthenticator  {"name": "test-authenticator-2"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  found WebhookAuthenticator  {"name": "test-authenticator-3"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  found WebhookAuthenticator  {"name": "test-authenticator-4"}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: multiple authenticators were found, so the --concierge-authenticator-type/--concierge-authenticator-name flags must be specified` + "\n")
			},
		},
		{
			name: "autodetect webhook authenticator, bad credential issuer with only failing strategy",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					&conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"},
						Status: conciergeconfigv1alpha1.CredentialIssuerStatus{
							Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{{
								Type:    "SomeType",
								Status:  conciergeconfigv1alpha1.ErrorStrategyStatus,
								Reason:  "SomeReason",
								Message: "Some message",
							}},
						},
					},
					&authenticationv1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  found CredentialIssuer strategy  {"type": "SomeType", "status": "Error", "reason": "SomeReason", "message": "Some message"}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: could not autodiscover --concierge-mode` + "\n")
			},
		},
		{
			name: "autodetect webhook authenticator, bad credential issuer with invalid impersonation CA",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					&conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"},
						Status: conciergeconfigv1alpha1.CredentialIssuerStatus{
							Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{
								{
									Type:           "SomeBrokenType",
									Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
									Reason:         "SomeFailureReason",
									Message:        "Some error message",
									LastUpdateTime: metav1.Now(),
								},
								{
									Type:           "SomeUnknownType",
									Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
									Reason:         "SomeReason",
									Message:        "Some error message",
									LastUpdateTime: metav1.Now(),
									Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
										Type: "SomeUnknownFrontendType",
									},
								},
								{
									Type:           "SomeType",
									Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
									Reason:         "SomeReason",
									Message:        "Some message",
									LastUpdateTime: metav1.Now(),
									Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
										Type: conciergeconfigv1alpha1.ImpersonationProxyFrontendType,
										ImpersonationProxyInfo: &conciergeconfigv1alpha1.ImpersonationProxyInfo{
											Endpoint:                 "https://impersonation-endpoint",
											CertificateAuthorityData: "invalid-base-64",
										},
									},
								},
							},
						},
					},
					&authenticationv1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in impersonation proxy mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://impersonation-endpoint"}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: autodiscovered Concierge CA bundle is invalid: illegal base64 data at input byte 7` + "\n")
			},
		},
		{
			name: "autodetect webhook authenticator, missing --oidc-issuer",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					&authenticationv1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered WebhookAuthenticator  {"name": "test-authenticator"}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: could not autodiscover --oidc-issuer and none was provided` + "\n")
			},
		},
		{
			name: "autodetect JWT authenticator, invalid TLS bundle",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					&conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"},
						Status: conciergeconfigv1alpha1.CredentialIssuerStatus{
							KubeConfigInfo: &conciergeconfigv1alpha1.CredentialIssuerKubeConfigInfo{
								Server:                   "https://concierge-endpoint",
								CertificateAuthorityData: "ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==",
							},
							Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{{
								Type:           conciergeconfigv1alpha1.KubeClusterSigningCertificateStrategyType,
								Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
								Reason:         conciergeconfigv1alpha1.FetchedKeyStrategyReason,
								Message:        "Successfully fetched key",
								LastUpdateTime: metav1.Now(),
								// Simulate a previous version of CredentialIssuer that's missing this Frontend field.
								Frontend: nil,
							}},
						},
					},
					&authenticationv1alpha1.JWTAuthenticator{
						ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"},
						Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
							Issuer:   issuerURL,
							Audience: "some-test-audience",
							TLS: &authenticationv1alpha1.TLSSpec{
								CertificateAuthorityData: "invalid-base64",
							},
						},
					},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "some-test-audience"}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: tried to autodiscover --oidc-ca-bundle, but JWTAuthenticator test-authenticator has invalid spec.tls.certificateAuthorityData: illegal base64 data at input byte 7` + "\n")
			},
		},
		{
			name: "autodetect JWT authenticator, invalid substring in audience",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					&authenticationv1alpha1.JWTAuthenticator{
						ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"},
						Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
							Issuer:   issuerURL,
							Audience: "some-test-audience.pinniped.dev-invalid-substring",
							TLS: &authenticationv1alpha1.TLSSpec{
								CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(issuerCABundle)),
							},
						},
					},
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "some-test-audience.pinniped.dev-invalid-substring"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: request audience is not allowed to include the substring '.pinniped.dev': some-test-audience.pinniped.dev-invalid-substring` + "\n")
			},
		},
		{
			name: "autodetect JWT authenticator, override audience value, invalid substring in audience override value",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--oidc-request-audience", "some-test-audience.pinniped.dev-invalid-substring",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: request audience is not allowed to include the substring '.pinniped.dev': some-test-audience.pinniped.dev-invalid-substring` + "\n")
			},
		},
		{
			name: "fail to get self-path",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
				}
			},
			getPathToSelfErr: fmt.Errorf("some OS error"),
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: onlyIssuerOIDCDiscoveryResponse,
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: could not determine the Pinniped executable path: some OS error` + "\n")
			},
		},
		{
			name: "invalid static token flags",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--static-token", "test-token",
					"--static-token-env", "TEST_TOKEN",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					&authenticationv1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered WebhookAuthenticator  {"name": "test-authenticator"}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: only one of --static-token and --static-token-env can be specified` + "\n")
			},
		},
		{
			name: "invalid API group suffix",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--concierge-api-group-suffix", ".starts.with.dot",
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: invalid API group suffix: a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')` + "\n")
			},
		},
		{
			name: "when OIDC discovery document 400s",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryStatusCode: http.StatusBadRequest,
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString("Error: while fetching OIDC discovery data from issuer: 400 Bad Request: {}\n")
			},
		},
		{
			name: "when OIDC discovery document lists the wrong issuer",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: func(issuerURL string) string {
				return here.Doc(`{
					"issuer": "https://wrong-issuer.com"
				}`)
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantSprintfErrorString(
					"Error: while fetching OIDC discovery data from issuer: oidc: issuer did not match the issuer returned by provider, expected \"%s\" got \"https://wrong-issuer.com\"\n",
					issuerURL)
			},
		},
		{
			name: "when IDP discovery document returns any error",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse:   happyOIDCDiscoveryResponse,
			idpsDiscoveryStatusCode: http.StatusBadRequest,
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString("Error: unable to fetch IDP discovery data from issuer: unexpected http response status: 400 Bad Request\n")
			},
		},
		{
			name: "when IDP discovery document contains multiple IDPs and no name or type flags are given",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-ldap-idp", "type": "ldap"},
					{"name": "some-oidc-idp", "type": "oidc", "flows": ["flow1", "flow2"]},
					{"name": "some-github-idp", "type": "github"}
				]
			}`),
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: multiple Supervisor upstream identity providers were found, ` +
					`so the --upstream-identity-provider-name/--upstream-identity-provider-type flags must be specified. ` +
					`Found these upstreams: [{"name":"some-ldap-idp","type":"ldap"},{"name":"some-oidc-idp","type":"oidc","flows":["flow1","flow2"]},{"name":"some-github-idp","type":"github"}]` + "\n")
			},
		},
		{
			name: "when OIDC discovery document is not valid JSON",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: func(issuerURL string) string {
				return "this is not valid JSON"
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString("Error: while fetching OIDC discovery data from issuer: oidc: failed to decode provider discovery object: got Content-Type = application/json, but could not unmarshal as JSON: invalid character 'h' in literal true (expecting 'r')\n")
			},
		},
		{
			name: "when IDP discovery document is not valid JSON",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: "this is not valid JSON",
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString("Error: unable to fetch IDP discovery data from issuer: could not parse response JSON: invalid character 'h' in literal true (expecting 'r')\n")
			},
		},
		{
			name: "when tls information is missing from jwtauthenticator, errors because OIDC discovery fails",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					&authenticationv1alpha1.JWTAuthenticator{
						ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"},
						Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
							Issuer:   issuerURL,
							Audience: "test-audience",
						},
					},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
				}
			},
			wantError: true,
			wantStderr: func(_issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantSprintfErrorString(`Error: while fetching OIDC discovery data from issuer: Get "%s/.well-known/openid-configuration": tls: failed to verify certificate: x509: certificate signed by unknown authority%s`, issuerURL, "\n")
			},
		},
		{
			name: "when the issuer url is bad",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--oidc-issuer", "https%://bad-issuer-url", // this url cannot be parsed
					"--oidc-ca-bundle", f.Name(),
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					&authenticationv1alpha1.JWTAuthenticator{
						ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"},
						Spec: authenticationv1alpha1.JWTAuthenticatorSpec{
							Issuer:   issuerURL,
							Audience: "test-audience",
						},
					},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: while fetching OIDC discovery data from issuer: parse "https%://bad-issuer-url/.well-known/openid-configuration": first path segment in URL cannot contain colon` + "\n")
			},
		},
		{
			name: "when the IDP discovery url is bad",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: func(issuerURL string) string {
				return here.Docf(`{
					"issuer": "%s",
					"discovery.supervisor.pinniped.dev/v1alpha1": {
						"pinniped_identity_providers_endpoint": "https%%://illegal_url"
					},
					"scopes_supported": ["openid", "offline_access", "pinniped:request-audience", "username", "groups"]
				}`, issuerURL)
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: while forming request to IDP discovery URL: parse "https%://illegal_url": first path segment in URL cannot contain colon` + "\n")
			},
		},
		{
			name: "supervisor upstream IDP discovery does not find matching IDP when name and type are both specified",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
					"--upstream-identity-provider-name", "does-not-exist-idp",
					"--upstream-identity-provider-type", "ldap",
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-ldap-idp", "type": "ldap"},
					{"name": "some-other-ldap-idp", "type": "ldap"}
				]
			}`),
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: no Supervisor upstream identity providers with name "does-not-exist-idp" of type "ldap" were found.` +
					` Found these upstreams: [{"name":"some-ldap-idp","type":"ldap"},{"name":"some-other-ldap-idp","type":"ldap"}]` + "\n")
			},
		},
		{
			name: "supervisor upstream IDP discovery fails to resolve ambiguity when type is specified but name is not",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
					"--upstream-identity-provider-type", "ldap",
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-ldap-idp", "type": "ldap"},
					{"name": "some-other-ldap-idp", "type": "ldap"},
					{"name": "some-oidc-idp", "type": "oidc"},
					{"name": "some-other-oidc-idp", "type": "oidc"}
				]
			}`),
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: multiple Supervisor upstream identity providers of type "ldap" were found,` +
					` so the --upstream-identity-provider-name flag must be specified.` +
					` Found these upstreams: [{"name":"some-ldap-idp","type":"ldap"},{"name":"some-other-ldap-idp","type":"ldap"},{"name":"some-oidc-idp","type":"oidc"},{"name":"some-other-oidc-idp","type":"oidc"}]` + "\n")
			},
		},
		{
			name: "supervisor upstream IDP discovery fails to resolve ambiguity when name is specified but type is not",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
					"--upstream-identity-provider-name", "my-idp",
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "my-idp", "type": "ldap"},
					{"name": "my-idp", "type": "oidc"},
					{"name": "some-other-oidc-idp", "type": "oidc"}
				]
			}`),
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: multiple Supervisor upstream identity providers with name "my-idp" were found,` +
					` so the --upstream-identity-provider-type flag must be specified.` +
					` Found these upstreams: [{"name":"my-idp","type":"ldap"},{"name":"my-idp","type":"oidc"},{"name":"some-other-oidc-idp","type":"oidc"}]` + "\n")
			},
		},
		{
			name: "supervisor upstream IDP discovery fails to find any matching IDPs when type is specified but name is not",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
					"--upstream-identity-provider-type", "ldap",
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-oidc-idp", "type": "oidc"},
					{"name": "some-other-oidc-idp", "type": "oidc"}
				]
			}`),
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: no Supervisor upstream identity providers of type "ldap" were found.` +
					` Found these upstreams: [{"name":"some-oidc-idp","type":"oidc"},{"name":"some-other-oidc-idp","type":"oidc"}]` + "\n")
			},
		},
		{
			name: "supervisor upstream IDP discovery fails to find any matching IDPs when type is specified but name is not and there is only one IDP found",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
					"--upstream-identity-provider-type", "ldap",
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-oidc-idp", "type": "oidc"}
				]
			}`),
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: no Supervisor upstream identity providers of type "ldap" were found.` +
					` Found these upstreams: [{"name":"some-oidc-idp","type":"oidc"}]` + "\n")
			},
		},
		{
			name: "supervisor upstream IDP discovery fails to find any matching IDPs when name is specified but type is not",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
					"--upstream-identity-provider-name", "my-nonexistent-idp",
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-oidc-idp", "type": "oidc"},
					{"name": "some-other-oidc-idp", "type": "oidc"}
				]
			}`),
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: no Supervisor upstream identity providers with name "my-nonexistent-idp" were found.` +
					` Found these upstreams: [{"name":"some-oidc-idp","type":"oidc"},{"name":"some-other-oidc-idp","type":"oidc"}]` + "\n")
			},
		},
		{
			name: "supervisor upstream IDP discovery fails to find any matching IDPs when name is specified but type is not and there is only one IDP found",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
					"--upstream-identity-provider-name", "my-nonexistent-idp",
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-oidc-idp", "type": "oidc"}
				]
			}`),
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: no Supervisor upstream identity providers with name "my-nonexistent-idp" were found.` +
					` Found these upstreams: [{"name":"some-oidc-idp","type":"oidc"}]` + "\n")
			},
		},
		{
			name: "supervisor upstream IDP discovery when flow is specified but it does not match any flow returned by discovery",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
					"--upstream-identity-provider-flow", "my-nonexistent-flow",
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-oidc-idp", "type": "oidc", "flows": ["non-matching-flow-1", "non-matching-flow-2"]}
				]
			}`),
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) testutil.RequireErrorStringFunc {
				return testutil.WantExactErrorString(`Error: no client flow "my-nonexistent-flow" for Supervisor upstream identity provider "some-oidc-idp" of type "oidc" were found.` +
					` Found these flows: [non-matching-flow-1 non-matching-flow-2]` + "\n")
			},
		},
		{
			name: "supervisor upstream IDP discovery when no flow is specified and more than one flow is returned by discovery",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-ldap-idp", "type": "ldap", "flows": ["cli_password", "flow2"]}
				]
			}`),
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --upstream-identity-provider-name=some-ldap-idp
						  - --upstream-identity-provider-type=ldap
						  - --upstream-identity-provider-flow=cli_password
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
			wantLogs: func(_ string, _ string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  multiple client flows found, selecting first value as default  {"idpName": "some-ldap-idp", "idpType": "ldap", "selectedFlow": "cli_password", "availableFlows": ["cli_password","flow2"]}`,
				}
			},
		},
		{
			name: "valid static token",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--static-token", "test-token",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					&authenticationv1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered WebhookAuthenticator  {"name": "test-authenticator"}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Doc(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - static
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=webhook
						  - --concierge-endpoint=https://fake-server-url-value
						  - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						  - --token=test-token
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
				`)
			},
		},
		{
			name: "valid static token from env var",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--static-token-env", "TEST_TOKEN",
					"--skip-validation",
					"--credential-cache", "",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					&authenticationv1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered WebhookAuthenticator  {"name": "test-authenticator"}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Doc(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - static
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=webhook
						  - --concierge-endpoint=https://fake-server-url-value
						  - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						  - --credential-cache=
						  - --token-env=TEST_TOKEN
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
				`)
			},
		},
		{
			name: "autodetect JWT authenticator",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: onlyIssuerOIDCDiscoveryResponse,
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=jwt
						  - --concierge-endpoint=https://fake-server-url-value
						  - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --request-audience=test-audience
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "autodetect nothing, set a bunch of options",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--concierge-credential-issuer", "test-credential-issuer",
					"--concierge-api-group-suffix", "tuna.io",
					"--concierge-authenticator-type", "webhook",
					"--concierge-authenticator-name", "test-authenticator",
					"--concierge-mode", "TokenCredentialRequestAPI",
					"--concierge-endpoint", "https://explicit-concierge-endpoint.example.com",
					"--concierge-ca-bundle", testConciergeCABundlePath,
					"--oidc-issuer", issuerURL,
					"--oidc-skip-browser",
					"--oidc-skip-listen",
					"--oidc-listen-port", "1234",
					"--oidc-ca-bundle", f.Name(),
					"--oidc-session-cache", "/path/to/cache/dir/sessions.yaml",
					"--oidc-debug-session-cache",
					"--oidc-request-audience", "test-audience",
					"--skip-validation",
					"--generated-name-suffix", "-sso",
					"--credential-cache", "/path/to/cache/dir/credentials.yaml",
					"--pinniped-cli-path", "/some/path/to/command-exe",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					&authenticationv1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"}},
				}
			},
			oidcDiscoveryResponse: onlyIssuerOIDCDiscoveryResponse,
			wantLogs:              func(issuerCABundle string, issuerURL string) []string { return nil },
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: %s
						server: https://explicit-concierge-endpoint.example.com
					  name: kind-cluster-sso
					contexts:
					- context:
						cluster: kind-cluster-sso
						user: kind-user-sso
					  name: kind-context-sso
					current-context: kind-context-sso
					kind: Config
					preferences: {}
					users:
					- name: kind-user-sso
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --enable-concierge
						  - --concierge-api-group-suffix=tuna.io
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=webhook
						  - --concierge-endpoint=https://explicit-concierge-endpoint.example.com
						  - --concierge-ca-bundle-data=%s
						  - --credential-cache=/path/to/cache/dir/credentials.yaml
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --skip-browser
						  - --skip-listen
						  - --listen-port=1234
						  - --ca-bundle-data=%s
						  - --session-cache=/path/to/cache/dir/sessions.yaml
						  - --debug-session-cache
						  - --request-audience=test-audience
						  command: /some/path/to/command-exe
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					base64.StdEncoding.EncodeToString(testConciergeCA.Bundle()),
					base64.StdEncoding.EncodeToString(testConciergeCA.Bundle()),
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)),
				)
			},
			wantAPIGroupSuffix: "tuna.io",
		},
		{
			name: "configure impersonation proxy with autodiscovered JWT authenticator",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--concierge-mode", "ImpersonationProxy",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					&conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"},
						Status: conciergeconfigv1alpha1.CredentialIssuerStatus{
							Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{
								// This TokenCredentialRequestAPI strategy would normally be chosen, but
								// --concierge-mode=ImpersonationProxy should force it to be skipped.
								{
									Type:           "SomeType",
									Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
									Reason:         "SomeReason",
									Message:        "Some message",
									LastUpdateTime: metav1.Now(),
									Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
										Type: conciergeconfigv1alpha1.TokenCredentialRequestAPIFrontendType,
										TokenCredentialRequestAPIInfo: &conciergeconfigv1alpha1.TokenCredentialRequestAPIInfo{
											Server:                   "https://token-credential-request-api-endpoint.test",
											CertificateAuthorityData: "dGVzdC10Y3ItYXBpLWNh",
										},
									},
								},
								// The endpoint and CA from this impersonation proxy strategy should be autodiscovered.
								{
									Type:           "SomeOtherType",
									Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
									Reason:         "SomeOtherReason",
									Message:        "Some other message",
									LastUpdateTime: metav1.Now(),
									Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
										Type: conciergeconfigv1alpha1.ImpersonationProxyFrontendType,
										ImpersonationProxyInfo: &conciergeconfigv1alpha1.ImpersonationProxyInfo{
											Endpoint:                 "https://impersonation-proxy-endpoint.test",
											CertificateAuthorityData: base64.StdEncoding.EncodeToString(testConciergeCA.Bundle()),
										},
									},
								},
							},
						},
					},
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: onlyIssuerOIDCDiscoveryResponse,
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://impersonation-proxy-endpoint.test"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 1}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: %s
						server: https://impersonation-proxy-endpoint.test
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=jwt
						  - --concierge-endpoint=https://impersonation-proxy-endpoint.test
						  - --concierge-ca-bundle-data=%s
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --request-audience=test-audience
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					base64.StdEncoding.EncodeToString(testConciergeCA.Bundle()),
					base64.StdEncoding.EncodeToString(testConciergeCA.Bundle()),
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)),
				)
			},
		},
		{
			name: "autodetect impersonation proxy with auto-discovered JWT authenticator",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					&conciergeconfigv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"},
						Status: conciergeconfigv1alpha1.CredentialIssuerStatus{
							Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{
								{
									Type:           "SomeType",
									Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
									Reason:         "SomeReason",
									Message:        "Some message",
									LastUpdateTime: metav1.Now(),
									Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
										Type: conciergeconfigv1alpha1.ImpersonationProxyFrontendType,
										ImpersonationProxyInfo: &conciergeconfigv1alpha1.ImpersonationProxyInfo{
											Endpoint:                 "https://impersonation-proxy-endpoint.test",
											CertificateAuthorityData: "dGVzdC1jb25jaWVyZ2UtY2E=",
										},
									},
								},
								{
									Type:           "SomeOtherType",
									Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
									Reason:         "SomeOtherReason",
									Message:        "Some other message",
									LastUpdateTime: metav1.Now(),
									Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
										Type: conciergeconfigv1alpha1.ImpersonationProxyFrontendType,
										ImpersonationProxyInfo: &conciergeconfigv1alpha1.ImpersonationProxyInfo{
											Endpoint:                 "https://some-other-impersonation-endpoint",
											CertificateAuthorityData: "dGVzdC1jb25jaWVyZ2UtY2E=",
										},
									},
								},
							},
						},
					},
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: onlyIssuerOIDCDiscoveryResponse,
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in impersonation proxy mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://impersonation-proxy-endpoint.test"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: dGVzdC1jb25jaWVyZ2UtY2E=
						server: https://impersonation-proxy-endpoint.test
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=jwt
						  - --concierge-endpoint=https://impersonation-proxy-endpoint.test
						  - --concierge-ca-bundle-data=dGVzdC1jb25jaWVyZ2UtY2E=
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --request-audience=test-audience
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "Find LDAP IDP in IDP discovery document, output ldap related flags",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-ldap-idp", "type": "ldap"}
				]
			}`),
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=jwt
						  - --concierge-endpoint=https://fake-server-url-value
						  - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --request-audience=test-audience
						  - --upstream-identity-provider-name=some-ldap-idp
						  - --upstream-identity-provider-type=ldap
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "Find OIDC IDP in IDP discovery document, output oidc related flags",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-oidc-idp", "type": "oidc"}
				]
			}`),
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=jwt
						  - --concierge-endpoint=https://fake-server-url-value
						  - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --request-audience=test-audience
						  - --upstream-identity-provider-name=some-oidc-idp
						  - --upstream-identity-provider-type=oidc
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "empty IDP list in IDP discovery document",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": []
			}`),
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=jwt
						  - --concierge-endpoint=https://fake-server-url-value
						  - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --request-audience=test-audience
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "Supervisor discovery section is not listed in OIDC discovery document",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse:   onlyIssuerOIDCDiscoveryResponse,
			idpsDiscoveryStatusCode: http.StatusBadRequest, // IDPs endpoint shouldn't be called by this test
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=jwt
						  - --concierge-endpoint=https://fake-server-url-value
						  - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --request-audience=test-audience
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "IDP discovery endpoint is not listed in OIDC discovery document within the Supervisor discovery section",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: func(issuerURL string) string {
				return here.Docf(`{
					"issuer": "%s",
					"discovery.supervisor.pinniped.dev/v1alpha1": {
						"wrong-key": "some-value"
					}
				}`, issuerURL)
			},
			idpsDiscoveryStatusCode: http.StatusBadRequest, // IDP discovery endpoint shouldn't be called by this test
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=jwt
						  - --concierge-endpoint=https://fake-server-url-value
						  - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --request-audience=test-audience
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "IDP discovery endpoint is listed in OIDC discovery document but scopes_supported does not include username or groups, so do not request username or groups in kubeconfig's --scopes",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: func(issuerURL string) string {
				return here.Docf(`{
					"issuer": "%s",
					"discovery.supervisor.pinniped.dev/v1alpha1": {
						"pinniped_identity_providers_endpoint": "%s/v1alpha1/pinniped_identity_providers"
					},
					"scopes_supported": ["openid", "offline_access", "pinniped:request-audience"]
				}`, issuerURL, issuerURL)
			},
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-oidc-idp", "type": "oidc"}
				]
			}`),
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  removed scope from --oidc-scopes list because it is not supported by this Supervisor  {"scope": "username"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  removed scope from --oidc-scopes list because it is not supported by this Supervisor  {"scope": "groups"}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=jwt
						  - --concierge-endpoint=https://fake-server-url-value
						  - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience
						  - --ca-bundle-data=%s
						  - --request-audience=test-audience
						  - --upstream-identity-provider-name=some-oidc-idp
						  - --upstream-identity-provider-type=oidc
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "IDP discovery endpoint is listed in OIDC discovery document but scopes_supported is not listed (which shouldn't really happen), so do not request username or groups in kubeconfig's --scopes",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: func(issuerURL string) string {
				return here.Docf(`{
					"issuer": "%s",
					"discovery.supervisor.pinniped.dev/v1alpha1": {
						"pinniped_identity_providers_endpoint": "%s/v1alpha1/pinniped_identity_providers"
					}
				}`, issuerURL, issuerURL)
			},
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-oidc-idp", "type": "oidc"}
				]
			}`),
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  removed scope from --oidc-scopes list because it is not supported by this Supervisor  {"scope": "username"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  removed scope from --oidc-scopes list because it is not supported by this Supervisor  {"scope": "groups"}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=jwt
						  - --concierge-endpoint=https://fake-server-url-value
						  - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience
						  - --ca-bundle-data=%s
						  - --request-audience=test-audience
						  - --upstream-identity-provider-name=some-oidc-idp
						  - --upstream-identity-provider-type=oidc
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "IDP discovery endpoint is listed in OIDC discovery document but scopes_supported does not include username or groups, and scopes username and groups were also not requested by flags",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--oidc-scopes", "foo,bar,baz",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: func(issuerURL string) string {
				return here.Docf(`{
					"issuer": "%s",
					"discovery.supervisor.pinniped.dev/v1alpha1": {
						"pinniped_identity_providers_endpoint": "%s/v1alpha1/pinniped_identity_providers"
					},
					"scopes_supported": ["openid", "offline_access", "pinniped:request-audience"]
				}`, issuerURL, issuerURL)
			},
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-oidc-idp", "type": "oidc"}
				]
			}`),
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=jwt
						  - --concierge-endpoint=https://fake-server-url-value
						  - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=foo,bar,baz
						  - --ca-bundle-data=%s
						  - --request-audience=test-audience
						  - --upstream-identity-provider-name=some-oidc-idp
						  - --upstream-identity-provider-type=oidc
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "when all upstream IDP related flags are sent, pass them through without performing IDP discovery",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--upstream-identity-provider-name=some-oidc-idp",
					"--upstream-identity-provider-type=oidc",
					"--upstream-identity-provider-flow=foobar",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse:   happyOIDCDiscoveryResponse, // still called to check for support of username and groups scopes
			idpsDiscoveryStatusCode: http.StatusNotFound,        // should not get called by the client in this case
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=jwt
						  - --concierge-endpoint=https://fake-server-url-value
						  - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --request-audience=test-audience
						  - --upstream-identity-provider-name=some-oidc-idp
						  - --upstream-identity-provider-type=oidc
						  - --upstream-identity-provider-flow=foobar
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "when all upstream IDP related flags are sent, pass them through even when IDP discovery shows a different IDP",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--upstream-identity-provider-name=some-oidc-idp",
					"--upstream-identity-provider-type=oidc",
					"--upstream-identity-provider-flow=foobar",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-other-ldap-idp", "type": "ldap"}
				]
			}`),
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered JWTAuthenticator  {"name": "test-authenticator"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC issuer  {"issuer": "` + issuerURL + `"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC audience  {"audience": "test-audience"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered OIDC CA bundle  {"roots": 1}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=jwt
						  - --concierge-endpoint=https://fake-server-url-value
						  - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --request-audience=test-audience
						  - --upstream-identity-provider-name=some-oidc-idp
						  - --upstream-identity-provider-type=oidc
						  - --upstream-identity-provider-flow=foobar
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "supervisor upstream IDP discovery still works when --no-concierge is used",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-ldap-idp", "type": "ldap"}
				]
			}`),
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --upstream-identity-provider-name=some-ldap-idp
						  - --upstream-identity-provider-type=ldap
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "supervisor upstream IDP discovery resolves ambiguity when type is specified but name is not",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
					"--upstream-identity-provider-type", "ldap",
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-ldap-idp", "type": "ldap"},
					{"name": "some-oidc-idp", "type": "oidc"},
					{"name": "some-other-oidc-idp", "type": "oidc"}
				]
			}`),
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --upstream-identity-provider-name=some-ldap-idp
						  - --upstream-identity-provider-type=ldap
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "supervisor upstream IDP discovery resolves ambiguity when name is specified but type is not",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
					"--upstream-identity-provider-name", "some-ldap-idp",
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-ldap-idp", "type": "ldap"},
					{"name": "some-oidc-idp", "type": "oidc"},
					{"name": "some-other-oidc-idp", "type": "oidc"}
				]
			}`),
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --upstream-identity-provider-name=some-ldap-idp
						  - --upstream-identity-provider-type=ldap
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		}, // TODO make sure there are active directory tests for various flows
		{
			name: "supervisor upstream IDP discovery when both name and type are specified but flow is not and a matching IDP is found",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
					"--upstream-identity-provider-name", "some-ldap-idp",
					"--upstream-identity-provider-type", "ldap",
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-ldap-idp", "type": "ldap"},
					{"name": "some-oidc-idp", "type": "oidc"},
					{"name": "some-other-oidc-idp", "type": "oidc"}
				]
			}`),
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --upstream-identity-provider-name=some-ldap-idp
						  - --upstream-identity-provider-type=ldap
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "supervisor upstream IDP discovery when flow is specified and no flows were returned by discovery uses the specified flow",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
					"--upstream-identity-provider-flow", "foobar",
					"--upstream-identity-provider-type", "ldap",
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-ldap-idp", "type": "ldap"},
					{"name": "some-oidc-idp", "type": "oidc"},
					{"name": "some-other-oidc-idp", "type": "oidc"}
				]
			}`),
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --upstream-identity-provider-name=some-ldap-idp
						  - --upstream-identity-provider-type=ldap
						  - --upstream-identity-provider-flow=foobar
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "supervisor upstream IDP discovery when flow is specified and it matches a flow returned by discovery uses the specified flow",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
					"--upstream-identity-provider-flow", "cli_password",
					"--upstream-identity-provider-type", "ldap",
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-ldap-idp", "type": "ldap", "flows": ["some_flow", "cli_password", "some_other_flow"]}
				]
			}`),
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --upstream-identity-provider-name=some-ldap-idp
						  - --upstream-identity-provider-type=ldap
						  - --upstream-identity-provider-flow=cli_password
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "supervisor upstream IDP discovery when no flow is specified but there is only one flow returned by discovery uses the discovered flow",
			args: func(issuerCABundle string, issuerURL string) []string {
				f := testutil.WriteStringToTempFile(t, "testca-*.pem", issuerCABundle)
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--no-concierge",
					"--oidc-issuer", issuerURL,
					"--oidc-ca-bundle", f.Name(),
					"--upstream-identity-provider-type", "ldap",
				}
			},
			oidcDiscoveryResponse: happyOIDCDiscoveryResponse,
			idpsDiscoveryResponse: here.Docf(`{
				"pinniped_identity_providers": [
					{"name": "some-ldap-idp", "type": "ldap", "flows": ["cli_password"]}
				]
			}`),
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Docf(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - oidc
						  - --issuer=%s
						  - --client-id=pinniped-cli
						  - --scopes=offline_access,openid,pinniped:request-audience,username,groups
						  - --ca-bundle-data=%s
						  - --upstream-identity-provider-name=some-ldap-idp
						  - --upstream-identity-provider-type=ldap
						  - --upstream-identity-provider-flow=cli_password
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli
						    for more details
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "user specified message for install-hint flag",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--install-hint", "Test installHint message",
					"--static-token", "test-token",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					&authenticationv1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered CredentialIssuer  {"name": "test-credential-issuer"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge operating in TokenCredentialRequest API mode`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge endpoint  {"endpoint": "https://fake-server-url-value"}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered Concierge certificate authority bundle  {"roots": 0}`,
					`2099-08-08T13:57:36.123456Z  info  cmd/kubeconfig.go:<line>  discovered WebhookAuthenticator  {"name": "test-authenticator"}`,
				}
			},
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Doc(`
					apiVersion: v1
					clusters:
					- cluster:
						certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						server: https://fake-server-url-value
					  name: kind-cluster-pinniped
					contexts:
					- context:
						cluster: kind-cluster-pinniped
						user: kind-user-pinniped
					  name: kind-context-pinniped
					current-context: kind-context-pinniped
					kind: Config
					preferences: {}
					users:
					- name: kind-user-pinniped
					  user:
						exec:
						  apiVersion: client.authentication.k8s.io/v1beta1
						  args:
						  - login
						  - static
						  - --enable-concierge
						  - --concierge-api-group-suffix=pinniped.dev
						  - --concierge-authenticator-name=test-authenticator
						  - --concierge-authenticator-type=webhook
						  - --concierge-endpoint=https://fake-server-url-value
						  - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
						  - --token=test-token
						  command: '.../path/to/pinniped'
						  env: []
						  installHint: Test installHint message
						  provideClusterInfo: true
				`)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var issuerEndpointPtr *string
			testServer, testServerCA := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("content-type", "application/json")
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					jsonResponseBody := "{}"
					if tt.oidcDiscoveryResponse != nil {
						jsonResponseBody = tt.oidcDiscoveryResponse(*issuerEndpointPtr)
					}
					if tt.oidcDiscoveryStatusCode == 0 {
						tt.oidcDiscoveryStatusCode = http.StatusOK
					}
					w.WriteHeader(tt.oidcDiscoveryStatusCode)
					_, err = w.Write([]byte(jsonResponseBody))
					require.NoError(t, err)
				case "/v1alpha1/pinniped_identity_providers":
					jsonResponseBody := tt.idpsDiscoveryResponse
					if tt.idpsDiscoveryResponse == "" {
						jsonResponseBody = "{}"
					}
					if tt.idpsDiscoveryStatusCode == 0 {
						tt.idpsDiscoveryStatusCode = http.StatusOK
					}
					w.WriteHeader(tt.idpsDiscoveryStatusCode)
					_, err = w.Write([]byte(jsonResponseBody))
					require.NoError(t, err)
				default:
					t.Fatalf("tried to call issuer at a path that wasn't one of the expected discovery endpoints.")
				}
			}), nil)
			issuerEndpointPtr = ptr.To(testServer.URL)

			var log bytes.Buffer

			cmd := kubeconfigCommand(kubeconfigDeps{
				getenv: func(key string) string {
					return tt.env[key]
				},
				getPathToSelf: func() (string, error) {
					if tt.getPathToSelfErr != nil {
						return "", tt.getPathToSelfErr
					}
					return ".../path/to/pinniped", nil
				},
				getClientset: func(clientConfig clientcmd.ClientConfig, apiGroupSuffix string) (conciergeclientset.Interface, error) {
					if tt.wantAPIGroupSuffix == "" {
						require.Equal(t, "pinniped.dev", apiGroupSuffix) // "pinniped.dev" = api group suffix default
					} else {
						require.Equal(t, tt.wantAPIGroupSuffix, apiGroupSuffix)
					}
					if tt.getClientsetErr != nil {
						return nil, tt.getClientsetErr
					}
					fake := conciergefake.NewSimpleClientset()
					if tt.conciergeObjects != nil {
						fake = conciergefake.NewSimpleClientset(tt.conciergeObjects(string(testServerCA), testServer.URL)...)
					}
					if len(tt.conciergeReactions) > 0 {
						fake.ReactionChain = slices.Concat(tt.conciergeReactions, fake.ReactionChain)
					}
					return fake, nil
				},
				log: plog.TestConsoleLogger(t, &log),
			})
			require.NotNil(t, cmd)

			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)

			cmd.SetArgs(tt.args(string(testServerCA), testServer.URL))

			err := cmd.Execute()
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantLogs != nil {
				wantLogs := tt.wantLogs(string(testServerCA), testServer.URL)
				testutil.RequireLogLines(t, wantLogs, &log)
			}

			expectedStdout := ""
			if tt.wantStdout != nil {
				expectedStdout = tt.wantStdout(string(testServerCA), testServer.URL)
			}
			require.Equal(t, expectedStdout, stdout.String(), "unexpected stdout")

			actualStderr := stderr.String()
			if tt.wantStderr != nil {
				testutil.RequireErrorString(t, actualStderr, tt.wantStderr(string(testServerCA), testServer.URL))
			} else {
				require.Empty(t, actualStderr, "unexpected stderr")
			}
		})
	}
}
