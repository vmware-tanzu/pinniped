// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/clientcmd"

	conciergev1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	configv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	fakeconciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/testlogger"
)

func TestGetKubeconfig(t *testing.T) {
	testOIDCCA, err := certauthority.New("Test CA", 1*time.Hour)
	require.NoError(t, err)
	tmpdir := testutil.TempDir(t)
	testOIDCCABundlePath := filepath.Join(tmpdir, "testca.pem")
	require.NoError(t, ioutil.WriteFile(testOIDCCABundlePath, testOIDCCA.Bundle(), 0600))

	testConciergeCA, err := certauthority.New("Test Concierge CA", 1*time.Hour)
	require.NoError(t, err)
	testConciergeCABundlePath := filepath.Join(tmpdir, "testconciergeca.pem")
	require.NoError(t, ioutil.WriteFile(testConciergeCABundlePath, testConciergeCA.Bundle(), 0600))

	credentialIssuer := func() runtime.Object {
		return &configv1alpha1.CredentialIssuer{
			ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"},
			Status: configv1alpha1.CredentialIssuerStatus{
				Strategies: []configv1alpha1.CredentialIssuerStrategy{{
					Type:   configv1alpha1.KubeClusterSigningCertificateStrategyType,
					Status: configv1alpha1.SuccessStrategyStatus,
					Reason: configv1alpha1.FetchedKeyStrategyReason,
					Frontend: &configv1alpha1.CredentialIssuerFrontend{
						Type: configv1alpha1.TokenCredentialRequestAPIFrontendType,
						TokenCredentialRequestAPIInfo: &configv1alpha1.TokenCredentialRequestAPIInfo{
							Server:                   "https://concierge-endpoint.example.com",
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(testConciergeCA.Bundle()),
						},
					},
				}},
			},
		}
	}

	jwtAuthenticator := func(issuerCABundle string, issuerURL string) runtime.Object {
		return &conciergev1alpha1.JWTAuthenticator{
			ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"},
			Spec: conciergev1alpha1.JWTAuthenticatorSpec{
				Issuer:   issuerURL,
				Audience: "test-audience",
				TLS: &conciergev1alpha1.TLSSpec{
					CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(issuerCABundle)),
				},
			},
		}
	}

	tests := []struct {
		name                string
		args                func(string, string) []string
		env                 map[string]string
		getPathToSelfErr    error
		getClientsetErr     error
		conciergeObjects    func(string, string) []runtime.Object
		conciergeReactions  []kubetesting.Reactor
		discoveryResponse   string
		discoveryStatusCode int
		wantLogs            func(string, string) []string
		wantError           bool
		wantStdout          func(string, string) string
		wantStderr          func(string, string) string
		wantOptionsCount    int
		wantAPIGroupSuffix  string
	}{
		{
			name: "help flag passed",
			args: func(issuerCABundle string, issuerURL string) []string { return []string{"--help"} },
			wantStdout: func(issuerCABundle string, issuerURL string) string {
				return here.Doc(`
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
				      --kubeconfig string                        Path to kubeconfig file
				      --kubeconfig-context string                Kubeconfig context name (default: current active context)
				      --no-concierge                             Generate a configuration which does not use the Concierge, but sends the credential to the cluster directly
				      --oidc-ca-bundle path                      Path to TLS certificate authority bundle (PEM format, optional, can be repeated)
				      --oidc-client-id string                    OpenID Connect client ID (default: autodiscover) (default "pinniped-cli")
				      --oidc-issuer string                       OpenID Connect issuer URL (default: autodiscover)
				      --oidc-listen-port uint16                  TCP port for localhost listener (authorization code flow only)
				      --oidc-request-audience string             Request a token with an alternate audience using RFC8693 token exchange
				      --oidc-scopes strings                      OpenID Connect scopes to request during login (default [offline_access,openid,pinniped:request-audience])
				      --oidc-session-cache string                Path to OpenID Connect session cache file
				      --oidc-skip-browser                        During OpenID Connect login, skip opening the browser (just print the URL)
				  -o, --output string                            Output file path (default: stdout)
				      --skip-validation                          Skip final validation of the kubeconfig (default: false)
				      --static-token string                      Instead of doing an OIDC-based login, specify a static token
				      --static-token-env string                  Instead of doing an OIDC-based login, read a static token from the environment
				      --timeout duration                         Timeout for autodiscovery and validation (default 10m0s)
				      --upstream-identity-provider-name string   The name of the upstream identity provider used during login with a Supervisor
				      --upstream-identity-provider-type string   The type of the upstream identity provider used during login with a Supervisor (e.g. 'oidc', 'ldap')
			`)
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
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: invalid argument "./does/not/exist" for "--oidc-ca-bundle" flag: could not read CA bundle path: open ./does/not/exist: no such file or directory` + "\n"
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
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: invalid argument "./does/not/exist" for "--concierge-ca-bundle" flag: could not read CA bundle path: open ./does/not/exist: no such file or directory` + "\n"
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
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: could not load --kubeconfig: stat ./does/not/exist: no such file or directory` + "\n"
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
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: could not load --kubeconfig/--kubeconfig-context: no such context "invalid"` + "\n"
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
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: could not load --kubeconfig/--kubeconfig-context: no such cluster "invalid-cluster"` + "\n"
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
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: could not load --kubeconfig/--kubeconfig-context: no such user "invalid-user"` + "\n"
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
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: could not configure Kubernetes client: some kube error` + "\n"
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
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: no CredentialIssuers were found` + "\n"
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
					&configv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: credentialissuers.config.concierge.pinniped.dev "does-not-exist" not found` + "\n"
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
					&configv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: webhookauthenticators.authentication.concierge.pinniped.dev "test-authenticator" not found` + "\n"
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
					&configv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: jwtauthenticators.authentication.concierge.pinniped.dev "test-authenticator" not found` + "\n"
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
					&configv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: invalid authenticator type "invalid", supported values are "webhook" and "jwt"` + "\n"
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
					&configv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
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
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: failed to list JWTAuthenticator objects for autodiscovery: some list error` + "\n"
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
					&configv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
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
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: failed to list WebhookAuthenticator objects for autodiscovery: some list error` + "\n"
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
					&configv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: no authenticators were found` + "\n"
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
					&configv1alpha1.CredentialIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"}},
					&conciergev1alpha1.JWTAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator-1"}},
					&conciergev1alpha1.JWTAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator-2"}},
					&conciergev1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator-3"}},
					&conciergev1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator-4"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="found JWTAuthenticator"  "name"="test-authenticator-1"`,
					`"level"=0 "msg"="found JWTAuthenticator"  "name"="test-authenticator-2"`,
					`"level"=0 "msg"="found WebhookAuthenticator"  "name"="test-authenticator-3"`,
					`"level"=0 "msg"="found WebhookAuthenticator"  "name"="test-authenticator-4"`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: multiple authenticators were found, so the --concierge-authenticator-type/--concierge-authenticator-name flags must be specified` + "\n"
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
					&configv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"},
						Status: configv1alpha1.CredentialIssuerStatus{
							Strategies: []configv1alpha1.CredentialIssuerStrategy{{
								Type:    "SomeType",
								Status:  configv1alpha1.ErrorStrategyStatus,
								Reason:  "SomeReason",
								Message: "Some message",
							}},
						},
					},
					&conciergev1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="found CredentialIssuer strategy"  "message"="Some message" "reason"="SomeReason" "status"="Error" "type"="SomeType"`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: could not autodiscover --concierge-mode` + "\n"
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
					&configv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"},
						Status: configv1alpha1.CredentialIssuerStatus{
							Strategies: []configv1alpha1.CredentialIssuerStrategy{
								{
									Type:           "SomeBrokenType",
									Status:         configv1alpha1.ErrorStrategyStatus,
									Reason:         "SomeFailureReason",
									Message:        "Some error message",
									LastUpdateTime: metav1.Now(),
								},
								{
									Type:           "SomeUnknownType",
									Status:         configv1alpha1.SuccessStrategyStatus,
									Reason:         "SomeReason",
									Message:        "Some error message",
									LastUpdateTime: metav1.Now(),
									Frontend: &configv1alpha1.CredentialIssuerFrontend{
										Type: "SomeUnknownFrontendType",
									},
								},
								{
									Type:           "SomeType",
									Status:         configv1alpha1.SuccessStrategyStatus,
									Reason:         "SomeReason",
									Message:        "Some message",
									LastUpdateTime: metav1.Now(),
									Frontend: &configv1alpha1.CredentialIssuerFrontend{
										Type: configv1alpha1.ImpersonationProxyFrontendType,
										ImpersonationProxyInfo: &configv1alpha1.ImpersonationProxyInfo{
											Endpoint:                 "https://impersonation-endpoint",
											CertificateAuthorityData: "invalid-base-64",
										},
									},
								},
							},
						},
					},
					&conciergev1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in impersonation proxy mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://impersonation-endpoint"`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: autodiscovered Concierge CA bundle is invalid: illegal base64 data at input byte 7` + "\n"
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
					&conciergev1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered WebhookAuthenticator"  "name"="test-authenticator"`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: could not autodiscover --oidc-issuer and none was provided` + "\n"
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
					&configv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"},
						Status: configv1alpha1.CredentialIssuerStatus{
							KubeConfigInfo: &configv1alpha1.CredentialIssuerKubeConfigInfo{
								Server:                   "https://concierge-endpoint",
								CertificateAuthorityData: "ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==",
							},
							Strategies: []configv1alpha1.CredentialIssuerStrategy{{
								Type:           configv1alpha1.KubeClusterSigningCertificateStrategyType,
								Status:         configv1alpha1.SuccessStrategyStatus,
								Reason:         configv1alpha1.FetchedKeyStrategyReason,
								Message:        "Successfully fetched key",
								LastUpdateTime: metav1.Now(),
								// Simulate a previous version of CredentialIssuer that's missing this Frontend field.
								Frontend: nil,
							}},
						},
					},
					&conciergev1alpha1.JWTAuthenticator{
						ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"},
						Spec: conciergev1alpha1.JWTAuthenticatorSpec{
							Issuer:   issuerURL,
							Audience: "some-test-audience",
							TLS: &conciergev1alpha1.TLSSpec{
								CertificateAuthorityData: "invalid-base64",
							},
						},
					},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered JWTAuthenticator"  "name"="test-authenticator"`,
					fmt.Sprintf(`"level"=0 "msg"="discovered OIDC issuer"  "issuer"="%s"`, issuerURL),
					`"level"=0 "msg"="discovered OIDC audience"  "audience"="some-test-audience"`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: tried to autodiscover --oidc-ca-bundle, but JWTAuthenticator test-authenticator has invalid spec.tls.certificateAuthorityData: illegal base64 data at input byte 7` + "\n"
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
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered JWTAuthenticator"  "name"="test-authenticator"`,
					fmt.Sprintf(`"level"=0 "msg"="discovered OIDC issuer"  "issuer"="%s"`, issuerURL),
					`"level"=0 "msg"="discovered OIDC audience"  "audience"="test-audience"`,
					`"level"=0 "msg"="discovered OIDC CA bundle"  "roots"=1`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: could not determine the Pinniped executable path: some OS error` + "\n"
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
					&conciergev1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered WebhookAuthenticator"  "name"="test-authenticator"`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: only one of --static-token and --static-token-env can be specified` + "\n"
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
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: invalid API group suffix: a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')` + "\n"
			},
		},
		{
			name: "when discovery document 400s",
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
			discoveryStatusCode: http.StatusBadRequest,
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered JWTAuthenticator"  "name"="test-authenticator"`,
					fmt.Sprintf(`"level"=0 "msg"="discovered OIDC issuer"  "issuer"="%s"`, issuerURL),
					`"level"=0 "msg"="discovered OIDC audience"  "audience"="test-audience"`,
					`"level"=0 "msg"="discovered OIDC CA bundle"  "roots"=1`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return "Error: unable to fetch discovery data from issuer: unexpected http response status: 400 Bad Request\n"
			},
		},
		{
			name: "when discovery document is not valid JSON",
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
			discoveryStatusCode: http.StatusOK,
			discoveryResponse:   "this is not valid JSON",
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered JWTAuthenticator"  "name"="test-authenticator"`,
					fmt.Sprintf(`"level"=0 "msg"="discovered OIDC issuer"  "issuer"="%s"`, issuerURL),
					`"level"=0 "msg"="discovered OIDC audience"  "audience"="test-audience"`,
					`"level"=0 "msg"="discovered OIDC CA bundle"  "roots"=1`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return "Error: unable to fetch discovery data from issuer: could not parse response JSON: invalid character 'h' in literal true (expecting 'r')\n"
			},
		},
		{
			name: "when tls information is missing from jwtauthenticator, test fails because discovery fails",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					&conciergev1alpha1.JWTAuthenticator{
						ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"},
						Spec: conciergev1alpha1.JWTAuthenticatorSpec{
							Issuer:   issuerURL,
							Audience: "test-audience",
						},
					},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered JWTAuthenticator"  "name"="test-authenticator"`,
					fmt.Sprintf(`"level"=0 "msg"="discovered OIDC issuer"  "issuer"="%s"`, issuerURL),
					`"level"=0 "msg"="discovered OIDC audience"  "audience"="test-audience"`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return fmt.Sprintf("Error: unable to fetch discovery data from issuer: Get \"%s/.well-known/openid-configuration\": x509: certificate signed by unknown authority\n", issuerURL)
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
					&conciergev1alpha1.JWTAuthenticator{
						ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"},
						Spec: conciergev1alpha1.JWTAuthenticatorSpec{
							Issuer:   issuerURL,
							Audience: "test-audience",
						},
					},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered JWTAuthenticator"  "name"="test-authenticator"`,
					`"level"=0 "msg"="discovered OIDC audience"  "audience"="test-audience"`,
				}
			},
			wantError: true,
			wantStderr: func(issuerCABundle string, issuerURL string) string {
				return `Error: while forming request to issuer URL: parse "https%://bad-issuer-url/.well-known/openid-configuration": first path segment in URL cannot contain colon` + "\n"
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
					&conciergev1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered WebhookAuthenticator"  "name"="test-authenticator"`,
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
					&conciergev1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered WebhookAuthenticator"  "name"="test-authenticator"`,
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
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered JWTAuthenticator"  "name"="test-authenticator"`,
					fmt.Sprintf(`"level"=0 "msg"="discovered OIDC issuer"  "issuer"="%s"`, issuerURL),
					`"level"=0 "msg"="discovered OIDC audience"  "audience"="test-audience"`,
					`"level"=0 "msg"="discovered OIDC CA bundle"  "roots"=1`,
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
						  command: '.../path/to/pinniped'
						  env: []
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
					"--oidc-listen-port", "1234",
					"--oidc-ca-bundle", f.Name(),
					"--oidc-session-cache", "/path/to/cache/dir/sessions.yaml",
					"--oidc-debug-session-cache",
					"--oidc-request-audience", "test-audience",
					"--skip-validation",
					"--generated-name-suffix", "-sso",
					"--credential-cache", "/path/to/cache/dir/credentials.yaml",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					&conciergev1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator"}},
				}
			},
			wantLogs: func(issuerCABundle string, issuerURL string) []string { return nil },
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
						  - --scopes=offline_access,openid,pinniped:request-audience
						  - --skip-browser
						  - --listen-port=1234
						  - --ca-bundle-data=%s
						  - --session-cache=/path/to/cache/dir/sessions.yaml
						  - --debug-session-cache
						  - --request-audience=test-audience
						  command: '.../path/to/pinniped'
						  env: []
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
					&configv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"},
						Status: configv1alpha1.CredentialIssuerStatus{
							Strategies: []configv1alpha1.CredentialIssuerStrategy{
								// This TokenCredentialRequestAPI strategy would normally be chosen, but
								// --concierge-mode=ImpersonationProxy should force it to be skipped.
								{
									Type:           "SomeType",
									Status:         configv1alpha1.SuccessStrategyStatus,
									Reason:         "SomeReason",
									Message:        "Some message",
									LastUpdateTime: metav1.Now(),
									Frontend: &configv1alpha1.CredentialIssuerFrontend{
										Type: configv1alpha1.TokenCredentialRequestAPIFrontendType,
										TokenCredentialRequestAPIInfo: &configv1alpha1.TokenCredentialRequestAPIInfo{
											Server:                   "https://token-credential-request-api-endpoint.test",
											CertificateAuthorityData: "dGVzdC10Y3ItYXBpLWNh",
										},
									},
								},
								// The endpoint and CA from this impersonation proxy strategy should be autodiscovered.
								{
									Type:           "SomeOtherType",
									Status:         configv1alpha1.SuccessStrategyStatus,
									Reason:         "SomeOtherReason",
									Message:        "Some other message",
									LastUpdateTime: metav1.Now(),
									Frontend: &configv1alpha1.CredentialIssuerFrontend{
										Type: configv1alpha1.ImpersonationProxyFrontendType,
										ImpersonationProxyInfo: &configv1alpha1.ImpersonationProxyInfo{
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
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://impersonation-proxy-endpoint.test"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=1`,
					`"level"=0 "msg"="discovered JWTAuthenticator"  "name"="test-authenticator"`,
					fmt.Sprintf(`"level"=0 "msg"="discovered OIDC issuer"  "issuer"="%s"`, issuerURL),
					`"level"=0 "msg"="discovered OIDC audience"  "audience"="test-audience"`,
					`"level"=0 "msg"="discovered OIDC CA bundle"  "roots"=1`,
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
						  - --scopes=offline_access,openid,pinniped:request-audience
						  - --ca-bundle-data=%s
						  - --request-audience=test-audience
						  command: '.../path/to/pinniped'
						  env: []
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
			name: "autodetect impersonation proxy with autodiscovered JWT authenticator",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					&configv1alpha1.CredentialIssuer{
						ObjectMeta: metav1.ObjectMeta{Name: "test-credential-issuer"},
						Status: configv1alpha1.CredentialIssuerStatus{
							Strategies: []configv1alpha1.CredentialIssuerStrategy{
								{
									Type:           "SomeType",
									Status:         configv1alpha1.SuccessStrategyStatus,
									Reason:         "SomeReason",
									Message:        "Some message",
									LastUpdateTime: metav1.Now(),
									Frontend: &configv1alpha1.CredentialIssuerFrontend{
										Type: configv1alpha1.ImpersonationProxyFrontendType,
										ImpersonationProxyInfo: &configv1alpha1.ImpersonationProxyInfo{
											Endpoint:                 "https://impersonation-proxy-endpoint.test",
											CertificateAuthorityData: "dGVzdC1jb25jaWVyZ2UtY2E=",
										},
									},
								},
								{
									Type:           "SomeOtherType",
									Status:         configv1alpha1.SuccessStrategyStatus,
									Reason:         "SomeOtherReason",
									Message:        "Some other message",
									LastUpdateTime: metav1.Now(),
									Frontend: &configv1alpha1.CredentialIssuerFrontend{
										Type: configv1alpha1.ImpersonationProxyFrontendType,
										ImpersonationProxyInfo: &configv1alpha1.ImpersonationProxyInfo{
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
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in impersonation proxy mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://impersonation-proxy-endpoint.test"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered JWTAuthenticator"  "name"="test-authenticator"`,
					fmt.Sprintf(`"level"=0 "msg"="discovered OIDC issuer"  "issuer"="%s"`, issuerURL),
					`"level"=0 "msg"="discovered OIDC audience"  "audience"="test-audience"`,
					`"level"=0 "msg"="discovered OIDC CA bundle"  "roots"=1`,
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
						  - --scopes=offline_access,openid,pinniped:request-audience
						  - --ca-bundle-data=%s
						  - --request-audience=test-audience
						  command: '.../path/to/pinniped'
						  env: []
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "Find LDAP idp in discovery document, output ldap related flags",
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
			discoveryResponse: here.Docf(`{
				"pinniped_idps": [{"name": "some-ldap-idp", "type": "ldap"}]
			}`),
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered JWTAuthenticator"  "name"="test-authenticator"`,
					fmt.Sprintf(`"level"=0 "msg"="discovered OIDC issuer"  "issuer"="%s"`, issuerURL),
					`"level"=0 "msg"="discovered OIDC audience"  "audience"="test-audience"`,
					`"level"=0 "msg"="discovered OIDC CA bundle"  "roots"=1`,
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
						  - --upstream-identity-provider-name=some-ldap-idp
						  - --upstream-identity-provider-type=ldap
						  command: '.../path/to/pinniped'
						  env: []
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "Find OIDC idp in discovery document, output oidc related flags",
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
			discoveryResponse: here.Docf(`{
				"pinniped_idps": [{"name": "some-oidc-idp", "type": "oidc"}]
			}`),
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered JWTAuthenticator"  "name"="test-authenticator"`,
					fmt.Sprintf(`"level"=0 "msg"="discovered OIDC issuer"  "issuer"="%s"`, issuerURL),
					`"level"=0 "msg"="discovered OIDC audience"  "audience"="test-audience"`,
					`"level"=0 "msg"="discovered OIDC CA bundle"  "roots"=1`,
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
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "empty idp list in discovery document",
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
			discoveryResponse: here.Docf(`{
				"pinniped_idps": []
			}`),
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered JWTAuthenticator"  "name"="test-authenticator"`,
					fmt.Sprintf(`"level"=0 "msg"="discovered OIDC issuer"  "issuer"="%s"`, issuerURL),
					`"level"=0 "msg"="discovered OIDC audience"  "audience"="test-audience"`,
					`"level"=0 "msg"="discovered OIDC CA bundle"  "roots"=1`,
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
						  command: '.../path/to/pinniped'
						  env: []
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "when discovery document 404s, dont set idp related flags",
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
			discoveryStatusCode: http.StatusNotFound,
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered JWTAuthenticator"  "name"="test-authenticator"`,
					fmt.Sprintf(`"level"=0 "msg"="discovered OIDC issuer"  "issuer"="%s"`, issuerURL),
					`"level"=0 "msg"="discovered OIDC audience"  "audience"="test-audience"`,
					`"level"=0 "msg"="discovered OIDC CA bundle"  "roots"=1`,
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
						  command: '.../path/to/pinniped'
						  env: []
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "when upstream idp related flags are sent, pass them through",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--upstream-identity-provider-name=some-oidc-idp",
					"--upstream-identity-provider-type=oidc",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			discoveryStatusCode: http.StatusNotFound,
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered JWTAuthenticator"  "name"="test-authenticator"`,
					fmt.Sprintf(`"level"=0 "msg"="discovered OIDC issuer"  "issuer"="%s"`, issuerURL),
					`"level"=0 "msg"="discovered OIDC audience"  "audience"="test-audience"`,
					`"level"=0 "msg"="discovered OIDC CA bundle"  "roots"=1`,
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
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
		{
			name: "when upstream idp related flags are sent, pass them through even when discovery shows a different idp",
			args: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					"--kubeconfig", "./testdata/kubeconfig.yaml",
					"--skip-validation",
					"--upstream-identity-provider-name=some-oidc-idp",
					"--upstream-identity-provider-type=oidc",
				}
			},
			conciergeObjects: func(issuerCABundle string, issuerURL string) []runtime.Object {
				return []runtime.Object{
					credentialIssuer(),
					jwtAuthenticator(issuerCABundle, issuerURL),
				}
			},
			discoveryResponse: here.Docf(`{
				"pinniped_idps": [{"name": "some-other-ldap-idp", "type": "ldap"}]
			}`),
			wantLogs: func(issuerCABundle string, issuerURL string) []string {
				return []string{
					`"level"=0 "msg"="discovered CredentialIssuer"  "name"="test-credential-issuer"`,
					`"level"=0 "msg"="discovered Concierge operating in TokenCredentialRequest API mode"`,
					`"level"=0 "msg"="discovered Concierge endpoint"  "endpoint"="https://fake-server-url-value"`,
					`"level"=0 "msg"="discovered Concierge certificate authority bundle"  "roots"=0`,
					`"level"=0 "msg"="discovered JWTAuthenticator"  "name"="test-authenticator"`,
					fmt.Sprintf(`"level"=0 "msg"="discovered OIDC issuer"  "issuer"="%s"`, issuerURL),
					`"level"=0 "msg"="discovered OIDC audience"  "audience"="test-audience"`,
					`"level"=0 "msg"="discovered OIDC CA bundle"  "roots"=1`,
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
			discoveryResponse: here.Docf(`{
				"pinniped_idps": [{"name": "some-ldap-idp", "type": "ldap"}]
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
						  - --scopes=offline_access,openid,pinniped:request-audience
						  - --ca-bundle-data=%s
						  - --upstream-identity-provider-name=some-ldap-idp
						  - --upstream-identity-provider-type=ldap
						  command: '.../path/to/pinniped'
						  env: []
						  provideClusterInfo: true
					`,
					issuerURL,
					base64.StdEncoding.EncodeToString([]byte(issuerCABundle)))
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// TODO multiple idps should error
			// TODO partial discovery: specify issuer, don't specify idp type or name
			// TODO if only idp type or only idp name is specified, not both, still do discovery and do some fancy checking or something
			// TODO logging the values we discover?

			issuerCABundle, issuerEndpoint := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/.well-known/openid-configuration" {
					jsonResponseBody := tt.discoveryResponse
					if tt.discoveryResponse == "" {
						jsonResponseBody = "{}"
					}
					if tt.discoveryStatusCode == 0 {
						tt.discoveryStatusCode = http.StatusOK
					}
					w.WriteHeader(tt.discoveryStatusCode)
					_, err = w.Write([]byte(jsonResponseBody))
					require.NoError(t, err)
				} else {
					t.Fatalf("tried to call issuer at a path that wasn't the discovery endpoint.")
				}
			})

			testLog := testlogger.New(t)
			cmd := kubeconfigCommand(kubeconfigDeps{
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
					fake := fakeconciergeclientset.NewSimpleClientset()
					if tt.conciergeObjects != nil {
						fake = fakeconciergeclientset.NewSimpleClientset(tt.conciergeObjects(issuerCABundle, issuerEndpoint)...)
					}
					if len(tt.conciergeReactions) > 0 {
						fake.ReactionChain = append(tt.conciergeReactions, fake.ReactionChain...)
					}
					return fake, nil
				},
				log: testLog,
			})
			require.NotNil(t, cmd)

			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)

			cmd.SetArgs(tt.args(issuerCABundle, issuerEndpoint))

			err := cmd.Execute()
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			var expectedLogs []string
			if tt.wantLogs != nil {
				expectedLogs = tt.wantLogs(issuerCABundle, issuerEndpoint)
			}
			testLog.Expect(expectedLogs)

			expectedStdout := ""
			if tt.wantStdout != nil {
				expectedStdout = tt.wantStdout(issuerCABundle, issuerEndpoint)
			}
			require.Equal(t, expectedStdout, stdout.String(), "unexpected stdout")

			expectedStderr := ""
			if tt.wantStderr != nil {
				expectedStderr = tt.wantStderr(issuerCABundle, issuerEndpoint)
			}
			require.Equal(t, expectedStderr, stderr.String(), "unexpected stderr")
		})
	}
}
