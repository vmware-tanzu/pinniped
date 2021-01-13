// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/clientcmd"

	conciergev1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/authentication/v1alpha1"
	conciergeclientset "go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned"
	fakeconciergeclientset "go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned/fake"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/testutil"
)

func TestGetKubeconfig(t *testing.T) {
	testCA, err := certauthority.New(pkix.Name{CommonName: "Test CA"}, 1*time.Hour)
	require.NoError(t, err)
	tmpdir := testutil.TempDir(t)
	testCABundlePath := filepath.Join(tmpdir, "testca.pem")
	require.NoError(t, ioutil.WriteFile(testCABundlePath, testCA.Bundle(), 0600))

	tests := []struct {
		name               string
		args               []string
		env                map[string]string
		getPathToSelfErr   error
		getClientsetErr    error
		conciergeObjects   []runtime.Object
		conciergeReactions []kubetesting.Reactor
		wantError          bool
		wantStdout         string
		wantStderr         string
		wantOptionsCount   int
		wantAPIGroupSuffix string
	}{
		{
			name: "help flag passed",
			args: []string{"--help"},
			wantStdout: here.Doc(`
				Generate a Pinniped-based kubeconfig for a cluster

				Usage:
				  kubeconfig [flags]

				Flags:
				      --concierge-api-group-suffix string     Concierge API group suffix (default "pinniped.dev")
				      --concierge-authenticator-name string   Concierge authenticator name (default: autodiscover)
				      --concierge-authenticator-type string   Concierge authenticator type (e.g., 'webhook', 'jwt') (default: autodiscover)
				      --concierge-namespace string            Namespace in which the concierge was installed (default "pinniped-concierge")
				  -h, --help                                  help for kubeconfig
				      --kubeconfig string                     Path to kubeconfig file
				      --kubeconfig-context string             Kubeconfig context name (default: current active context)
				      --no-concierge                          Generate a configuration which does not use the concierge, but sends the credential to the cluster directly
				      --oidc-ca-bundle strings                Path to TLS certificate authority bundle (PEM format, optional, can be repeated)
				      --oidc-client-id string                 OpenID Connect client ID (default: autodiscover) (default "pinniped-cli")
				      --oidc-issuer string                    OpenID Connect issuer URL (default: autodiscover)
				      --oidc-listen-port uint16               TCP port for localhost listener (authorization code flow only)
				      --oidc-request-audience string          Request a token with an alternate audience using RFC8693 token exchange
				      --oidc-scopes strings                   OpenID Connect scopes to request during login (default [offline_access,openid,pinniped:request-audience])
				      --oidc-session-cache string             Path to OpenID Connect session cache file
				      --oidc-skip-browser                     During OpenID Connect login, skip opening the browser (just print the URL)
				      --static-token string                   Instead of doing an OIDC-based login, specify a static token
				      --static-token-env string               Instead of doing an OIDC-based login, read a static token from the environment
			`),
		},
		{
			name:             "fail to get self-path",
			args:             []string{},
			getPathToSelfErr: fmt.Errorf("some OS error"),
			wantError:        true,
			wantStderr: here.Doc(`
				Error: could not determine the Pinniped executable path: some OS error
			`),
		},
		{
			name: "invalid CA bundle paths",
			args: []string{
				"--oidc-ca-bundle", "./does/not/exist",
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: could not read --oidc-ca-bundle: open ./does/not/exist: no such file or directory
			`),
		},
		{
			name: "invalid kubeconfig path",
			args: []string{
				"--kubeconfig", "./does/not/exist",
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: could not load --kubeconfig: stat ./does/not/exist: no such file or directory
			`),
		},
		{
			name: "invalid kubeconfig context",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
				"--kubeconfig-context", "invalid",
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: could not load --kubeconfig/--kubeconfig-context: no such context "invalid"
			`),
		},
		{
			name: "clientset creation failure",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
			},
			getClientsetErr: fmt.Errorf("some kube error"),
			wantError:       true,
			wantStderr: here.Doc(`
				Error: could not configure Kubernetes client: some kube error
			`),
		},
		{
			name: "webhook authenticator not found",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
				"--concierge-authenticator-type", "webhook",
				"--concierge-authenticator-name", "test-authenticator",
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: webhookauthenticators.authentication.concierge.pinniped.dev "test-authenticator" not found
			`),
		},
		{
			name: "JWT authenticator not found",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
				"--concierge-authenticator-type", "jwt",
				"--concierge-authenticator-name", "test-authenticator",
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: jwtauthenticators.authentication.concierge.pinniped.dev "test-authenticator" not found
			`),
		},
		{
			name: "invalid authenticator type",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
				"--concierge-authenticator-type", "invalid",
				"--concierge-authenticator-name", "test-authenticator",
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: invalid authenticator type "invalid", supported values are "webhook" and "jwt"
			`),
		},
		{
			name: "fail to autodetect authenticator, listing jwtauthenticators fails",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
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
			wantStderr: here.Doc(`
				Error: failed to list JWTAuthenticator objects for autodiscovery: some list error
			`),
		},
		{
			name: "fail to autodetect authenticator, listing webhookauthenticators fails",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
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
			wantError: true,
			wantStderr: here.Doc(`
				Error: failed to list WebhookAuthenticator objects for autodiscovery: some list error
			`),
		},
		{
			name: "fail to autodetect authenticator, none found",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: no authenticators were found in namespace "pinniped-concierge" (try setting --concierge-namespace)
			`),
		},
		{
			name: "fail to autodetect authenticator, multiple found",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
				"--concierge-namespace", "test-namespace",
			},
			conciergeObjects: []runtime.Object{
				&conciergev1alpha1.JWTAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator-1", Namespace: "test-namespace"}},
				&conciergev1alpha1.JWTAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator-2", Namespace: "test-namespace"}},
				&conciergev1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator-3", Namespace: "test-namespace"}},
				&conciergev1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator-4", Namespace: "test-namespace"}},
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: multiple authenticators were found in namespace "test-namespace", so the --concierge-authenticator-type/--concierge-authenticator-name flags must be specified
			`),
		},
		{
			name: "autodetect webhook authenticator, missing --oidc-issuer",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
				"--concierge-namespace", "test-namespace",
			},
			conciergeObjects: []runtime.Object{
				&conciergev1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator", Namespace: "test-namespace"}},
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: could not autodiscover --oidc-issuer, and none was provided
			`),
		},
		{
			name: "autodetect JWT authenticator, invalid TLS bundle",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
				"--concierge-namespace", "test-namespace",
			},
			conciergeObjects: []runtime.Object{
				&conciergev1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator", Namespace: "test-namespace"},
					Spec: conciergev1alpha1.JWTAuthenticatorSpec{
						TLS: &conciergev1alpha1.TLSSpec{
							CertificateAuthorityData: "invalid-base64",
						},
					},
				},
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: tried to autodiscover --oidc-ca-bundle, but JWTAuthenticator test-namespace/test-authenticator has invalid spec.tls.certificateAuthorityData: illegal base64 data at input byte 7
			`),
		},
		{
			name: "invalid static token flags",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
				"--concierge-namespace", "test-namespace",
				"--static-token", "test-token",
				"--static-token-env", "TEST_TOKEN",
			},
			conciergeObjects: []runtime.Object{
				&conciergev1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator", Namespace: "test-namespace"}},
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: only one of --static-token and --static-token-env can be specified
			`),
		},
		{
			name: "invalid api group suffix",
			args: []string{
				"--concierge-api-group-suffix", ".starts.with.dot",
			},
			wantError: true,
			wantStderr: here.Doc(`
				Error: invalid api group suffix: 1 error(s):
				- a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')
			`),
		},
		{
			name: "valid static token",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
				"--concierge-namespace", "test-namespace",
				"--static-token", "test-token",
			},
			conciergeObjects: []runtime.Object{
				&conciergev1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator", Namespace: "test-namespace"}},
			},
			wantStdout: here.Doc(`
        		apiVersion: v1
        		clusters:
        		- cluster:
        		    certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
        		    server: https://fake-server-url-value
        		  name: pinniped
        		contexts:
        		- context:
        		    cluster: pinniped
        		    user: pinniped
        		  name: pinniped
        		current-context: pinniped
        		kind: Config
        		preferences: {}
        		users:
        		- name: pinniped
        		  user:
        		    exec:
        		      apiVersion: client.authentication.k8s.io/v1beta1
        		      args:
        		      - login
        		      - static
        		      - --enable-concierge
        		      - --concierge-api-group-suffix=pinniped.dev
        		      - --concierge-namespace=test-namespace
        		      - --concierge-authenticator-name=test-authenticator
        		      - --concierge-authenticator-type=webhook
        		      - --concierge-endpoint=https://fake-server-url-value
        		      - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
        		      - --token=test-token
        		      command: '.../path/to/pinniped'
        		      env: []
        		      provideClusterInfo: true
			`),
		},
		{
			name: "valid static token from env var",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
				"--concierge-namespace", "test-namespace",
				"--static-token-env", "TEST_TOKEN",
			},
			conciergeObjects: []runtime.Object{
				&conciergev1alpha1.WebhookAuthenticator{ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator", Namespace: "test-namespace"}},
			},
			wantStdout: here.Doc(`
        		apiVersion: v1
        		clusters:
        		- cluster:
        		    certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
        		    server: https://fake-server-url-value
        		  name: pinniped
        		contexts:
        		- context:
        		    cluster: pinniped
        		    user: pinniped
        		  name: pinniped
        		current-context: pinniped
        		kind: Config
        		preferences: {}
        		users:
        		- name: pinniped
        		  user:
        		    exec:
        		      apiVersion: client.authentication.k8s.io/v1beta1
        		      args:
        		      - login
        		      - static
        		      - --enable-concierge
        		      - --concierge-api-group-suffix=pinniped.dev
        		      - --concierge-namespace=test-namespace
        		      - --concierge-authenticator-name=test-authenticator
        		      - --concierge-authenticator-type=webhook
        		      - --concierge-endpoint=https://fake-server-url-value
        		      - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
        		      - --token-env=TEST_TOKEN
        		      command: '.../path/to/pinniped'
        		      env: []
        		      provideClusterInfo: true
			`),
		},
		{
			name: "autodetect JWT authenticator",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
			},
			conciergeObjects: []runtime.Object{
				&conciergev1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator", Namespace: "pinniped-concierge"},
					Spec: conciergev1alpha1.JWTAuthenticatorSpec{
						Issuer:   "https://example.com/issuer",
						Audience: "test-audience",
						TLS: &conciergev1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(testCA.Bundle()),
						},
					},
				},
			},
			wantStdout: here.Docf(`
        		apiVersion: v1
        		clusters:
        		- cluster:
        		    certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
        		    server: https://fake-server-url-value
        		  name: pinniped
        		contexts:
        		- context:
        		    cluster: pinniped
        		    user: pinniped
        		  name: pinniped
        		current-context: pinniped
        		kind: Config
        		preferences: {}
        		users:
        		- name: pinniped
        		  user:
        		    exec:
        		      apiVersion: client.authentication.k8s.io/v1beta1
        		      args:
        		      - login
        		      - oidc
        		      - --enable-concierge
        		      - --concierge-api-group-suffix=pinniped.dev
        		      - --concierge-namespace=pinniped-concierge
        		      - --concierge-authenticator-name=test-authenticator
        		      - --concierge-authenticator-type=jwt
        		      - --concierge-endpoint=https://fake-server-url-value
        		      - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
        		      - --issuer=https://example.com/issuer
        		      - --client-id=pinniped-cli
        		      - --scopes=offline_access,openid,pinniped:request-audience
        		      - --ca-bundle-data=%s
        		      - --request-audience=test-audience
        		      command: '.../path/to/pinniped'
        		      env: []
        		      provideClusterInfo: true
			`, base64.StdEncoding.EncodeToString(testCA.Bundle())),
		},
		{
			name: "autodetect nothing, set a bunch of options",
			args: []string{
				"--kubeconfig", "./testdata/kubeconfig.yaml",
				"--concierge-api-group-suffix", "tuna.io",
				"--concierge-authenticator-type", "webhook",
				"--concierge-authenticator-name", "test-authenticator",
				"--oidc-issuer", "https://example.com/issuer",
				"--oidc-skip-browser",
				"--oidc-listen-port", "1234",
				"--oidc-ca-bundle", testCABundlePath,
				"--oidc-session-cache", "/path/to/cache/dir/sessions.yaml",
				"--oidc-debug-session-cache",
				"--oidc-request-audience", "test-audience",
			},
			conciergeObjects: []runtime.Object{
				&conciergev1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{Name: "test-authenticator", Namespace: "pinniped-concierge"},
				},
			},
			wantStdout: here.Docf(`
        		apiVersion: v1
        		clusters:
        		- cluster:
        		    certificate-authority-data: ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
        		    server: https://fake-server-url-value
        		  name: pinniped
        		contexts:
        		- context:
        		    cluster: pinniped
        		    user: pinniped
        		  name: pinniped
        		current-context: pinniped
        		kind: Config
        		preferences: {}
        		users:
        		- name: pinniped
        		  user:
        		    exec:
        		      apiVersion: client.authentication.k8s.io/v1beta1
        		      args:
        		      - login
        		      - oidc
        		      - --enable-concierge
        		      - --concierge-api-group-suffix=tuna.io
        		      - --concierge-namespace=pinniped-concierge
        		      - --concierge-authenticator-name=test-authenticator
        		      - --concierge-authenticator-type=webhook
        		      - --concierge-endpoint=https://fake-server-url-value
        		      - --concierge-ca-bundle-data=ZmFrZS1jZXJ0aWZpY2F0ZS1hdXRob3JpdHktZGF0YS12YWx1ZQ==
        		      - --issuer=https://example.com/issuer
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
			`, base64.StdEncoding.EncodeToString(testCA.Bundle())),
			wantAPIGroupSuffix: "tuna.io",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
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
					fake := fakeconciergeclientset.NewSimpleClientset(tt.conciergeObjects...)
					if len(tt.conciergeReactions) > 0 {
						fake.ReactionChain = tt.conciergeReactions
					}
					return fake, nil
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
		})
	}
}
