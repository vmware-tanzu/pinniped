// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	"go.pinniped.dev/internal/oidcclientsecretstorage"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/test/testlib"
)

func TestOIDCClientStaticValidation_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	adminClient := testlib.NewKubernetesClientset(t)

	needsErrFix := testutil.KubeServerMinorVersionInBetweenInclusive(t, adminClient.Discovery(), 0, 23)
	reallyOld := testutil.KubeServerMinorVersionInBetweenInclusive(t, adminClient.Discovery(), 0, 19)
	noSets := testutil.KubeServerMinorVersionInBetweenInclusive(t, adminClient.Discovery(), 0, 17)

	groupFix := strings.NewReplacer(".supervisor.pinniped.dev", ".supervisor."+env.APIGroupSuffix)
	errFix := strings.NewReplacer(makeErrFix(reallyOld)...)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	namespaceClient := adminClient.CoreV1().Namespaces()

	ns, err := namespaceClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-oidc-client-",
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, namespaceClient.Delete(ctx, ns.Name, metav1.DeleteOptions{}))
	})

	oidcClients := testlib.NewSupervisorClientset(t).ConfigV1alpha1().OIDCClients(ns.Name)

	tests := []struct {
		name    string
		client  *supervisorconfigv1alpha1.OIDCClient
		fixWant func(t *testing.T, err error, want string) string
		wantErr string
		skip    bool
	}{
		{
			name: "bad name",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name: "panda",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{
						"https://a",
					},
					AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{
						"refresh_token",
					},
					AllowedScopes: []supervisorconfigv1alpha1.Scope{
						"username",
					},
				},
			},
			wantErr: `OIDCClient.config.supervisor.pinniped.dev "panda" is invalid: metadata.name: Invalid value: "panda": metadata.name in body should match '^client\.oauth\.pinniped\.dev-'`,
		},
		{
			name: "bad name but close",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name: "client0oauth1pinniped2dev-regex",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{
						"https://a",
					},
					AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{
						"refresh_token",
					},
					AllowedScopes: []supervisorconfigv1alpha1.Scope{
						"username",
					},
				},
			},
			wantErr: `OIDCClient.config.supervisor.pinniped.dev "client0oauth1pinniped2dev-regex" is invalid: metadata.name: Invalid value: "client0oauth1pinniped2dev-regex": metadata.name in body should match '^client\.oauth\.pinniped\.dev-'`,
		},
		{
			name: "bad generate name",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "snorlax-",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{
						"http://127.0.0.1/callback",
					},
					AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{
						"refresh_token",
					},
					AllowedScopes: []supervisorconfigv1alpha1.Scope{
						"username",
					},
				},
			},
			fixWant: func(t *testing.T, err error, want string) string {
				require.Error(t, err)
				gotErr := err.Error()
				errPrefix := groupFix.Replace(`OIDCClient.config.supervisor.pinniped.dev "snorlax-`)
				require.True(t, strings.HasPrefix(gotErr, errPrefix))
				gotErr = strings.TrimPrefix(gotErr, errPrefix)
				end := strings.Index(gotErr, `"`)
				require.Equal(t, end, 5)
				gotErr = gotErr[:end]
				if reallyOld { // these servers do not show the actual invalid value
					want = strings.Replace(want, `Invalid value: "snorlax-RAND"`, `Invalid value: ""`, 1)
				}
				return strings.Replace(want, "RAND", gotErr, 2)
			},
			wantErr: `OIDCClient.config.supervisor.pinniped.dev "snorlax-RAND" is invalid: metadata.name: Invalid value: "snorlax-RAND": metadata.name in body should match '^client\.oauth\.pinniped\.dev-'`,
		},
		{
			name: "bad redirect uri",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name: "client.oauth.pinniped.dev-hello",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{
						"http://127.0.0.1/callback",
						"oob",
						"https://a",
					},
					AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{
						"refresh_token",
					},
					AllowedScopes: []supervisorconfigv1alpha1.Scope{
						"username",
					},
				},
			},
			wantErr: `OIDCClient.config.supervisor.pinniped.dev "client.oauth.pinniped.dev-hello" is invalid: spec.allowedRedirectURIs[1]: Invalid value: "oob": spec.allowedRedirectURIs[1] in body should match '^https://.+|^http://(127\.0\.0\.1|\[::1\])(:\d+)?/'`,
		},
		{
			name: "bad grant type",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name: "client.oauth.pinniped.dev-sky",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{
						"http://127.0.0.1/callback",
					},
					AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{
						"refresh_token",
						"authorization_code",
						"bird",
					},
					AllowedScopes: []supervisorconfigv1alpha1.Scope{
						"username",
					},
				},
			},
			wantErr: `OIDCClient.config.supervisor.pinniped.dev "client.oauth.pinniped.dev-sky" is invalid: spec.allowedGrantTypes[2]: Unsupported value: "bird": supported values: "authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"`,
		},
		{
			name: "bad scope",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name: "client.oauth.pinniped.dev-blue",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{
						"http://127.0.0.1/callback",
					},
					AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{
						"refresh_token",
					},
					AllowedScopes: []supervisorconfigv1alpha1.Scope{
						"*",
						"username",
					},
				},
			},
			wantErr: `OIDCClient.config.supervisor.pinniped.dev "client.oauth.pinniped.dev-blue" is invalid: spec.allowedScopes[0]: Unsupported value: "*": supported values: "openid", "offline_access", "username", "groups", "pinniped:request-audience"`,
		},
		{
			name:    "empty unset all",
			client:  &supervisorconfigv1alpha1.OIDCClient{},
			wantErr: `OIDCClient.config.supervisor.pinniped.dev "" is invalid: [metadata.name: Required value: name or generateName is required, spec.allowedGrantTypes: Required value, spec.allowedRedirectURIs: Required value, spec.allowedScopes: Required value]`,
			skip:    reallyOld, // the error is both different and has unstable order on older servers
		},
		{
			name: "empty uris",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name: "client.oauth.pinniped.dev-green-1",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{},
					AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{
						"refresh_token",
					},
					AllowedScopes: []supervisorconfigv1alpha1.Scope{
						"username",
					},
				},
			},
			wantErr: `OIDCClient.config.supervisor.pinniped.dev "client.oauth.pinniped.dev-green-1" is invalid: spec.allowedRedirectURIs: Invalid value: 0: spec.allowedRedirectURIs in body should have at least 1 items`,
		},
		{
			name: "empty grants",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name: "client.oauth.pinniped.dev-green-2",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{
						"http://127.0.0.1/callback",
					},
					AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{},
					AllowedScopes: []supervisorconfigv1alpha1.Scope{
						"username",
					},
				},
			},
			wantErr: `OIDCClient.config.supervisor.pinniped.dev "client.oauth.pinniped.dev-green-2" is invalid: spec.allowedGrantTypes: Invalid value: 0: spec.allowedGrantTypes in body should have at least 1 items`,
		},
		{
			name: "empty scopes",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name: "client.oauth.pinniped.dev-green-3",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{
						"http://127.0.0.1/callback",
					},
					AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{
						"refresh_token",
					},
					AllowedScopes: []supervisorconfigv1alpha1.Scope{},
				},
			},
			wantErr: `OIDCClient.config.supervisor.pinniped.dev "client.oauth.pinniped.dev-green-3" is invalid: spec.allowedScopes: Invalid value: 0: spec.allowedScopes in body should have at least 1 items`,
		},
		{
			name: "duplicate uris",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name: "client.oauth.pinniped.dev-red-1",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{
						"http://127.0.0.1/callback",
						"http://127.0.0.1/callback",
					},
					AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{
						"refresh_token",
					},
					AllowedScopes: []supervisorconfigv1alpha1.Scope{
						"username",
					},
				},
			},
			wantErr: `OIDCClient.config.supervisor.pinniped.dev "client.oauth.pinniped.dev-red-1" is invalid: spec.allowedRedirectURIs[1]: Duplicate value: "http://127.0.0.1/callback"`,
			skip:    noSets, // needs v1.18+ for x-kubernetes-list-type: set
		},
		{
			name: "duplicate grants",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name: "client.oauth.pinniped.dev-red-2",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{
						"http://127.0.0.1/callback",
					},
					AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{
						"refresh_token",
						"refresh_token",
					},
					AllowedScopes: []supervisorconfigv1alpha1.Scope{
						"username",
					},
				},
			},
			wantErr: `OIDCClient.config.supervisor.pinniped.dev "client.oauth.pinniped.dev-red-2" is invalid: spec.allowedGrantTypes[1]: Duplicate value: "refresh_token"`,
			skip:    noSets, // needs v1.18+ for x-kubernetes-list-type: set
		},
		{
			name: "duplicate scopes",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name: "client.oauth.pinniped.dev-red-3",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{
						"http://127.0.0.1/callback",
					},
					AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{
						"refresh_token",
					},
					AllowedScopes: []supervisorconfigv1alpha1.Scope{
						"username",
						"username",
					},
				},
			},
			wantErr: `OIDCClient.config.supervisor.pinniped.dev "client.oauth.pinniped.dev-red-3" is invalid: spec.allowedScopes[1]: Duplicate value: "username"`,
			skip:    noSets, // needs v1.18+ for x-kubernetes-list-type: set
		},
		{
			name: "bad everything",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name: "zone",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{
						"of",
					},
					AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{
						"the",
					},
					AllowedScopes: []supervisorconfigv1alpha1.Scope{
						"enders",
					},
				},
			},
			fixWant: func(t *testing.T, err error, want string) string {
				// sort the error causes and use that to rebuild a sorted error message
				statusErr := &errors.StatusError{}
				require.ErrorAs(t, err, &statusErr)
				require.Len(t, statusErr.ErrStatus.Details.Causes, 4)
				out := make([]string, 0, len(statusErr.ErrStatus.Details.Causes))
				for _, cause := range statusErr.ErrStatus.Details.Causes {
					cause := cause
					out = append(out, fmt.Sprintf("%s: %s", cause.Field, cause.Message))
				}
				sort.Strings(out)
				errPrefix := groupFix.Replace(`OIDCClient.config.supervisor.pinniped.dev "zone" is invalid: [`)
				require.True(t, strings.HasPrefix(err.Error(), errPrefix))
				require.Equal(t, err.Error(), statusErr.ErrStatus.Message)
				statusErr.ErrStatus.Message = errPrefix + strings.Join(out, ", ") + "]"
				return want // leave the wanted error unchanged
			},
			wantErr: `OIDCClient.config.supervisor.pinniped.dev "zone" is invalid: [metadata.name: Invalid value: "zone": metadata.name in body should match '^client\.oauth\.pinniped\.dev-', spec.allowedGrantTypes[0]: Unsupported value: "the": supported values: "authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange", spec.allowedRedirectURIs[0]: Invalid value: "of": spec.allowedRedirectURIs[0] in body should match '^https://.+|^http://(127\.0\.0\.1|\[::1\])(:\d+)?/', spec.allowedScopes[0]: Unsupported value: "enders": supported values: "openid", "offline_access", "username", "groups", "pinniped:request-audience"]`,
		},
		{
			name: "everything valid",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name: "client.oauth.pinniped.dev-lava",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{
						"https://example.com",
						"http://127.0.0.1/yoyo",
					},
					AllowedGrantTypes: []supervisorconfigv1alpha1.GrantType{
						"authorization_code",
						"refresh_token",
						"urn:ietf:params:oauth:grant-type:token-exchange",
					},
					AllowedScopes: []supervisorconfigv1alpha1.Scope{
						"openid",
						"offline_access",
						"username",
						"groups",
						"pinniped:request-audience",
					},
				},
			},
			wantErr: "",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip {
				t.Skip()
			}

			t.Parallel()

			client, err := oidcClients.Create(ctx, tt.client, metav1.CreateOptions{})

			want := tt.wantErr

			if len(want) == 0 {
				require.NoError(t, err)

				// unset server generated fields
				client.Namespace = ""
				client.UID = ""
				client.ResourceVersion = ""
				client.ManagedFields = nil
				client.CreationTimestamp = metav1.Time{}
				client.Generation = 0
				client.SelfLink = "" // nolint: staticcheck  // old API servers still set this field

				require.Equal(t, tt.client, client)
				return
			}

			if tt.fixWant != nil {
				want = tt.fixWant(t, err, want)
			}

			want = groupFix.Replace(want)

			// old API servers have slightly different error messages
			if needsErrFix && !strings.Contains(want, "Duplicate value:") {
				want = errFix.Replace(want)
			}

			require.EqualError(t, err, want)
		})
	}
}

func makeErrFix(reallyOld bool) []string {
	const total = 10                  // should be enough indexes
	out := make([]string, 0, total*6) // good enough allocation

	// these servers do not show the actual index of where the error occurred
	for i := 0; i < total; i++ {
		idx := fmt.Sprintf("[%d]", i)
		out = append(out, idx+":", ":")
		out = append(out, idx+" ", " ")
	}

	if reallyOld {
		// these servers display empty values differently
		out = append(out, "0:", `"":`)

		// these servers do not show the actual invalid value
		for _, s := range []string{
			"of",
			"oob",
			"zone",
			"panda",
			"client0oauth1pinniped2dev-regex",
		} {
			out = append(out,
				fmt.Sprintf(`Invalid value: "%s"`, s),
				`Invalid value: ""`)
		}
	}

	return out
}

func TestOIDCClientControllerValidations_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	secrets := testlib.NewKubernetesClientset(t).CoreV1().Secrets(env.SupervisorNamespace)
	oidcClients := testlib.NewSupervisorClientset(t).ConfigV1alpha1().OIDCClients(env.SupervisorNamespace)

	tests := []struct {
		name           string
		client         *supervisorconfigv1alpha1.OIDCClient
		secret         *corev1.Secret
		wantPhase      string
		wantConditions []supervisorconfigv1alpha1.Condition
	}{
		{
			name: "invalid AllowedGrantTypes and AllowedScopes (missing minimum required values), with no Secret",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "client.oauth.pinniped.dev-",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{"https://some-redirect-url.test.pinniped.dev/some/path"},
					AllowedGrantTypes:   []supervisorconfigv1alpha1.GrantType{"refresh_token"}, // needs to have authorization_code
					AllowedScopes:       []supervisorconfigv1alpha1.Scope{"username"},          // needs to have openid
				},
			},
			wantPhase: "Error",
			wantConditions: []supervisorconfigv1alpha1.Condition{
				{
					Type:    "AllowedGrantTypesValid",
					Status:  "False",
					Reason:  "MissingRequiredValue",
					Message: `"authorization_code" must always be included in "allowedGrantTypes"`,
				},
				{
					Type:    "AllowedScopesValid",
					Status:  "False",
					Reason:  "MissingRequiredValue",
					Message: `"openid" must always be included in "allowedScopes"; "offline_access" must be included in "allowedScopes" when "refresh_token" is included in "allowedGrantTypes"`,
				},
				{
					Type:    "ClientSecretExists",
					Status:  "False",
					Reason:  "NoClientSecretFound",
					Message: `no client secret found (no Secret storage found)`,
				},
			},
		},
		{
			name: "minimal valid AllowedGrantTypes and AllowedScopes, with Secret that contains empty list of client secrets",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "client.oauth.pinniped.dev-",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{"https://some-redirect-url.test.pinniped.dev/some/path"},
					AllowedGrantTypes:   []supervisorconfigv1alpha1.GrantType{"authorization_code"},
					AllowedScopes:       []supervisorconfigv1alpha1.Scope{"openid"},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"storage.pinniped.dev/type": "oidc-client-secret"},
				},
				Type: "storage.pinniped.dev/oidc-client-secret",
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"version":"1","hashes":[]}`),
					"pinniped-storage-version": []byte("1"),
				},
			},
			wantPhase: "Error",
			wantConditions: []supervisorconfigv1alpha1.Condition{
				{
					Type:    "AllowedGrantTypesValid",
					Status:  "True",
					Reason:  "Success",
					Message: `"allowedGrantTypes" is valid`,
				},
				{
					Type:    "AllowedScopesValid",
					Status:  "True",
					Reason:  "Success",
					Message: `"allowedScopes" is valid`,
				},
				{
					Type:    "ClientSecretExists",
					Status:  "False",
					Reason:  "NoClientSecretFound",
					Message: `no client secret found (empty list in storage)`,
				},
			},
		},
		{
			name: "happy path example with one client secret stored and all possible AllowedGrantTypes and AllowedScopes",
			client: &supervisorconfigv1alpha1.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "client.oauth.pinniped.dev-",
				},
				Spec: supervisorconfigv1alpha1.OIDCClientSpec{
					AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{"https://some-redirect-url.test.pinniped.dev/some/path"},
					AllowedGrantTypes:   []supervisorconfigv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
					AllowedScopes:       []supervisorconfigv1alpha1.Scope{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"storage.pinniped.dev/type": "oidc-client-secret"},
				},
				Type: "storage.pinniped.dev/oidc-client-secret",
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"version":"1","hashes":["$2y$15$Kh7cRj0ScSD5QelE3ZNSl.nF04JDv7zb3SgGN.tSfLIX.4kt3UX7m"]}`),
					"pinniped-storage-version": []byte("1"),
				},
			},
			wantPhase: "Ready",
			wantConditions: []supervisorconfigv1alpha1.Condition{
				{
					Type:    "AllowedGrantTypesValid",
					Status:  "True",
					Reason:  "Success",
					Message: `"allowedGrantTypes" is valid`,
				},
				{
					Type:    "AllowedScopesValid",
					Status:  "True",
					Reason:  "Success",
					Message: `"allowedScopes" is valid`,
				},
				{
					Type:    "ClientSecretExists",
					Status:  "True",
					Reason:  "Success",
					Message: `1 client secret(s) found`,
				},
			},
		},
		// Note: there are many more possible combinations of these settings, but they are covered by the controller's
		// unit tests. This test ensures that everything is wired up correctly in regard to this controller, enough to
		// allow the controller to work correctly.
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, err := oidcClients.Create(ctx, tt.client, metav1.CreateOptions{})
			require.NoError(t, err)
			t.Cleanup(func() {
				t.Logf("cleaning up test OIDCClient %s/%s", client.Namespace, client.Name)
				err := oidcClients.Delete(ctx, client.Name, metav1.DeleteOptions{})
				require.NoError(t, err)
			})

			if tt.secret != nil {
				// Force the Secret's name to match the client created above.
				tt.secret.Name = oidcclientsecretstorage.New(nil).GetName(client.UID)
				secret, err := secrets.Create(ctx, tt.secret, metav1.CreateOptions{})
				require.NoError(t, err)
				t.Cleanup(func() {
					t.Logf("cleaning up test Secret %s/%s", secret.Namespace, secret.Name)
					err := secrets.Delete(ctx, secret.Name, metav1.DeleteOptions{})
					require.NoError(t, err)
				})
			}

			// Wait for the OIDCClient to enter the expected phase (or time out).
			testlib.RequireEventuallyf(t, func(requireEventually *require.Assertions) {
				var err error
				updatedClient, err := oidcClients.Get(ctx, client.Name, metav1.GetOptions{})
				requireEventually.NoErrorf(err, "error while getting OIDCClient %s/%s", client.Namespace, client.Name)
				requireEventually.Equalf(supervisorconfigv1alpha1.OIDCClientPhase(tt.wantPhase), updatedClient.Status.Phase,
					"OIDCClient is not in phase %s: %v", tt.wantPhase, testlib.Sdump(updatedClient))
			}, 1*time.Minute, 2*time.Second, "expected the OIDCClient to go into phase %s", tt.wantPhase)

			// Wait for the controller to converge to the expected Conditions list. It may take several passes of the
			// controller running, since the Secret is created after the OIDCClient is created, potentially causing
			// the controller to Sync at least twice.
			testlib.RequireEventuallyf(t, func(requireEventually *require.Assertions) {
				var err error
				updatedClient, err := oidcClients.Get(ctx, client.Name, metav1.GetOptions{})
				requireEventually.NoErrorf(err, "error while getting OIDCClient %s/%s", client.Namespace, client.Name)

				// Note that the controller sorts the conditions by type name,
				// so we can assume that ordering in the test expectations for this test.
				requireEventually.Len(updatedClient.Status.Conditions, len(tt.wantConditions))
				for i, want := range tt.wantConditions {
					actual := updatedClient.Status.Conditions[i]
					requireEventually.Equal(want.Type, actual.Type)
					requireEventually.Equal(want.Status, actual.Status)
					requireEventually.Equal(want.Reason, actual.Reason)
					requireEventually.Equal(want.Message, actual.Message)
					requireEventually.Equal(updatedClient.Generation, actual.ObservedGeneration)
					requireEventually.NotEmpty(actual.LastTransitionTime)
				}
			}, 1*time.Minute, 2*time.Second, "expected the OIDCClient to to have conditions %v", tt.wantConditions)
		})
	}
}
