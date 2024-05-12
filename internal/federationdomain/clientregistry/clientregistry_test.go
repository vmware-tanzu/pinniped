// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package clientregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	supervisorfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	"go.pinniped.dev/internal/federationdomain/oidcclientvalidator"
	"go.pinniped.dev/internal/oidcclientsecretstorage"
	"go.pinniped.dev/internal/testutil"
)

func TestClientManager(t *testing.T) {
	ctx := context.Background()

	const (
		testName      = "client.oauth.pinniped.dev-test-name"
		testNamespace = "test-namespace"
		testUID       = "test-uid-123"
	)

	tests := []struct {
		name                   string
		secrets                []*corev1.Secret
		oidcClients            []*supervisorconfigv1alpha1.OIDCClient
		addKubeReactions       func(client *fake.Clientset)
		addSupervisorReactions func(client *supervisorfake.Clientset)
		run                    func(t *testing.T, subject *ClientManager)
	}{
		{
			name: "unimplemented methods",
			run: func(t *testing.T, subject *ClientManager) {
				require.EqualError(t, subject.ClientAssertionJWTValid(ctx, "some-token-id"), "not implemented")
				require.EqualError(t, subject.SetClientAssertionJWT(ctx, "some-token-id", time.Now()), "not implemented")
			},
		},
		{
			name: "find pinniped-cli client when no dynamic clients exist",
			run: func(t *testing.T, subject *ClientManager) {
				got, err := subject.GetClient(ctx, "pinniped-cli")
				require.NoError(t, err)
				require.IsType(t, &Client{}, got)
				requireEqualsPinnipedCLI(t, got.(*Client))
			},
		},
		{
			name: "find pinniped-cli client when some dynamic clients also exist",
			oidcClients: []*supervisorconfigv1alpha1.OIDCClient{
				{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID}},
			},
			run: func(t *testing.T, subject *ClientManager) {
				got, err := subject.GetClient(ctx, "pinniped-cli")
				require.NoError(t, err)
				require.IsType(t, &Client{}, got)
				requireEqualsPinnipedCLI(t, got.(*Client))
			},
		},
		{
			name: "client not found",
			oidcClients: []*supervisorconfigv1alpha1.OIDCClient{
				{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID}},
			},
			run: func(t *testing.T, subject *ClientManager) {
				got, err := subject.GetClient(ctx, "does-not-exist")
				require.Error(t, err)
				require.Nil(t, got)
				rfcErr := fosite.ErrorToRFC6749Error(err)
				require.NotNil(t, rfcErr)
				require.Equal(t, rfcErr.CodeField, 404)
				require.Equal(t, rfcErr.GetDescription(), "no such client")
			},
		},
		{
			name: "find a dynamic client when its storage secret does not exist (client is invalid because is has no client secret)",
			oidcClients: []*supervisorconfigv1alpha1.OIDCClient{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
					Spec: supervisorconfigv1alpha1.OIDCClientSpec{
						AllowedGrantTypes:   []supervisorconfigv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
						AllowedScopes:       []supervisorconfigv1alpha1.Scope{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
						AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{"http://localhost:80", "https://foobar.com/callback"},
					},
				},
			},
			run: func(t *testing.T, subject *ClientManager) {
				got, err := subject.GetClient(ctx, testName)
				require.EqualError(t, err, fmt.Sprintf("client %q exists but is invalid or not ready", testName))
				require.Nil(t, got)
			},
		},
		{
			name: "find a dynamic client which is invalid due to its spec",
			oidcClients: []*supervisorconfigv1alpha1.OIDCClient{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
					Spec: supervisorconfigv1alpha1.OIDCClientSpec{
						AllowedGrantTypes:   []supervisorconfigv1alpha1.GrantType{"authorization_code"},
						AllowedScopes:       []supervisorconfigv1alpha1.Scope{}, // at least "openid" is required here, so this makes the client invalid
						AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{"http://localhost:80"},
					},
				},
			},
			secrets: []*corev1.Secret{
				testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost, testutil.HashedPassword2AtSupervisorMinCost}),
			},
			run: func(t *testing.T, subject *ClientManager) {
				got, err := subject.GetClient(ctx, testName)
				require.EqualError(t, err, fmt.Sprintf("client %q exists but is invalid or not ready", testName))
				require.Nil(t, got)
			},
		},
		{
			name: "find a dynamic client which somehow does not have the required prefix in its name, just in case, although should not be possible since prefix is a validation on the CRD",
			oidcClients: []*supervisorconfigv1alpha1.OIDCClient{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "does-not-have-prefix", Generation: 1234, UID: testUID},
					Spec: supervisorconfigv1alpha1.OIDCClientSpec{
						AllowedGrantTypes:   []supervisorconfigv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
						AllowedScopes:       []supervisorconfigv1alpha1.Scope{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
						AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{"http://localhost:80", "https://foobar.com/callback"},
					},
				},
			},
			secrets: []*corev1.Secret{
				testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost, testutil.HashedPassword2AtSupervisorMinCost}),
			},
			run: func(t *testing.T, subject *ClientManager) {
				got, err := subject.GetClient(ctx, "does-not-have-prefix")
				require.Error(t, err)
				require.Nil(t, got)
				rfcErr := fosite.ErrorToRFC6749Error(err)
				require.NotNil(t, rfcErr)
				require.Equal(t, rfcErr.CodeField, 404)
				require.Equal(t, rfcErr.GetDescription(), "no such client")
			},
		},
		{
			name: "when there is an unexpected error getting the OIDCClient",
			addSupervisorReactions: func(client *supervisorfake.Clientset) {
				client.PrependReactor("get", "oidcclients", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("some get OIDCClients error")
				})
			},
			run: func(t *testing.T, subject *ClientManager) {
				got, err := subject.GetClient(ctx, testName)
				require.EqualError(t, err, fmt.Sprintf("failed to get client %q", testName))
				require.Nil(t, got)
			},
		},
		{
			name: "when there is an unexpected error getting the storage secret for the OIDCClient",
			oidcClients: []*supervisorconfigv1alpha1.OIDCClient{
				{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID}},
			},
			addKubeReactions: func(client *fake.Clientset) {
				client.PrependReactor("get", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, fmt.Errorf("some get Secrets error")
				})
			},
			run: func(t *testing.T, subject *ClientManager) {
				got, err := subject.GetClient(ctx, testName)
				require.EqualError(t, err, fmt.Sprintf("failed to get storage secret for client %q", testName))
				require.Nil(t, got)
			},
		},
		{
			name: "find a valid dynamic client without an ID token lifetime configuration",
			oidcClients: []*supervisorconfigv1alpha1.OIDCClient{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
					Spec: supervisorconfigv1alpha1.OIDCClientSpec{
						AllowedGrantTypes:   []supervisorconfigv1alpha1.GrantType{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
						AllowedScopes:       []supervisorconfigv1alpha1.Scope{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
						AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{"http://localhost:80", "https://foobar.com/callback"},
						TokenLifetimes:      supervisorconfigv1alpha1.OIDCClientTokenLifetimes{IDTokenSeconds: nil},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "other-client", Generation: 1234, UID: testUID},
				},
			},
			secrets: []*corev1.Secret{
				testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword1AtSupervisorMinCost, testutil.HashedPassword2AtSupervisorMinCost}),
			},
			run: func(t *testing.T, subject *ClientManager) {
				got, err := subject.GetClient(ctx, testName)
				require.NoError(t, err)
				require.IsType(t, &Client{}, got)
				c := got.(*Client)

				requireDynamicOIDCClient(t, c,
					testName,
					[]string{testutil.HashedPassword1AtSupervisorMinCost, testutil.HashedPassword2AtSupervisorMinCost},
					fosite.Arguments{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
					fosite.Arguments{"openid", "offline_access", "pinniped:request-audience", "username", "groups"},
					[]string{"http://localhost:80", "https://foobar.com/callback"},
					0*time.Second,
				)
			},
		},
		{
			name: "find a valid dynamic client with an ID token lifetime configuration",
			oidcClients: []*supervisorconfigv1alpha1.OIDCClient{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234, UID: testUID},
					Spec: supervisorconfigv1alpha1.OIDCClientSpec{
						AllowedGrantTypes:   []supervisorconfigv1alpha1.GrantType{"authorization_code", "refresh_token"},
						AllowedScopes:       []supervisorconfigv1alpha1.Scope{"openid", "offline_access", "username", "groups"},
						AllowedRedirectURIs: []supervisorconfigv1alpha1.RedirectURI{"http://localhost:8080"},
						TokenLifetimes:      supervisorconfigv1alpha1.OIDCClientTokenLifetimes{IDTokenSeconds: ptr.To[int32](4242)},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "other-client", Generation: 1234, UID: testUID},
				},
			},
			secrets: []*corev1.Secret{
				testutil.OIDCClientSecretStorageSecretForUID(t, testNamespace, testUID, []string{testutil.HashedPassword2AtSupervisorMinCost, testutil.HashedPassword1AtSupervisorMinCost}),
			},
			run: func(t *testing.T, subject *ClientManager) {
				got, err := subject.GetClient(ctx, testName)
				require.NoError(t, err)
				require.IsType(t, &Client{}, got)
				c := got.(*Client)

				requireDynamicOIDCClient(t, c,
					testName,
					[]string{testutil.HashedPassword2AtSupervisorMinCost, testutil.HashedPassword1AtSupervisorMinCost},
					fosite.Arguments{"authorization_code", "refresh_token"},
					fosite.Arguments{"openid", "offline_access", "username", "groups"},
					[]string{"http://localhost:8080"},
					4242*time.Second,
				)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			kubeClient := fake.NewSimpleClientset()
			secrets := kubeClient.CoreV1().Secrets(testNamespace)
			supervisorClient := supervisorfake.NewSimpleClientset()
			oidcClientsClient := supervisorClient.ConfigV1alpha1().OIDCClients(testNamespace)
			subject := NewClientManager(
				oidcClientsClient,
				oidcclientsecretstorage.New(secrets),
				oidcclientvalidator.DefaultMinBcryptCost,
			)

			for _, secret := range test.secrets {
				require.NoError(t, kubeClient.Tracker().Add(secret))
			}
			for _, oidcClient := range test.oidcClients {
				require.NoError(t, supervisorClient.Tracker().Add(oidcClient))
			}
			if test.addKubeReactions != nil {
				test.addKubeReactions(kubeClient)
			}
			if test.addSupervisorReactions != nil {
				test.addSupervisorReactions(supervisorClient)
			}

			test.run(t, subject)
		})
	}
}

func TestPinnipedCLI(t *testing.T) {
	requireEqualsPinnipedCLI(t, PinnipedCLI())
}

func requireEqualsPinnipedCLI(t *testing.T, c *Client) {
	require.Equal(t, "pinniped-cli", c.GetID())
	require.Nil(t, c.GetHashedSecret())
	require.Equal(t, []string{"http://127.0.0.1/callback"}, c.GetRedirectURIs())
	require.Equal(t, fosite.Arguments{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"}, c.GetGrantTypes())
	require.Equal(t, fosite.Arguments{"code"}, c.GetResponseTypes())
	require.Equal(t, fosite.Arguments{coreosoidc.ScopeOpenID, coreosoidc.ScopeOfflineAccess, "profile", "email", "pinniped:request-audience", "username", "groups"}, c.GetScopes())
	require.True(t, c.IsPublic())
	require.Nil(t, c.GetAudience())
	require.Nil(t, c.GetRequestURIs())
	require.Nil(t, c.GetJSONWebKeys())
	require.Equal(t, "", c.GetJSONWebKeysURI())
	require.Equal(t, "", c.GetRequestObjectSigningAlgorithm())
	require.Equal(t, "none", c.GetTokenEndpointAuthMethod())
	require.Equal(t, "RS256", c.GetTokenEndpointAuthSigningAlgorithm())
	require.Equal(t, []fosite.ResponseModeType{"", "query", "form_post"}, c.GetResponseModes())
	require.Equal(t, 0*time.Second, c.GetIDTokenLifetimeConfiguration())

	marshaled, err := json.Marshal(c)
	require.NoError(t, err)
	require.JSONEq(t, `
		{
		  "id": "pinniped-cli",
		  "redirect_uris": [
			"http://127.0.0.1/callback"
		  ],
		  "grant_types": [
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:token-exchange"
		  ],
		  "response_types": [
			"code"
		  ],
		  "scopes": [
			"openid",
			"offline_access",
			"profile",
			"email",
			"pinniped:request-audience",
			"username",
			"groups"
		  ],
		  "audience": null,
		  "public": true,
		  "jwks_uri": "",
		  "jwks": null,
		  "token_endpoint_auth_method": "none",
		  "request_uris": null,
		  "request_object_signing_alg": "",
		  "token_endpoint_auth_signing_alg": "RS256",
		  "IDTokenLifetimeConfiguration": 0
		}`, string(marshaled))
}

func requireDynamicOIDCClient(
	t *testing.T,
	c *Client,
	wantClientID string,
	wantHashes []string,
	wantGrantTypes fosite.Arguments,
	wantScopes fosite.Arguments,
	wantRedirectURIs []string,
	wantIDTokenLifetimeConfiguration time.Duration,
) {
	require.Equal(t, wantClientID, c.GetID())

	require.Len(t, c.GetRotatedHashes(), len(wantHashes))
	for i := range wantHashes {
		require.Equal(t, wantHashes[i], string(c.GetRotatedHashes()[i]))
	}

	require.Equal(t, wantRedirectURIs, c.GetRedirectURIs())
	require.Equal(t, wantGrantTypes, c.GetGrantTypes())
	require.Equal(t, wantScopes, c.GetScopes())
	require.Equal(t, wantIDTokenLifetimeConfiguration, c.GetIDTokenLifetimeConfiguration())

	// The following are always the same for all OIDCClients.
	require.Nil(t, c.GetHashedSecret())
	require.Equal(t, fosite.Arguments{"code"}, c.GetResponseTypes())
	require.False(t, c.IsPublic())
	require.Nil(t, c.GetAudience())
	require.Nil(t, c.GetRequestURIs())
	require.Nil(t, c.GetJSONWebKeys())
	require.Equal(t, "", c.GetJSONWebKeysURI())
	require.Equal(t, "", c.GetRequestObjectSigningAlgorithm())
	require.Equal(t, "client_secret_basic", c.GetTokenEndpointAuthMethod())
	require.Equal(t, "RS256", c.GetTokenEndpointAuthSigningAlgorithm())
	require.Equal(t, []fosite.ResponseModeType{"", "query"}, c.GetResponseModes())
}
