// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/generated/latest/apis/supervisor/clientsecret/v1alpha1"
	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	"go.pinniped.dev/test/testlib"
)

func TestOIDCClientSecretRequest_HappyPath_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)

	client := testlib.NewSupervisorClientset(t)

	oidcClient, err := client.ConfigV1alpha1().OIDCClients(env.SupervisorNamespace).Create(ctx,
		&supervisorconfigv1alpha1.OIDCClient{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "client.oauth.pinniped.dev-",
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
		metav1.CreateOptions{},
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		deleteErr := client.ConfigV1alpha1().OIDCClients(env.SupervisorNamespace).Delete(ctx, oidcClient.Name, metav1.DeleteOptions{})
		require.NoError(t, deleteErr)
	})

	response, err := client.ClientsecretV1alpha1().OIDCClientSecretRequests(env.SupervisorNamespace).Create(ctx,
		&v1alpha1.OIDCClientSecretRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name: oidcClient.Name,
			},
			Spec: v1alpha1.OIDCClientSecretRequestSpec{
				GenerateNewSecret: true,
			},
		}, metav1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, response.Status.TotalClientSecrets, 1)
	require.Len(t, response.Status.GeneratedSecret, hex.EncodedLen(32))
}

func TestOIDCClientSecretRequest_Unauthenticated_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)

	client := testlib.NewAnonymousSupervisorClientset(t)

	_, err := client.ClientsecretV1alpha1().OIDCClientSecretRequests(env.SupervisorNamespace).Create(ctx,
		&v1alpha1.OIDCClientSecretRequest{
			Spec: v1alpha1.OIDCClientSecretRequestSpec{
				GenerateNewSecret: true,
			},
		}, metav1.CreateOptions{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "User \"system:anonymous\" cannot create resource \"oidcclientsecretrequests\"")
}
