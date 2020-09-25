// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	idpv1alpha1 "go.pinniped.dev/generated/1.19/apis/idp/v1alpha1"
	"go.pinniped.dev/test/library"
)

func TestOIDC(t *testing.T) {
	// Right now, we simply validate that we can create an OIDC provider CR. As we move forward with
	// OIDC support, we will most likely remove this test in favor of one that actually tests real
	// functionality.
	env := library.IntegrationEnv(t)
	client := library.NewPinnipedClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	oidcProvider := &idpv1alpha1.OpenIDConnectIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-oidc-provider-",
			Labels:       map[string]string{"pinniped.dev/test": ""},
			Annotations:  map[string]string{"pinniped.dev/testName": t.Name()},
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "OpenIDConnectIdentityProvider",
			APIVersion: idpv1alpha1.SchemeGroupVersion.String(),
		},
		Spec: idpv1alpha1.OpenIDConnectIdentityProviderSpec{
			Issuer: "https://some-issuer",
			AuthorizationConfig: idpv1alpha1.OpenIDConnectAuthorizationConfig{
				RedirectURI: "https://some-redirect-uri:12345",
				Scopes: []string{
					"tuna",
					"fish",
					"marlin",
				},
			},
			Claims: idpv1alpha1.OpenIDConnectClaims{
				Groups:   "something",
				Username: "something-else",
			},
			Client: idpv1alpha1.OpenIDConnectClient{
				SecretName: "some-secret-name",
			},
		},
	}
	var err error
	oidcProvider, err = client.
		IDPV1alpha1().
		OpenIDConnectIdentityProviders(env.Namespace).
		Create(ctx, oidcProvider, metav1.CreateOptions{})
	require.NoError(t, err)

	err = client.
		IDPV1alpha1().
		OpenIDConnectIdentityProviders(env.Namespace).
		Delete(ctx, oidcProvider.Name, metav1.DeleteOptions{})
	require.NoError(t, err)
}
