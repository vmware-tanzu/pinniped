// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package openidconnect

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	coretesting "k8s.io/client-go/testing"
)

const namespace = "test-ns"

var fakeNow = time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
var lifetime = time.Minute * 10
var fakeNowPlusLifetimeAsString = metav1.Time{Time: fakeNow.Add(lifetime)}.Format(time.RFC3339)

func TestOpenIdConnectStorage(t *testing.T) {
	secretsGVR := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "secrets",
	}

	wantActions := []coretesting.Action{
		coretesting.NewCreateAction(secretsGVR, namespace, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "pinniped-storage-oidc-pwu5zs7lekbhnln2w4",
				ResourceVersion: "",
				Labels: map[string]string{
					"storage.pinniped.dev/type": "oidc",
				},
				Annotations: map[string]string{
					"storage.pinniped.dev/garbage-collect-after": fakeNowPlusLifetimeAsString,
				},
			},
			Data: map[string][]byte{
				"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":""},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"Claims":null,"Headers":null,"ExpiresAt":null,"Username":"snorlax","Subject":"panda"},"requestedAudience":null,"grantedAudience":null},"version":"1"}`),
				"pinniped-storage-version": []byte("1"),
			},
			Type: "storage.pinniped.dev/oidc",
		}),
		coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-oidc-pwu5zs7lekbhnln2w4"),
		coretesting.NewDeleteAction(secretsGVR, namespace, "pinniped-storage-oidc-pwu5zs7lekbhnln2w4"),
	}

	ctx, client, _, storage := makeTestSubject()

	request := &fosite.Request{
		ID:          "abcd-1",
		RequestedAt: time.Time{},
		Client: &fosite.DefaultOpenIDConnectClient{
			DefaultClient: &fosite.DefaultClient{
				ID:            "pinny",
				Secret:        nil,
				RedirectURIs:  nil,
				GrantTypes:    nil,
				ResponseTypes: nil,
				Scopes:        nil,
				Audience:      nil,
				Public:        true,
			},
			JSONWebKeysURI:                    "where",
			JSONWebKeys:                       nil,
			TokenEndpointAuthMethod:           "something",
			RequestURIs:                       nil,
			RequestObjectSigningAlgorithm:     "",
			TokenEndpointAuthSigningAlgorithm: "",
		},
		RequestedScope: nil,
		GrantedScope:   nil,
		Form:           url.Values{"key": []string{"val"}},
		Session: &openid.DefaultSession{
			Claims:    nil,
			Headers:   nil,
			ExpiresAt: nil,
			Username:  "snorlax",
			Subject:   "panda",
		},
		RequestedAudience: nil,
		GrantedAudience:   nil,
	}
	err := storage.CreateOpenIDConnectSession(ctx, "fancy-code.fancy-signature", request)
	require.NoError(t, err)

	newRequest, err := storage.GetOpenIDConnectSession(ctx, "fancy-code.fancy-signature", nil)
	require.NoError(t, err)
	require.Equal(t, request, newRequest)

	err = storage.DeleteOpenIDConnectSession(ctx, "fancy-code.fancy-signature")
	require.NoError(t, err)

	require.Equal(t, wantActions, client.Actions())
}

func TestGetNotFound(t *testing.T) {
	ctx, _, _, storage := makeTestSubject()

	_, notFoundErr := storage.GetOpenIDConnectSession(ctx, "authcode.non-existent-signature", nil)
	require.EqualError(t, notFoundErr, "not_found")
	require.True(t, errors.Is(notFoundErr, fosite.ErrNotFound))
}

func TestWrongVersion(t *testing.T) {
	ctx, _, secrets, storage := makeTestSubject()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pinniped-storage-oidc-pwu5zs7lekbhnln2w4",
			ResourceVersion: "",
			Labels: map[string]string{
				"storage.pinniped.dev/type": "oidc",
			},
		},
		Data: map[string][]byte{
			"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":""},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"Claims":null,"Headers":null,"ExpiresAt":null,"Username":"snorlax","Subject":"panda"},"requestedAudience":null,"grantedAudience":null},"version":"not-the-right-version"}`),
			"pinniped-storage-version": []byte("1"),
		},
		Type: "storage.pinniped.dev/oidc",
	}
	_, err := secrets.Create(ctx, secret, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = storage.GetOpenIDConnectSession(ctx, "fancy-code.fancy-signature", nil)

	require.EqualError(t, err, "oidc request data has wrong version: oidc session for fancy-signature has version not-the-right-version instead of 1")
}

func TestNilSessionRequest(t *testing.T) {
	ctx, _, secrets, storage := makeTestSubject()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pinniped-storage-oidc-pwu5zs7lekbhnln2w4",
			ResourceVersion: "",
			Labels: map[string]string{
				"storage.pinniped.dev/type": "oidc",
			},
		},
		Data: map[string][]byte{
			"pinniped-storage-data":    []byte(`{"nonsense-key": "nonsense-value","version":"1"}`),
			"pinniped-storage-version": []byte("1"),
		},
		Type: "storage.pinniped.dev/oidc",
	}

	_, err := secrets.Create(ctx, secret, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = storage.GetOpenIDConnectSession(ctx, "fancy-code.fancy-signature", nil)
	require.EqualError(t, err, "malformed oidc session for fancy-signature: oidc request data must be present")
}

func TestCreateWithNilRequester(t *testing.T) {
	ctx, _, _, storage := makeTestSubject()

	err := storage.CreateOpenIDConnectSession(ctx, "authcode.signature-doesnt-matter", nil)
	require.EqualError(t, err, "requester must be of type fosite.Request")
}

func TestCreateWithWrongRequesterDataTypes(t *testing.T) {
	ctx, _, _, storage := makeTestSubject()

	request := &fosite.Request{
		Session: nil,
		Client:  &fosite.DefaultOpenIDConnectClient{},
	}
	err := storage.CreateOpenIDConnectSession(ctx, "authcode.signature-doesnt-matter", request)
	require.EqualError(t, err, "requester's session must be of type openid.DefaultSession")

	request = &fosite.Request{
		Session: &openid.DefaultSession{},
		Client:  nil,
	}
	err = storage.CreateOpenIDConnectSession(ctx, "authcode.signature-doesnt-matter", request)
	require.EqualError(t, err, "requester's client must be of type fosite.DefaultOpenIDConnectClient")
}

func TestAuthcodeHasNoDot(t *testing.T) {
	ctx, _, _, storage := makeTestSubject()

	err := storage.CreateOpenIDConnectSession(ctx, "all-one-part", nil)
	require.EqualError(t, err, "malformed authorization code")
}

func makeTestSubject() (context.Context, *fake.Clientset, corev1client.SecretInterface, openid.OpenIDConnectRequestStorage) {
	client := fake.NewSimpleClientset()
	secrets := client.CoreV1().Secrets(namespace)
	return context.Background(), client, secrets, New(secrets, clock.NewFakeClock(fakeNow).Now, lifetime)
}
