// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package pkce

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
	"k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
)

const namespace = "test-ns"

func TestPKCEStorage(t *testing.T) {
	ctx := context.Background()
	secretsGVR := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "secrets",
	}

	wantActions := []coretesting.Action{
		coretesting.NewCreateAction(secretsGVR, namespace, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "pinniped-storage-pkce-pwu5zs7lekbhnln2w4",
				ResourceVersion: "",
				Labels: map[string]string{
					"storage.pinniped.dev/type": "pkce",
				},
			},
			Data: map[string][]byte{
				"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":""},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"Claims":null,"Headers":null,"ExpiresAt":null,"Username":"snorlax","Subject":"panda"},"requestedAudience":null,"grantedAudience":null},"version":"1"}`),
				"pinniped-storage-version": []byte("1"),
			},
			Type: "storage.pinniped.dev/pkce",
		}),
		coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-pkce-pwu5zs7lekbhnln2w4"),
		coretesting.NewDeleteAction(secretsGVR, namespace, "pinniped-storage-pkce-pwu5zs7lekbhnln2w4"),
	}

	client := fake.NewSimpleClientset()
	secrets := client.CoreV1().Secrets(namespace)
	storage := New(secrets)

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
	err := storage.CreatePKCERequestSession(ctx, "fancy-signature", request)
	require.NoError(t, err)

	newRequest, err := storage.GetPKCERequestSession(ctx, "fancy-signature", nil)
	require.NoError(t, err)
	require.Equal(t, request, newRequest)

	err = storage.DeletePKCERequestSession(ctx, "fancy-signature")
	require.NoError(t, err)

	require.Equal(t, wantActions, client.Actions())
}

func TestGetNotFound(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	secrets := client.CoreV1().Secrets(namespace)
	storage := New(secrets)

	_, notFoundErr := storage.GetPKCERequestSession(ctx, "non-existent-signature", nil)
	require.EqualError(t, notFoundErr, "not_found")
	require.True(t, errors.Is(notFoundErr, fosite.ErrNotFound))
}

func TestWrongVersion(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	secrets := client.CoreV1().Secrets(namespace)
	storage := New(secrets)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pinniped-storage-pkce-pwu5zs7lekbhnln2w4",
			ResourceVersion: "",
			Labels: map[string]string{
				"storage.pinniped.dev/type": "pkce",
			},
		},
		Data: map[string][]byte{
			"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":""},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"Claims":null,"Headers":null,"ExpiresAt":null,"Username":"snorlax","Subject":"panda"},"requestedAudience":null,"grantedAudience":null},"version":"not-the-right-version"}`),
			"pinniped-storage-version": []byte("1"),
		},
		Type: "storage.pinniped.dev/pkce",
	}
	_, err := secrets.Create(ctx, secret, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = storage.GetPKCERequestSession(ctx, "fancy-signature", nil)

	require.EqualError(t, err, "pkce request data has wrong version: pkce session for fancy-signature has version not-the-right-version instead of 1")
}

func TestNilSessionRequest(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	secrets := client.CoreV1().Secrets(namespace)
	storage := New(secrets)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pinniped-storage-pkce-pwu5zs7lekbhnln2w4",
			ResourceVersion: "",
			Labels: map[string]string{
				"storage.pinniped.dev/type": "pkce",
			},
		},
		Data: map[string][]byte{
			"pinniped-storage-data":    []byte(`{"nonsense-key": "nonsense-value","version":"1"}`),
			"pinniped-storage-version": []byte("1"),
		},
		Type: "storage.pinniped.dev/pkce",
	}

	_, err := secrets.Create(ctx, secret, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = storage.GetPKCERequestSession(ctx, "fancy-signature", nil)
	require.EqualError(t, err, "malformed pkce session for fancy-signature: pkce request data must be present")
}

func TestCreateWithNilRequester(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	secrets := client.CoreV1().Secrets(namespace)
	storage := New(secrets)

	err := storage.CreatePKCERequestSession(ctx, "signature-doesnt-matter", nil)
	require.EqualError(t, err, "requester must be of type fosite.Request")
}

func TestCreateWithWrongRequesterDataTypes(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	secrets := client.CoreV1().Secrets(namespace)
	storage := New(secrets)

	request := &fosite.Request{
		Session: nil,
		Client:  &fosite.DefaultOpenIDConnectClient{},
	}
	err := storage.CreatePKCERequestSession(ctx, "signature-doesnt-matter", request)
	require.EqualError(t, err, "requester's session must be of type openid.DefaultSession")

	request = &fosite.Request{
		Session: &openid.DefaultSession{},
		Client:  nil,
	}
	err = storage.CreatePKCERequestSession(ctx, "signature-doesnt-matter", request)
	require.EqualError(t, err, "requester's client must be of type fosite.DefaultOpenIDConnectClient")
}
