// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package accesstoken

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

var secretsGVR = schema.GroupVersionResource{
	Group:    "",
	Version:  "v1",
	Resource: "secrets",
}

func TestAccessTokenStorage(t *testing.T) {
	ctx := context.Background()

	wantActions := []coretesting.Action{
		coretesting.NewCreateAction(secretsGVR, namespace, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "pinniped-storage-access-token-pwu5zs7lekbhnln2w4",
				ResourceVersion: "",
				Labels: map[string]string{
					"storage.pinniped.dev/type":       "access-token",
					"storage.pinniped.dev/request-id": "abcd-1",
				},
			},
			Data: map[string][]byte{
				"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":""},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"Claims":null,"Headers":null,"ExpiresAt":null,"Username":"snorlax","Subject":"panda"},"requestedAudience":null,"grantedAudience":null},"version":"1"}`),
				"pinniped-storage-version": []byte("1"),
			},
			Type: "storage.pinniped.dev/access-token",
		}),
		coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-access-token-pwu5zs7lekbhnln2w4"),
		coretesting.NewDeleteAction(secretsGVR, namespace, "pinniped-storage-access-token-pwu5zs7lekbhnln2w4"),
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
	err := storage.CreateAccessTokenSession(ctx, "fancy-signature", request)
	require.NoError(t, err)

	newRequest, err := storage.GetAccessTokenSession(ctx, "fancy-signature", nil)
	require.NoError(t, err)
	require.Equal(t, request, newRequest)

	err = storage.DeleteAccessTokenSession(ctx, "fancy-signature")
	require.NoError(t, err)

	require.Equal(t, wantActions, client.Actions())
}

func TestAccessTokenStorageRevocation(t *testing.T) {
	ctx := context.Background()

	wantActions := []coretesting.Action{
		coretesting.NewCreateAction(secretsGVR, namespace, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "pinniped-storage-access-token-pwu5zs7lekbhnln2w4",
				ResourceVersion: "",
				Labels: map[string]string{
					"storage.pinniped.dev/type":       "access-token",
					"storage.pinniped.dev/request-id": "abcd-1",
				},
			},
			Data: map[string][]byte{
				"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":""},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"Claims":null,"Headers":null,"ExpiresAt":null,"Username":"snorlax","Subject":"panda"},"requestedAudience":null,"grantedAudience":null},"version":"1"}`),
				"pinniped-storage-version": []byte("1"),
			},
			Type: "storage.pinniped.dev/access-token",
		}),
		coretesting.NewListAction(secretsGVR, schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}, namespace, metav1.ListOptions{
			LabelSelector: "storage.pinniped.dev/type=access-token,storage.pinniped.dev/request-id=abcd-1",
		}),
		coretesting.NewDeleteAction(secretsGVR, namespace, "pinniped-storage-access-token-pwu5zs7lekbhnln2w4"),
	}

	client := fake.NewSimpleClientset()
	secrets := client.CoreV1().Secrets(namespace)
	storage := New(secrets)

	request := &fosite.Request{
		ID:          "abcd-1",
		RequestedAt: time.Time{},
		Client: &fosite.DefaultOpenIDConnectClient{
			DefaultClient: &fosite.DefaultClient{
				ID:     "pinny",
				Public: true,
			},
			JSONWebKeysURI:          "where",
			TokenEndpointAuthMethod: "something",
		},
		Form: url.Values{"key": []string{"val"}},
		Session: &openid.DefaultSession{
			Username: "snorlax",
			Subject:  "panda",
		},
	}
	err := storage.CreateAccessTokenSession(ctx, "fancy-signature", request)
	require.NoError(t, err)

	// Revoke the request ID of the session that we just created
	err = storage.RevokeAccessToken(ctx, "abcd-1")
	require.NoError(t, err)

	require.Equal(t, wantActions, client.Actions())
}

func TestGetNotFound(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	secrets := client.CoreV1().Secrets(namespace)
	storage := New(secrets)

	_, notFoundErr := storage.GetAccessTokenSession(ctx, "non-existent-signature", nil)
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
			Name:            "pinniped-storage-access-token-pwu5zs7lekbhnln2w4",
			ResourceVersion: "",
			Labels: map[string]string{
				"storage.pinniped.dev/type": "access-token",
			},
		},
		Data: map[string][]byte{
			"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":""},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"Claims":null,"Headers":null,"ExpiresAt":null,"Username":"snorlax","Subject":"panda"},"requestedAudience":null,"grantedAudience":null},"version":"not-the-right-version"}`),
			"pinniped-storage-version": []byte("1"),
		},
		Type: "storage.pinniped.dev/access-token",
	}
	_, err := secrets.Create(ctx, secret, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = storage.GetAccessTokenSession(ctx, "fancy-signature", nil)

	require.EqualError(t, err, "access token request data has wrong version: access token session for fancy-signature has version not-the-right-version instead of 1")
}

func TestNilSessionRequest(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	secrets := client.CoreV1().Secrets(namespace)
	storage := New(secrets)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pinniped-storage-access-token-pwu5zs7lekbhnln2w4",
			ResourceVersion: "",
			Labels: map[string]string{
				"storage.pinniped.dev/type": "access-token",
			},
		},
		Data: map[string][]byte{
			"pinniped-storage-data":    []byte(`{"nonsense-key": "nonsense-value","version":"1"}`),
			"pinniped-storage-version": []byte("1"),
		},
		Type: "storage.pinniped.dev/access-token",
	}

	_, err := secrets.Create(ctx, secret, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = storage.GetAccessTokenSession(ctx, "fancy-signature", nil)
	require.EqualError(t, err, "malformed access token session for fancy-signature: access token request data must be present")
}

func TestCreateWithNilRequester(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	secrets := client.CoreV1().Secrets(namespace)
	storage := New(secrets)

	err := storage.CreateAccessTokenSession(ctx, "signature-doesnt-matter", nil)
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
	err := storage.CreateAccessTokenSession(ctx, "signature-doesnt-matter", request)
	require.EqualError(t, err, "requester's session must be of type openid.DefaultSession")

	request = &fosite.Request{
		Session: &openid.DefaultSession{},
		Client:  nil,
	}
	err = storage.CreateAccessTokenSession(ctx, "signature-doesnt-matter", request)
	require.EqualError(t, err, "requester's client must be of type fosite.DefaultOpenIDConnectClient")
}

func TestCreateWithoutRequesterID(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	secrets := client.CoreV1().Secrets(namespace)
	storage := New(secrets)

	request := &fosite.Request{
		ID:      "", // empty ID
		Session: &openid.DefaultSession{},
		Client:  &fosite.DefaultOpenIDConnectClient{},
	}
	err := storage.CreateAccessTokenSession(ctx, "signature-doesnt-matter", request)
	require.NoError(t, err)

	// the blank ID was filled in with an auto-generated ID
	require.NotEmpty(t, request.ID)

	require.Len(t, client.Actions(), 1)
	actualAction := client.Actions()[0].(coretesting.CreateActionImpl)
	actualSecret := actualAction.GetObject().(*corev1.Secret)

	// The generated secret was labeled with that auto-generated request ID
	require.Equal(t, request.ID, actualSecret.Labels["storage.pinniped.dev/request-id"])
}
