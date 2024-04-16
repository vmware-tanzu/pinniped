// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package refreshtoken

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	coretesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"

	"go.pinniped.dev/internal/federationdomain/clientregistry"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
)

const namespace = "test-ns"

var secretsGVR = schema.GroupVersionResource{
	Group:    "",
	Version:  "v1",
	Resource: "secrets",
}
var fakeNow = time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
var lifetime = time.Minute * 10
var fakeNowPlusLifetimeAsString = metav1.Time{Time: fakeNow.Add(lifetime)}.Format(time.RFC3339)

func TestRefreshTokenStorage(t *testing.T) {
	wantActions := []coretesting.Action{
		coretesting.NewCreateAction(secretsGVR, namespace, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "pinniped-storage-refresh-token-pwu5zs7lekbhnln2w4",
				ResourceVersion: "",
				Labels: map[string]string{
					"storage.pinniped.dev/type":       "refresh-token",
					"storage.pinniped.dev/request-id": "abcd-1",
				},
				Annotations: map[string]string{
					"storage.pinniped.dev/garbage-collect-after": fakeNowPlusLifetimeAsString,
				},
			},
			Data: map[string][]byte{
				"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":"","IDTokenLifetimeConfiguration":0},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"fosite":{"id_token_claims":null,"headers":null,"expires_at":null,"username":"snorlax","subject":"panda"},"custom":{"username":"fake-username","upstreamUsername":"fake-upstream-username","upstreamGroups":["fake-upstream-group1","fake-upstream-group2"],"providerUID":"fake-provider-uid","providerName":"fake-provider-name","providerType":"fake-provider-type","warnings":null,"oidc":{"upstreamRefreshToken":"fake-upstream-refresh-token","upstreamAccessToken":"","upstreamSubject":"some-subject","upstreamIssuer":"some-issuer"}}},"requestedAudience":null,"grantedAudience":null},"version":"6"}`),
				"pinniped-storage-version": []byte("1"),
			},
			Type: "storage.pinniped.dev/refresh-token",
		}),
		coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-refresh-token-pwu5zs7lekbhnln2w4"),
		coretesting.NewDeleteAction(secretsGVR, namespace, "pinniped-storage-refresh-token-pwu5zs7lekbhnln2w4"),
	}

	ctx, client, _, storage := makeTestSubject()

	request := &fosite.Request{
		ID:          "abcd-1",
		RequestedAt: time.Time{},
		Client: &clientregistry.Client{
			DefaultOpenIDConnectClient: fosite.DefaultOpenIDConnectClient{
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
		},
		RequestedScope:    nil,
		GrantedScope:      nil,
		Form:              url.Values{"key": []string{"val"}},
		Session:           testutil.NewFakePinnipedSession(),
		RequestedAudience: nil,
		GrantedAudience:   nil,
	}
	err := storage.CreateRefreshTokenSession(ctx, "fancy-signature", request)
	require.NoError(t, err)

	newRequest, err := storage.GetRefreshTokenSession(ctx, "fancy-signature", nil)
	require.NoError(t, err)
	require.Equal(t, request, newRequest)

	err = storage.DeleteRefreshTokenSession(ctx, "fancy-signature")
	require.NoError(t, err)

	testutil.LogActualJSONFromCreateAction(t, client, 0) // makes it easier to update expected values when needed
	require.Equal(t, wantActions, client.Actions())
}

func TestRefreshTokenStorageRevocation(t *testing.T) {
	wantActions := []coretesting.Action{
		coretesting.NewCreateAction(secretsGVR, namespace, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "pinniped-storage-refresh-token-pwu5zs7lekbhnln2w4",
				ResourceVersion: "",
				Labels: map[string]string{
					"storage.pinniped.dev/type":       "refresh-token",
					"storage.pinniped.dev/request-id": "abcd-1",
				},
				Annotations: map[string]string{
					"storage.pinniped.dev/garbage-collect-after": fakeNowPlusLifetimeAsString,
				},
			},
			Data: map[string][]byte{
				"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":"","IDTokenLifetimeConfiguration":0},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"fosite":{"id_token_claims":null,"headers":null,"expires_at":null,"username":"snorlax","subject":"panda"},"custom":{"username":"fake-username","upstreamUsername":"fake-upstream-username","upstreamGroups":["fake-upstream-group1","fake-upstream-group2"],"providerUID":"fake-provider-uid","providerName":"fake-provider-name","providerType":"fake-provider-type","warnings":null,"oidc":{"upstreamRefreshToken":"fake-upstream-refresh-token","upstreamAccessToken":"","upstreamSubject":"some-subject","upstreamIssuer":"some-issuer"}}},"requestedAudience":null,"grantedAudience":null},"version":"6"}`),
				"pinniped-storage-version": []byte("1"),
			},
			Type: "storage.pinniped.dev/refresh-token",
		}),
		coretesting.NewListAction(secretsGVR, schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}, namespace, metav1.ListOptions{
			LabelSelector: "storage.pinniped.dev/type=refresh-token,storage.pinniped.dev/request-id=abcd-1",
		}),
		coretesting.NewDeleteAction(secretsGVR, namespace, "pinniped-storage-refresh-token-pwu5zs7lekbhnln2w4"),
	}

	ctx, client, _, storage := makeTestSubject()

	request := &fosite.Request{
		ID:          "abcd-1",
		RequestedAt: time.Time{},
		Client: &clientregistry.Client{
			DefaultOpenIDConnectClient: fosite.DefaultOpenIDConnectClient{
				DefaultClient: &fosite.DefaultClient{
					ID:     "pinny",
					Public: true,
				},
				JSONWebKeysURI:          "where",
				TokenEndpointAuthMethod: "something",
			},
		},
		Form:    url.Values{"key": []string{"val"}},
		Session: testutil.NewFakePinnipedSession(),
	}
	err := storage.CreateRefreshTokenSession(ctx, "fancy-signature", request)
	require.NoError(t, err)

	// Revoke the request ID of the session that we just created
	err = storage.RevokeRefreshToken(ctx, "abcd-1")
	require.NoError(t, err)

	testutil.LogActualJSONFromCreateAction(t, client, 0) // makes it easier to update expected values when needed
	require.Equal(t, wantActions, client.Actions())
}

func TestRefreshTokenStorageRevokeRefreshTokenMaybeGracePeriod(t *testing.T) {
	wantActions := []coretesting.Action{
		coretesting.NewCreateAction(secretsGVR, namespace, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "pinniped-storage-refresh-token-pwu5zs7lekbhnln2w4",
				ResourceVersion: "",
				Labels: map[string]string{
					"storage.pinniped.dev/type":       "refresh-token",
					"storage.pinniped.dev/request-id": "abcd-1",
				},
				Annotations: map[string]string{
					"storage.pinniped.dev/garbage-collect-after": fakeNowPlusLifetimeAsString,
				},
			},
			Data: map[string][]byte{
				"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":"","IDTokenLifetimeConfiguration":0},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"fosite":{"id_token_claims":null,"headers":null,"expires_at":null,"username":"snorlax","subject":"panda"},"custom":{"username":"fake-username","upstreamUsername":"fake-upstream-username","upstreamGroups":["fake-upstream-group1","fake-upstream-group2"],"providerUID":"fake-provider-uid","providerName":"fake-provider-name","providerType":"fake-provider-type","warnings":null,"oidc":{"upstreamRefreshToken":"fake-upstream-refresh-token","upstreamAccessToken":"","upstreamSubject":"some-subject","upstreamIssuer":"some-issuer"}}},"requestedAudience":null,"grantedAudience":null},"version":"6"}`),
				"pinniped-storage-version": []byte("1"),
			},
			Type: "storage.pinniped.dev/refresh-token",
		}),
		coretesting.NewListAction(secretsGVR, schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}, namespace, metav1.ListOptions{
			LabelSelector: "storage.pinniped.dev/type=refresh-token,storage.pinniped.dev/request-id=abcd-1",
		}),
		coretesting.NewDeleteAction(secretsGVR, namespace, "pinniped-storage-refresh-token-pwu5zs7lekbhnln2w4"),
	}

	ctx, client, _, storage := makeTestSubject()

	request := &fosite.Request{
		ID:          "abcd-1",
		RequestedAt: time.Time{},
		Client: &clientregistry.Client{
			DefaultOpenIDConnectClient: fosite.DefaultOpenIDConnectClient{
				DefaultClient: &fosite.DefaultClient{
					ID:     "pinny",
					Public: true,
				},
				JSONWebKeysURI:          "where",
				TokenEndpointAuthMethod: "something",
			},
		},
		Form:    url.Values{"key": []string{"val"}},
		Session: testutil.NewFakePinnipedSession(),
	}
	err := storage.CreateRefreshTokenSession(ctx, "fancy-signature", request)
	require.NoError(t, err)

	// Revoke the request ID of the session that we just created. We don't support grace periods, so this
	// should work exactly like the regular RevokeRefreshToken() function.
	err = storage.RevokeRefreshTokenMaybeGracePeriod(ctx, "abcd-1", "fancy-signature")
	require.NoError(t, err)

	testutil.LogActualJSONFromCreateAction(t, client, 0) // makes it easier to update expected values when needed
	require.Equal(t, wantActions, client.Actions())
}

func TestGetNotFound(t *testing.T) {
	ctx, _, _, storage := makeTestSubject()

	_, notFoundErr := storage.GetRefreshTokenSession(ctx, "non-existent-signature", nil)
	require.EqualError(t, notFoundErr, "not_found")
	require.True(t, errors.Is(notFoundErr, fosite.ErrNotFound))
}

func TestWrongVersion(t *testing.T) {
	ctx, _, secrets, storage := makeTestSubject()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pinniped-storage-refresh-token-pwu5zs7lekbhnln2w4",
			ResourceVersion: "",
			Labels: map[string]string{
				"storage.pinniped.dev/type": "refresh-token",
			},
			Annotations: map[string]string{
				"storage.pinniped.dev/garbage-collect-after": fakeNowPlusLifetimeAsString,
			},
		},
		Data: map[string][]byte{
			"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1"},"version":"not-the-right-version"}`),
			"pinniped-storage-version": []byte("1"),
		},
		Type: "storage.pinniped.dev/refresh-token",
	}
	_, err := secrets.Create(ctx, secret, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = storage.GetRefreshTokenSession(ctx, "fancy-signature", nil)

	require.EqualError(t, err, "refresh token request data has wrong version: refresh token session for fancy-signature has version not-the-right-version instead of 6")
}

func TestNilSessionRequest(t *testing.T) {
	ctx, _, secrets, storage := makeTestSubject()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pinniped-storage-refresh-token-pwu5zs7lekbhnln2w4",
			ResourceVersion: "",
			Labels: map[string]string{
				"storage.pinniped.dev/type": "refresh-token",
			},
			Annotations: map[string]string{
				"storage.pinniped.dev/garbage-collect-after": fakeNowPlusLifetimeAsString,
			},
		},
		Data: map[string][]byte{
			"pinniped-storage-data":    []byte(`{"nonsense-key": "nonsense-value","version":"6"}`),
			"pinniped-storage-version": []byte("1"),
		},
		Type: "storage.pinniped.dev/refresh-token",
	}

	_, err := secrets.Create(ctx, secret, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = storage.GetRefreshTokenSession(ctx, "fancy-signature", nil)
	require.EqualError(t, err, "malformed refresh token session for fancy-signature: refresh token request data must be present")
}

func TestCreateWithNilRequester(t *testing.T) {
	ctx, _, _, storage := makeTestSubject()

	err := storage.CreateRefreshTokenSession(ctx, "signature-doesnt-matter", nil)
	require.EqualError(t, err, "requester must be of type fosite.Request")
}

func TestCreateWithWrongRequesterDataTypes(t *testing.T) {
	ctx, _, _, storage := makeTestSubject()

	request := &fosite.Request{
		Session: nil,
		Client:  &clientregistry.Client{},
	}
	err := storage.CreateRefreshTokenSession(ctx, "signature-doesnt-matter", request)
	require.EqualError(t, err, "requester's session must be of type PinnipedSession")

	request = &fosite.Request{
		Session: &psession.PinnipedSession{},
		Client:  nil,
	}
	err = storage.CreateRefreshTokenSession(ctx, "signature-doesnt-matter", request)
	require.EqualError(t, err, "requester's client must be of type clientregistry.Client")
}

func TestCreateWithoutRequesterID(t *testing.T) {
	ctx, client, _, storage := makeTestSubject()

	request := &fosite.Request{
		ID:      "", // empty ID
		Session: &psession.PinnipedSession{},
		Client:  &clientregistry.Client{},
	}
	err := storage.CreateRefreshTokenSession(ctx, "signature-doesnt-matter", request)
	require.NoError(t, err)

	// the blank ID was filled in with an auto-generated ID
	require.NotEmpty(t, request.ID)

	require.Len(t, client.Actions(), 1)
	actualAction := client.Actions()[0].(coretesting.CreateActionImpl)
	actualSecret := actualAction.GetObject().(*corev1.Secret)

	// The generated secret was labeled with that auto-generated request ID
	require.Equal(t, request.ID, actualSecret.Labels["storage.pinniped.dev/request-id"])
}

func makeTestSubject() (context.Context, *fake.Clientset, corev1client.SecretInterface, RevocationStorage) {
	client := fake.NewSimpleClientset()
	secrets := client.CoreV1().Secrets(namespace)
	return context.Background(), client, secrets, New(secrets, clocktesting.NewFakeClock(fakeNow).Now, func(requester fosite.Requester) time.Duration { return lifetime })
}

func TestReadFromSecret(t *testing.T) {
	tests := []struct {
		name        string
		secret      *corev1.Secret
		wantSession *Session
		wantErr     string
	}{
		{
			name: "happy path",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "pinniped-storage-refresh-token-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "refresh-token",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1","session":{"fosite":{"id_token_claims":{"jti": "xyz"},"headers":{"extra":{"myheader": "foo"}},"expires_at":null,"username":"snorlax","subject":"panda"},"custom":{"username":"fake-username","upstreamUsername":"fake-upstream-username","upstreamGroups":["fake-upstream-group1","fake-upstream-group2"],"providerUID":"fake-provider-uid","providerName":"fake-provider-name","providerType":"fake-provider-type","oidc":{"upstreamRefreshToken":"fake-upstream-refresh-token"}}}},"version":"6","active": true}`),
					"pinniped-storage-version": []byte("1"),
				},
				Type: "storage.pinniped.dev/refresh-token",
			},
			wantSession: &Session{
				Version: "6",
				Request: &fosite.Request{
					ID:     "abcd-1",
					Client: &clientregistry.Client{},
					Session: &psession.PinnipedSession{
						Fosite: &openid.DefaultSession{
							Username: "snorlax",
							Subject:  "panda",
							Claims:   &jwt.IDTokenClaims{JTI: "xyz"},
							Headers:  &jwt.Headers{Extra: map[string]interface{}{"myheader": "foo"}},
						},
						Custom: &psession.CustomSessionData{
							Username:         "fake-username",
							ProviderUID:      "fake-provider-uid",
							ProviderName:     "fake-provider-name",
							ProviderType:     "fake-provider-type",
							UpstreamUsername: "fake-upstream-username",
							UpstreamGroups:   []string{"fake-upstream-group1", "fake-upstream-group2"},
							OIDC: &psession.OIDCSessionData{
								UpstreamRefreshToken: "fake-upstream-refresh-token",
							},
						},
					},
				},
			},
		},
		{
			name: "wrong secret type",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "pinniped-storage-refresh-token-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "refresh-token",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1"},"version":"6","active": true}`),
					"pinniped-storage-version": []byte("1"),
				},
				Type: "storage.pinniped.dev/not-refresh-token",
			},
			wantErr: "secret storage data has incorrect type: storage.pinniped.dev/not-refresh-token must equal storage.pinniped.dev/refresh-token",
		},
		{
			name: "wrong session version",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "pinniped-storage-refresh-token-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "refresh-token",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1"},"version":"wrong-version-here","active": true}`),
					"pinniped-storage-version": []byte("1"),
				},
				Type: "storage.pinniped.dev/refresh-token",
			},
			wantErr: "refresh token request data has wrong version: refresh token session has version wrong-version-here instead of 6",
		},
		{
			name: "missing request",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "pinniped-storage-refresh-token-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "refresh-token",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"version":"6","active": true}`),
					"pinniped-storage-version": []byte("1"),
				},
				Type: "storage.pinniped.dev/refresh-token",
			},
			wantErr: "malformed refresh token session: refresh token request data must be present",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			session, err := ReadFromSecret(tt.secret)
			if tt.wantErr == "" {
				require.NoError(t, err)
				require.Equal(t, tt.wantSession, session)
			} else {
				require.EqualError(t, err, tt.wantErr)
				require.Nil(t, session)
			}
		})
	}
}
