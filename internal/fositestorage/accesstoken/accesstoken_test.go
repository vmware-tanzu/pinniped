// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	fositejwt "github.com/ory/fosite/token/jwt"
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
	"go.pinniped.dev/internal/federationdomain/timeouts"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
)

const (
	namespace       = "test-ns"
	expectedVersion = "8" // update this when you update the storage version in the production code
)

var (
	fakeNow                     = time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	lifetime                    = time.Minute * 10
	fakeNowPlusLifetimeAsString = metav1.Time{Time: fakeNow.Add(lifetime)}.Format(time.RFC3339)
	lifetimeFunc                = func(requester fosite.Requester) time.Duration { return lifetime }

	secretsGVR = schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "secrets",
	}
)

func TestAccessTokenStorage(t *testing.T) {
	wantActions := []coretesting.Action{
		coretesting.NewCreateAction(secretsGVR, namespace, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "pinniped-storage-access-token-pwu5zs7lekbhnln2w4",
				ResourceVersion: "",
				Labels: map[string]string{
					"storage.pinniped.dev/type":       "access-token",
					"storage.pinniped.dev/request-id": "abcd-1",
				},
				Annotations: map[string]string{
					"storage.pinniped.dev/garbage-collect-after": fakeNowPlusLifetimeAsString,
				},
			},
			Data: map[string][]byte{
				"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":"","IDTokenLifetimeConfiguration":42000000000},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"fosite":{"id_token_claims":null,"headers":null,"expires_at":null,"username":"snorlax","subject":"panda"},"custom":{"username":"fake-username","upstreamUsername":"fake-upstream-username","upstreamGroups":["fake-upstream-group1","fake-upstream-group2"],"providerUID":"fake-provider-uid","providerName":"fake-provider-name","providerType":"fake-provider-type","warnings":null,"oidc":{"upstreamRefreshToken":"fake-upstream-refresh-token","upstreamAccessToken":"","upstreamSubject":"some-subject","upstreamIssuer":"some-issuer"}}},"requestedAudience":null,"grantedAudience":null},"version":"` + expectedVersion + `"}`),
				"pinniped-storage-version": []byte("1"),
			},
			Type: "storage.pinniped.dev/access-token",
		}),
		coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-access-token-pwu5zs7lekbhnln2w4"),
		coretesting.NewDeleteAction(secretsGVR, namespace, "pinniped-storage-access-token-pwu5zs7lekbhnln2w4"),
	}

	storageLifetimeFuncCallCount := 0
	var storageLifetimeFuncCallRequesterArg fosite.Requester
	ctx, client, _, storage := makeTestSubject(func(requester fosite.Requester) time.Duration {
		storageLifetimeFuncCallCount++
		storageLifetimeFuncCallRequesterArg = requester
		return lifetime
	})

	request := &fosite.Request{
		ID:          "abcd-1",
		RequestedAt: time.Time{},
		Client: &clientregistry.Client{
			IDTokenLifetimeConfiguration: 42 * time.Second,
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
			}},
		RequestedScope:    nil,
		GrantedScope:      nil,
		Form:              url.Values{"key": []string{"val"}},
		Session:           testutil.NewFakePinnipedSession(),
		RequestedAudience: nil,
		GrantedAudience:   nil,
	}
	err := storage.CreateAccessTokenSession(ctx, "fancy-signature", request)
	require.NoError(t, err)
	require.Equal(t, 1, storageLifetimeFuncCallCount)
	require.Equal(t, request, storageLifetimeFuncCallRequesterArg)

	newRequest, err := storage.GetAccessTokenSession(ctx, "fancy-signature", nil)
	require.NoError(t, err)
	require.Equal(t, request, newRequest)

	err = storage.DeleteAccessTokenSession(ctx, "fancy-signature")
	require.NoError(t, err)

	testutil.LogActualJSONFromCreateAction(t, client, 0) // makes it easier to update expected values when needed
	require.Equal(t, wantActions, client.Actions())

	// Check that there were no more calls to the lifetime func since the original create.
	require.Equal(t, 1, storageLifetimeFuncCallCount)
}

func TestAccessTokenStorageRevocation(t *testing.T) {
	wantActions := []coretesting.Action{
		coretesting.NewCreateAction(secretsGVR, namespace, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "pinniped-storage-access-token-pwu5zs7lekbhnln2w4",
				ResourceVersion: "",
				Labels: map[string]string{
					"storage.pinniped.dev/type":       "access-token",
					"storage.pinniped.dev/request-id": "abcd-1",
				},
				Annotations: map[string]string{
					"storage.pinniped.dev/garbage-collect-after": fakeNowPlusLifetimeAsString,
				},
			},
			Data: map[string][]byte{
				"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":"","IDTokenLifetimeConfiguration":0},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"fosite":{"id_token_claims":null,"headers":null,"expires_at":null,"username":"snorlax","subject":"panda"},"custom":{"username":"fake-username","upstreamUsername":"fake-upstream-username","upstreamGroups":["fake-upstream-group1","fake-upstream-group2"],"providerUID":"fake-provider-uid","providerName":"fake-provider-name","providerType":"fake-provider-type","warnings":null,"oidc":{"upstreamRefreshToken":"fake-upstream-refresh-token","upstreamAccessToken":"","upstreamSubject":"some-subject","upstreamIssuer":"some-issuer"}}},"requestedAudience":null,"grantedAudience":null},"version":"` + expectedVersion + `"}`),
				"pinniped-storage-version": []byte("1"),
			},
			Type: "storage.pinniped.dev/access-token",
		}),
		coretesting.NewListAction(secretsGVR, schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}, namespace, metav1.ListOptions{
			LabelSelector: "storage.pinniped.dev/type=access-token,storage.pinniped.dev/request-id=abcd-1",
		}),
		coretesting.NewDeleteAction(secretsGVR, namespace, "pinniped-storage-access-token-pwu5zs7lekbhnln2w4"),
	}

	ctx, client, _, storage := makeTestSubject(lifetimeFunc)

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
	err := storage.CreateAccessTokenSession(ctx, "fancy-signature", request)
	require.NoError(t, err)

	// Revoke the request ID of the session that we just created
	err = storage.RevokeAccessToken(ctx, "abcd-1")
	require.NoError(t, err)

	testutil.LogActualJSONFromCreateAction(t, client, 0) // makes it easier to update expected values when needed
	require.Equal(t, wantActions, client.Actions())
}

func TestGetNotFound(t *testing.T) {
	ctx, _, _, storage := makeTestSubject(lifetimeFunc)

	_, notFoundErr := storage.GetAccessTokenSession(ctx, "non-existent-signature", nil)
	require.EqualError(t, notFoundErr, "not_found")
	require.True(t, errors.Is(notFoundErr, fosite.ErrNotFound))
}

func TestWrongVersion(t *testing.T) {
	ctx, _, secrets, storage := makeTestSubject(lifetimeFunc)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pinniped-storage-access-token-pwu5zs7lekbhnln2w4",
			ResourceVersion: "",
			Labels: map[string]string{
				"storage.pinniped.dev/type": "access-token",
			},
			Annotations: map[string]string{
				"storage.pinniped.dev/garbage-collect-after": fakeNowPlusLifetimeAsString,
			},
		},
		Data: map[string][]byte{
			"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1"},"version":"not-the-right-version"}`),
			"pinniped-storage-version": []byte("1"),
		},
		Type: "storage.pinniped.dev/access-token",
	}
	_, err := secrets.Create(ctx, secret, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = storage.GetAccessTokenSession(ctx, "fancy-signature", nil)

	require.EqualError(t, err, "access token request data has wrong version: access token session for fancy-signature has version not-the-right-version instead of "+expectedVersion)
}

func TestNilSessionRequest(t *testing.T) {
	ctx, _, secrets, storage := makeTestSubject(lifetimeFunc)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pinniped-storage-access-token-pwu5zs7lekbhnln2w4",
			ResourceVersion: "",
			Labels: map[string]string{
				"storage.pinniped.dev/type": "access-token",
			},
			Annotations: map[string]string{
				"storage.pinniped.dev/garbage-collect-after": fakeNowPlusLifetimeAsString,
			},
		},
		Data: map[string][]byte{
			"pinniped-storage-data":    []byte(`{"nonsense-key": "nonsense-value","version":"` + expectedVersion + `"}`),
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
	ctx, _, _, storage := makeTestSubject(lifetimeFunc)

	err := storage.CreateAccessTokenSession(ctx, "signature-doesnt-matter", nil)
	require.EqualError(t, err, "requester must be of type fosite.Request")
}

func TestCreateWithWrongRequesterDataTypes(t *testing.T) {
	ctx, _, _, storage := makeTestSubject(lifetimeFunc)

	request := &fosite.Request{
		Session: nil,
		Client:  &clientregistry.Client{},
	}
	err := storage.CreateAccessTokenSession(ctx, "signature-doesnt-matter", request)
	require.EqualError(t, err, "requester's session must be of type PinnipedSession")

	request = &fosite.Request{
		Session: &psession.PinnipedSession{},
		Client:  nil,
	}
	err = storage.CreateAccessTokenSession(ctx, "signature-doesnt-matter", request)
	require.EqualError(t, err, "requester's client must be of type clientregistry.Client")
}

func TestCreateWithoutRequesterID(t *testing.T) {
	ctx, client, _, storage := makeTestSubject(lifetimeFunc)

	request := &fosite.Request{
		ID:      "", // empty ID
		Session: &psession.PinnipedSession{},
		Client:  &clientregistry.Client{},
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

func makeTestSubject(lifetimeFunc timeouts.StorageLifetime) (context.Context, *fake.Clientset, corev1client.SecretInterface, RevocationStorage) {
	client := fake.NewSimpleClientset()
	secrets := client.CoreV1().Secrets(namespace)
	return context.Background(),
		client,
		secrets,
		New(secrets, clocktesting.NewFakeClock(fakeNow).Now, lifetimeFunc)
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
					Name:            "pinniped-storage-access-token-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "access-token",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1","session":{"fosite":{"id_token_claims":{"jti": "xyz"},"headers":{"extra":{"myheader": "foo"}},"expires_at":null,"username":"snorlax","subject":"panda"},"custom":{"username":"fake-username","upstreamUsername":"fake-upstream-username","upstreamGroups":["fake-upstream-group1","fake-upstream-group2"],"providerUID":"fake-provider-uid","providerName":"fake-provider-name","providerType":"fake-provider-type","oidc":{"upstreamRefreshToken":"fake-upstream-refresh-token"}}}},"version":"` + expectedVersion + `","active": true}`),
					"pinniped-storage-version": []byte("1"),
				},
				Type: "storage.pinniped.dev/access-token",
			},
			wantSession: &Session{
				Version: expectedVersion,
				Request: &fosite.Request{
					ID:     "abcd-1",
					Client: &clientregistry.Client{},
					Session: &psession.PinnipedSession{
						Fosite: &openid.DefaultSession{
							Username: "snorlax",
							Subject:  "panda",
							Claims:   &fositejwt.IDTokenClaims{JTI: "xyz"},
							Headers:  &fositejwt.Headers{Extra: map[string]any{"myheader": "foo"}},
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
					Name:            "pinniped-storage-access-token-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "access-token",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1"},"version":"` + expectedVersion + `","active": true}`),
					"pinniped-storage-version": []byte("1"),
				},
				Type: "storage.pinniped.dev/not-access-token",
			},
			wantErr: "secret storage data has incorrect type: storage.pinniped.dev/not-access-token must equal storage.pinniped.dev/access-token",
		},
		{
			name: "wrong session version",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "pinniped-storage-access-token-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "access-token",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1"},"version":"wrong-version-here","active": true}`),
					"pinniped-storage-version": []byte("1"),
				},
				Type: "storage.pinniped.dev/access-token",
			},
			wantErr: "access token request data has wrong version: access token session has version wrong-version-here instead of " + expectedVersion,
		},
		{
			name: "missing request",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "pinniped-storage-access-token-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "access-token",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"version":"` + expectedVersion + `","active": true}`),
					"pinniped-storage-version": []byte("1"),
				},
				Type: "storage.pinniped.dev/access-token",
			},
			wantErr: "malformed access token session: access token request data must be present",
		},
	}
	for _, tt := range tests {
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
