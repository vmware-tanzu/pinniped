// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package authorizationcode

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"testing"
	"time"

	fuzz "github.com/google/gofuzz"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	kubetesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"

	"go.pinniped.dev/internal/fositestorage"
	"go.pinniped.dev/internal/oidc/clientregistry"
	"go.pinniped.dev/internal/psession"
	"go.pinniped.dev/internal/testutil"
)

const namespace = "test-ns"

var fakeNow = time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
var lifetime = time.Minute * 10
var fakeNowPlusLifetimeAsString = metav1.Time{Time: fakeNow.Add(lifetime)}.Format(time.RFC3339)

func TestAuthorizationCodeStorage(t *testing.T) {
	secretsGVR := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "secrets",
	}

	wantActions := []kubetesting.Action{
		kubetesting.NewCreateAction(secretsGVR, namespace, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "pinniped-storage-authcode-pwu5zs7lekbhnln2w4",
				ResourceVersion: "",
				Labels: map[string]string{
					"storage.pinniped.dev/type": "authcode",
				},
				Annotations: map[string]string{
					"storage.pinniped.dev/garbage-collect-after": fakeNowPlusLifetimeAsString,
				},
			},
			Data: map[string][]byte{
				"pinniped-storage-data":    []byte(`{"active":true,"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":""},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"fosite":{"Claims":null,"Headers":null,"ExpiresAt":null,"Username":"snorlax","Subject":"panda"},"custom":{"providerUID":"fake-provider-uid","providerName":"fake-provider-name","providerType":"fake-provider-type","oidc":{"upstreamRefreshToken":"fake-upstream-refresh-token"}}},"requestedAudience":null,"grantedAudience":null},"version":"2"}`),
				"pinniped-storage-version": []byte("1"),
			},
			Type: "storage.pinniped.dev/authcode",
		}),
		kubetesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-authcode-pwu5zs7lekbhnln2w4"),
		kubetesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-authcode-pwu5zs7lekbhnln2w4"),
		kubetesting.NewUpdateAction(secretsGVR, namespace, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "pinniped-storage-authcode-pwu5zs7lekbhnln2w4",
				ResourceVersion: "",
				Labels: map[string]string{
					"storage.pinniped.dev/type": "authcode",
				},
				Annotations: map[string]string{
					"storage.pinniped.dev/garbage-collect-after": fakeNowPlusLifetimeAsString,
				},
			},
			Data: map[string][]byte{
				"pinniped-storage-data":    []byte(`{"active":false,"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":""},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"fosite":{"Claims":null,"Headers":null,"ExpiresAt":null,"Username":"snorlax","Subject":"panda"},"custom":{"providerUID":"fake-provider-uid","providerName":"fake-provider-name","providerType":"fake-provider-type","oidc":{"upstreamRefreshToken":"fake-upstream-refresh-token"}}},"requestedAudience":null,"grantedAudience":null},"version":"2"}`),
				"pinniped-storage-version": []byte("1"),
			},
			Type: "storage.pinniped.dev/authcode",
		}),
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
	err := storage.CreateAuthorizeCodeSession(ctx, "fancy-signature", request)
	require.NoError(t, err)

	newRequest, err := storage.GetAuthorizeCodeSession(ctx, "fancy-signature", nil)
	require.NoError(t, err)
	require.Equal(t, request, newRequest)

	err = storage.InvalidateAuthorizeCodeSession(ctx, "fancy-signature")
	require.NoError(t, err)

	testutil.LogActualJSONFromCreateAction(t, client, 0) // makes it easier to update expected values when needed
	testutil.LogActualJSONFromUpdateAction(t, client, 3) // makes it easier to update expected values when needed
	require.Equal(t, wantActions, client.Actions())

	// Doing a Get on an invalidated session should still return the session, but also return an error.
	invalidatedRequest, err := storage.GetAuthorizeCodeSession(ctx, "fancy-signature", nil)
	require.EqualError(t, err, "authorization code session for fancy-signature has already been used: Authorization code has ben invalidated")
	require.Equal(t, "abcd-1", invalidatedRequest.GetID())
}

func TestGetNotFound(t *testing.T) {
	ctx, _, _, storage := makeTestSubject()

	_, notFoundErr := storage.GetAuthorizeCodeSession(ctx, "non-existent-signature", nil)
	require.EqualError(t, notFoundErr, "not_found")
	require.True(t, errors.Is(notFoundErr, fosite.ErrNotFound))
}

func TestInvalidateWhenNotFound(t *testing.T) {
	ctx, _, _, storage := makeTestSubject()

	notFoundErr := storage.InvalidateAuthorizeCodeSession(ctx, "non-existent-signature")
	require.EqualError(t, notFoundErr, "not_found")
	require.True(t, errors.Is(notFoundErr, fosite.ErrNotFound))
}

func TestInvalidateWhenConflictOnUpdateHappens(t *testing.T) {
	ctx, client, _, storage := makeTestSubject()

	client.PrependReactor("update", "secrets", func(_ kubetesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(schema.GroupResource{
			Group:    "",
			Resource: "secrets",
		}, "some-secret-name", fmt.Errorf("there was a conflict"))
	})

	request := &fosite.Request{
		ID:      "some-request-id",
		Client:  &clientregistry.Client{},
		Session: testutil.NewFakePinnipedSession(),
	}
	err := storage.CreateAuthorizeCodeSession(ctx, "fancy-signature", request)
	require.NoError(t, err)
	err = storage.InvalidateAuthorizeCodeSession(ctx, "fancy-signature")
	require.EqualError(t, err, `The request could not be completed due to concurrent access: failed to update authcode for signature fancy-signature at resource version : Operation cannot be fulfilled on secrets "some-secret-name": there was a conflict`)
}

func TestWrongVersion(t *testing.T) {
	ctx, _, secrets, storage := makeTestSubject()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pinniped-storage-authcode-pwu5zs7lekbhnln2w4",
			ResourceVersion: "",
			Labels: map[string]string{
				"storage.pinniped.dev/type": "authcode",
			},
		},
		Data: map[string][]byte{
			"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1"},"version":"not-the-right-version","active": true}`),
			"pinniped-storage-version": []byte("1"),
		},
		Type: "storage.pinniped.dev/authcode",
	}
	_, err := secrets.Create(ctx, secret, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = storage.GetAuthorizeCodeSession(ctx, "fancy-signature", nil)

	require.EqualError(t, err, "authorization request data has wrong version: authorization code session for fancy-signature has version not-the-right-version instead of 2")
}

func TestNilSessionRequest(t *testing.T) {
	ctx, _, secrets, storage := makeTestSubject()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "pinniped-storage-authcode-pwu5zs7lekbhnln2w4",
			ResourceVersion: "",
			Labels: map[string]string{
				"storage.pinniped.dev/type": "authcode",
			},
		},
		Data: map[string][]byte{
			"pinniped-storage-data":    []byte(`{"nonsense-key": "nonsense-value", "version":"2", "active": true}`),
			"pinniped-storage-version": []byte("1"),
		},
		Type: "storage.pinniped.dev/authcode",
	}

	_, err := secrets.Create(ctx, secret, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = storage.GetAuthorizeCodeSession(ctx, "fancy-signature", nil)
	require.EqualError(t, err, "malformed authorization code session for fancy-signature: authorization request data must be present")
}

func TestCreateWithNilRequester(t *testing.T) {
	ctx, _, _, storage := makeTestSubject()

	err := storage.CreateAuthorizeCodeSession(ctx, "signature-doesnt-matter", nil)
	require.EqualError(t, err, "requester must be of type fosite.Request")
}

func TestCreateWithWrongRequesterDataTypes(t *testing.T) {
	ctx, _, _, storage := makeTestSubject()

	request := &fosite.Request{
		Session: nil,
		Client:  &clientregistry.Client{},
	}
	err := storage.CreateAuthorizeCodeSession(ctx, "signature-doesnt-matter", request)
	require.EqualError(t, err, "requester's session must be of type PinnipedSession")

	request = &fosite.Request{
		Session: &psession.PinnipedSession{},
		Client:  nil,
	}
	err = storage.CreateAuthorizeCodeSession(ctx, "signature-doesnt-matter", request)
	require.EqualError(t, err, "requester's client must be of type clientregistry.Client")
}

func makeTestSubject() (context.Context, *fake.Clientset, corev1client.SecretInterface, oauth2.AuthorizeCodeStorage) {
	client := fake.NewSimpleClientset()
	secrets := client.CoreV1().Secrets(namespace)
	return context.Background(), client, secrets, New(secrets, clocktesting.NewFakeClock(fakeNow).Now, lifetime)
}

// TestFuzzAndJSONNewValidEmptyAuthorizeCodeSession asserts that we can correctly round trip our authorize code session.
// It will detect any changes to fosite.AuthorizeRequest and guarantees that all interface types have concrete implementations.
func TestFuzzAndJSONNewValidEmptyAuthorizeCodeSession(t *testing.T) {
	validSession := NewValidEmptyAuthorizeCodeSession()

	// sanity check our valid session
	extractedRequest, err := fositestorage.ValidateAndExtractAuthorizeRequest(validSession.Request)
	require.NoError(t, err)
	require.Equal(t, validSession.Request, extractedRequest)

	// checked above
	defaultClient := validSession.Request.Client.(*clientregistry.Client)
	pinnipedSession := validSession.Request.Session.(*psession.PinnipedSession)

	// makes it easier to use a raw string
	replacer := strings.NewReplacer("`", "a")
	randString := func(c fuzz.Continue) string {
		for {
			s := c.RandString()
			if len(s) == 0 {
				continue // skip empty string
			}
			return replacer.Replace(s)
		}
	}

	// deterministic fuzzing of fosite.Request
	f := fuzz.New().RandSource(rand.NewSource(1)).NilChance(0).NumElements(1, 3).Funcs(
		// these functions guarantee that these are the only interface types we need to fill out
		// if fosite.Request changes to add more, the fuzzer will panic
		func(fc *fosite.Client, c fuzz.Continue) {
			c.Fuzz(defaultClient)
			*fc = defaultClient
		},
		func(fs *fosite.Session, c fuzz.Continue) {
			c.Fuzz(pinnipedSession)
			*fs = pinnipedSession
		},

		// these types contain an interface{} that we need to handle
		// this is safe because we explicitly provide the PinnipedSession concrete type
		func(value *map[string]interface{}, c fuzz.Continue) {
			// cover all the JSON data types just in case
			*value = map[string]interface{}{
				randString(c): float64(c.Intn(1 << 32)),
				randString(c): map[string]interface{}{
					randString(c): []interface{}{float64(c.Intn(1 << 32))},
					randString(c): map[string]interface{}{
						randString(c): nil,
						randString(c): map[string]interface{}{
							randString(c): c.RandBool(),
						},
					},
				},
			}
		},
		// JWK contains an interface{} Key that we need to handle
		// this is safe because JWK explicitly implements JSON marshalling and unmarshalling
		func(jwk *jose.JSONWebKey, c fuzz.Continue) {
			key, _, err := ed25519.GenerateKey(c)
			require.NoError(t, err)
			jwk.Key = key

			// set these fields to make the .Equal comparison work
			jwk.Certificates = []*x509.Certificate{}
			jwk.CertificatesURL = &url.URL{}
			jwk.CertificateThumbprintSHA1 = []byte{}
			jwk.CertificateThumbprintSHA256 = []byte{}
		},

		// set this to make the .Equal comparison work
		// this is safe because Time explicitly implements JSON marshalling and unmarshalling
		func(tp *time.Time, c fuzz.Continue) {
			*tp = time.Unix(c.Int63n(1<<32), c.Int63n(1<<32)).UTC()
		},

		// make random strings that do not contain any ` characters
		func(s *string, c fuzz.Continue) {
			*s = randString(c)
		},
		// handle string type alias
		func(s *fosite.TokenType, c fuzz.Continue) {
			*s = fosite.TokenType(randString(c))
		},
		func(s *types.UID, c fuzz.Continue) {
			*s = types.UID(randString(c))
		},
		// handle string type alias
		func(s *fosite.Arguments, c fuzz.Continue) {
			n := c.Intn(3) + 1 // 1 to 3 items
			arguments := make(fosite.Arguments, n)
			for i := range arguments {
				arguments[i] = randString(c)
			}
			*s = arguments
		},
	)

	f.Fuzz(validSession)

	const name = "fuzz" // value is irrelevant
	ctx := context.Background()
	secrets := fake.NewSimpleClientset().CoreV1().Secrets(name)
	storage := New(secrets, func() time.Time { return fakeNow }, lifetime)

	// issue a create using the fuzzed request to confirm that marshalling works
	err = storage.CreateAuthorizeCodeSession(ctx, name, validSession.Request)
	require.NoError(t, err)

	// retrieve a copy of the fuzzed request from storage to confirm that unmarshalling works
	newRequest, err := storage.GetAuthorizeCodeSession(ctx, name, nil)
	require.NoError(t, err)

	// the fuzzed request and the copy from storage should be exactly the same
	require.Equal(t, validSession.Request, newRequest)

	secretList, err := secrets.List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, secretList.Items, 1)
	authorizeCodeSessionJSONFromStorage := string(secretList.Items[0].Data["pinniped-storage-data"])

	// set these to match CreateAuthorizeCodeSession so that .JSONEq works
	validSession.Active = true
	validSession.Version = "2"

	validSessionJSONBytes, err := json.MarshalIndent(validSession, "", "\t")
	require.NoError(t, err)
	authorizeCodeSessionJSONFromFuzzing := string(validSessionJSONBytes)

	// the fuzzed session and storage session should have identical JSON
	require.JSONEq(t, authorizeCodeSessionJSONFromFuzzing, authorizeCodeSessionJSONFromStorage)

	// while the fuzzer will panic if AuthorizeRequest changes in a way that cannot be fuzzed,
	// if it adds a new field that can be fuzzed, this check will fail
	// thus if AuthorizeRequest changes, we will detect it here (though we could possibly miss an omitempty field)
	require.JSONEq(t, ExpectedAuthorizeCodeSessionJSONFromFuzzing, authorizeCodeSessionJSONFromFuzzing, "actual:\n%s", authorizeCodeSessionJSONFromFuzzing)
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
					Name:            "pinniped-storage-authcode-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "authcode",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1","session":{"fosite":{"Claims":null,"Headers":null,"ExpiresAt":null,"Username":"snorlax","Subject":"panda"},"custom":{"providerUID":"fake-provider-uid","providerName":"fake-provider-name","providerType":"fake-provider-type","oidc":{"upstreamRefreshToken":"fake-upstream-refresh-token"}}}},"version":"2","active": true}`),
					"pinniped-storage-version": []byte("1"),
				},
				Type: "storage.pinniped.dev/authcode",
			},
			wantSession: &Session{
				Version: "2",
				Active:  true,
				Request: &fosite.Request{
					ID:     "abcd-1",
					Client: &clientregistry.Client{},
					Session: &psession.PinnipedSession{
						Fosite: &openid.DefaultSession{
							Username: "snorlax",
							Subject:  "panda",
						},
						Custom: &psession.CustomSessionData{
							ProviderUID:  "fake-provider-uid",
							ProviderName: "fake-provider-name",
							ProviderType: "fake-provider-type",
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
					Name:            "pinniped-storage-authcode-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "authcode",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1"},"version":"2","active": true}`),
					"pinniped-storage-version": []byte("1"),
				},
				Type: "storage.pinniped.dev/not-authcode",
			},
			wantErr: "secret storage data has incorrect type: storage.pinniped.dev/not-authcode must equal storage.pinniped.dev/authcode",
		},
		{
			name: "wrong session version",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "pinniped-storage-authcode-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "authcode",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"request":{"id":"abcd-1"},"version":"wrong-version-here","active": true}`),
					"pinniped-storage-version": []byte("1"),
				},
				Type: "storage.pinniped.dev/authcode",
			},
			wantErr: "authorization request data has wrong version: authorization code session has version wrong-version-here instead of 2",
		},
		{
			name: "missing request",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "pinniped-storage-authcode-pwu5zs7lekbhnln2w4",
					ResourceVersion: "",
					Labels: map[string]string{
						"storage.pinniped.dev/type": "authcode",
					},
				},
				Data: map[string][]byte{
					"pinniped-storage-data":    []byte(`{"version":"2","active": true}`),
					"pinniped-storage-version": []byte("1"),
				},
				Type: "storage.pinniped.dev/authcode",
			},
			wantErr: "malformed authorization code session: authorization request data must be present",
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
