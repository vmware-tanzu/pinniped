// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package authorizationcode

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"math/rand"
	"net/url"
	"strings"
	"testing"
	"time"

	fuzz "github.com/google/gofuzz"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"

	"go.pinniped.dev/internal/fositestorage"
)

func TestAuthorizeCodeStorage(t *testing.T) {
	ctx := context.Background()
	secretsGVR := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "secrets",
	}

	const namespace = "test-ns"

	type mocker interface {
		AddReactor(verb, resource string, reaction coretesting.ReactionFunc)
		PrependReactor(verb, resource string, reaction coretesting.ReactionFunc)
		Tracker() coretesting.ObjectTracker
	}

	tests := []struct {
		name        string
		mocks       func(*testing.T, mocker)
		run         func(*testing.T, oauth2.AuthorizeCodeStorage) error
		wantActions []coretesting.Action
		wantSecrets []corev1.Secret
		wantErr     string
	}{
		{
			name:  "create, get, invalidate standard flow",
			mocks: nil,
			run: func(t *testing.T, storage oauth2.AuthorizeCodeStorage) error {
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
				err := storage.CreateAuthorizeCodeSession(ctx, "fancy-signature", request)
				require.NoError(t, err)

				newRequest, err := storage.GetAuthorizeCodeSession(ctx, "fancy-signature", nil)
				require.NoError(t, err)
				require.Equal(t, request, newRequest)

				return storage.InvalidateAuthorizeCodeSession(ctx, "fancy-signature")
			},
			wantActions: []coretesting.Action{
				coretesting.NewCreateAction(secretsGVR, namespace, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-authcode-pwu5zs7lekbhnln2w4",
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev": "authcode",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"active":true,"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":""},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"Claims":null,"Headers":null,"ExpiresAt":null,"Username":"snorlax","Subject":"panda"},"requestedAudience":null,"grantedAudience":null},"version":"1"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/authcode",
				}),
				coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-authcode-pwu5zs7lekbhnln2w4"),
				coretesting.NewGetAction(secretsGVR, namespace, "pinniped-storage-authcode-pwu5zs7lekbhnln2w4"),
				coretesting.NewUpdateAction(secretsGVR, namespace, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-authcode-pwu5zs7lekbhnln2w4",
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev": "authcode",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"active":false,"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":""},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"Claims":null,"Headers":null,"ExpiresAt":null,"Username":"snorlax","Subject":"panda"},"requestedAudience":null,"grantedAudience":null},"version":"1"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/authcode",
				}),
			},
			wantSecrets: []corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "pinniped-storage-authcode-pwu5zs7lekbhnln2w4",
						Namespace:       namespace,
						ResourceVersion: "",
						Labels: map[string]string{
							"storage.pinniped.dev": "authcode",
						},
					},
					Data: map[string][]byte{
						"pinniped-storage-data":    []byte(`{"active":false,"request":{"id":"abcd-1","requestedAt":"0001-01-01T00:00:00Z","client":{"id":"pinny","redirect_uris":null,"grant_types":null,"response_types":null,"scopes":null,"audience":null,"public":true,"jwks_uri":"where","jwks":null,"token_endpoint_auth_method":"something","request_uris":null,"request_object_signing_alg":"","token_endpoint_auth_signing_alg":""},"scopes":null,"grantedScopes":null,"form":{"key":["val"]},"session":{"Claims":null,"Headers":null,"ExpiresAt":null,"Username":"snorlax","Subject":"panda"},"requestedAudience":null,"grantedAudience":null},"version":"1"}`),
						"pinniped-storage-version": []byte("1"),
					},
					Type: "storage.pinniped.dev/authcode",
				},
			},
			wantErr: "",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := fake.NewSimpleClientset()
			if tt.mocks != nil {
				tt.mocks(t, client)
			}
			secrets := client.CoreV1().Secrets(namespace)
			storage := New(secrets)

			err := tt.run(t, storage)

			require.Equal(t, tt.wantErr, errString(err))
			require.Equal(t, tt.wantActions, client.Actions())

			actualSecrets, err := secrets.List(ctx, metav1.ListOptions{})
			require.NoError(t, err)
			require.Equal(t, tt.wantSecrets, actualSecrets.Items)
		})
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
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
	defaultClient := validSession.Request.Client.(*fosite.DefaultOpenIDConnectClient)
	defaultSession := validSession.Request.Session.(*openid.DefaultSession)

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
			c.Fuzz(defaultSession)
			*fs = defaultSession
		},

		// these types contain an interface{} that we need to handle
		// this is safe because we explicitly provide the openid.DefaultSession concrete type
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
	storage := New(secrets)

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
	validSession.Version = "1"

	validSessionJSONBytes, err := json.MarshalIndent(validSession, "", "\t")
	require.NoError(t, err)
	authorizeCodeSessionJSONFromFuzzing := string(validSessionJSONBytes)

	// the fuzzed session and storage session should have identical JSON
	require.JSONEq(t, authorizeCodeSessionJSONFromFuzzing, authorizeCodeSessionJSONFromStorage)

	// while the fuzzer will panic if AuthorizeRequest changes in a way that cannot be fuzzed,
	// if it adds a new field that can be fuzzed, this check will fail
	// thus if AuthorizeRequest changes, we will detect it here (though we could possibly miss an omitempty field)
	require.Equal(t, ExpectedAuthorizeCodeSessionJSONFromFuzzing, authorizeCodeSessionJSONFromFuzzing)
}
