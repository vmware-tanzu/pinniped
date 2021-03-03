// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package conciergeclient

import (
	"context"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/testutil"
)

func TestNew(t *testing.T) {
	t.Parallel()
	testCA, err := certauthority.New(pkix.Name{}, 1*time.Hour)
	require.NoError(t, err)

	tests := []struct {
		name    string
		opts    []Option
		wantErr string
	}{
		{
			name: "some option error",
			opts: []Option{
				func(client *Client) error { return fmt.Errorf("some error") },
			},
			wantErr: "some error",
		},
		{
			name: "with invalid authenticator",
			opts: []Option{
				WithAuthenticator("invalid-type", "test-authenticator"),
			},
			wantErr: `invalid authenticator type: "invalid-type", supported values are "webhook" and "jwt"`,
		},
		{
			name: "with empty authenticator name",
			opts: []Option{
				WithAuthenticator("webhook", ""),
			},
			wantErr: `authenticator name must not be empty`,
		},
		{
			name: "invalid CA bundle",
			opts: []Option{
				WithCABundle("invalid-base64"),
			},
			wantErr: "invalid CA bundle data: no certificates found",
		},
		{
			name: "invalid base64 CA bundle",
			opts: []Option{
				WithBase64CABundle("invalid-base64"),
			},
			wantErr: "invalid CA bundle data: illegal base64 data at input byte 7",
		},
		{
			name: "empty endpoint",
			opts: []Option{
				WithEndpoint(""),
			},
			wantErr: `endpoint must not be empty`,
		},
		{
			name: "invalid endpoint",
			opts: []Option{
				WithEndpoint("%"),
			},
			wantErr: `invalid endpoint URL: parse "%": invalid URL escape "%"`,
		},
		{
			name: "non-https endpoint",
			opts: []Option{
				WithEndpoint("http://example.com"),
			},
			wantErr: `invalid endpoint scheme "http" (must be "https")`,
		},
		{
			name: "missing authenticator",
			opts: []Option{
				WithEndpoint("https://example.com"),
			},
			wantErr: "WithAuthenticator must be specified",
		},
		{
			name: "missing endpoint",
			opts: []Option{
				WithAuthenticator("jwt", "test-authenticator"),
			},
			wantErr: "WithEndpoint must be specified",
		},
		{
			name: "empty api group suffix",
			opts: []Option{
				WithAuthenticator("jwt", "test-authenticator"),
				WithEndpoint("https://example.com"),
				WithAPIGroupSuffix(""),
			},
			wantErr: "invalid api group suffix: [must contain '.', a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')]",
		},
		{
			name: "invalid api group suffix",
			opts: []Option{
				WithAuthenticator("jwt", "test-authenticator"),
				WithEndpoint("https://example.com"),
				WithAPIGroupSuffix(".starts.with.dot"),
			},
			wantErr: "invalid api group suffix: a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')",
		},
		{
			name: "valid",
			opts: []Option{
				WithEndpoint("https://example.com"),
				WithCABundle(""),
				WithCABundle(string(testCA.Bundle())),
				WithBase64CABundle(base64.StdEncoding.EncodeToString(testCA.Bundle())),
				WithAuthenticator("jwt", "test-authenticator"),
				WithAuthenticator("webhook", "test-authenticator"),
				WithAPIGroupSuffix("suffix.com"),
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := New(tt.opts...)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
		})
	}
}

func TestExchangeToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("clientset failure", func(t *testing.T) {
		c := Client{endpoint: &url.URL{}}
		_, err := c.ExchangeToken(ctx, "")
		require.EqualError(t, err, "invalid configuration: no configuration has been provided, try setting KUBERNETES_MASTER environment variable")
	})

	t.Run("server error", func(t *testing.T) {
		t.Parallel()
		// Start a test server that returns only 500 errors.
		caBundle, endpoint := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("some server error"))
		})

		client, err := New(WithEndpoint(endpoint), WithCABundle(caBundle), WithAuthenticator("jwt", "test-authenticator"))
		require.NoError(t, err)

		got, err := client.ExchangeToken(ctx, "test-token")
		require.EqualError(t, err, `could not login: an error on the server ("some server error") has prevented the request from succeeding (post tokencredentialrequests.login.concierge.pinniped.dev)`)
		require.Nil(t, got)
	})

	t.Run("login failure", func(t *testing.T) {
		t.Parallel()
		// Start a test server that returns success but with an error message
		errorMessage := "some login failure"
		caBundle, endpoint := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(w).Encode(&loginv1alpha1.TokenCredentialRequest{
				TypeMeta: metav1.TypeMeta{APIVersion: "login.concierge.pinniped.dev/v1alpha1", Kind: "TokenCredentialRequest"},
				Status:   loginv1alpha1.TokenCredentialRequestStatus{Message: &errorMessage},
			})
		})

		client, err := New(WithEndpoint(endpoint), WithCABundle(caBundle), WithAuthenticator("jwt", "test-authenticator"))
		require.NoError(t, err)

		got, err := client.ExchangeToken(ctx, "test-token")
		require.EqualError(t, err, `login failed: some login failure`)
		require.Nil(t, got)
	})

	t.Run("login failure unknown error", func(t *testing.T) {
		t.Parallel()
		// Start a test server that returns without any error message but also without valid credentials
		caBundle, endpoint := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(w).Encode(&loginv1alpha1.TokenCredentialRequest{
				TypeMeta: metav1.TypeMeta{APIVersion: "login.concierge.pinniped.dev/v1alpha1", Kind: "TokenCredentialRequest"},
			})
		})

		client, err := New(WithEndpoint(endpoint), WithCABundle(caBundle), WithAuthenticator("jwt", "test-authenticator"))
		require.NoError(t, err)

		got, err := client.ExchangeToken(ctx, "test-token")
		require.EqualError(t, err, `login failed: unknown cause`)
		require.Nil(t, got)
	})

	t.Run("success from cache", func(t *testing.T) {
		cache := mockCredCache{
			t: t,
			getReturnsCred: &clientauthenticationv1beta1.ExecCredentialStatus{
				Token: "test-token",
			},
		}
		c := Client{cache: &cache, endpoint: &url.URL{}, authenticator: &corev1.TypedLocalObjectReference{}}
		got, err := c.ExchangeToken(ctx, "some-token")
		require.NoError(t, err)
		require.Equal(t,
			// some opaque value that's a SHA256 of a bunch of input parameters but should be static across test runs.
			[]string{"08a6c37d4d9b9b537def2a275517abe8a70c687cb1cffa8cd3b317c005a38c93"},
			cache.sawGetKeys,
		)
		require.Empty(t, cache.sawPutKeys)
		require.Equal(t, &clientauthenticationv1beta1.ExecCredential{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ExecCredential",
				APIVersion: "client.authentication.k8s.io/v1beta1",
			},
			Status: &clientauthenticationv1beta1.ExecCredentialStatus{
				Token: "test-token",
			},
		}, got)
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		expires := metav1.NewTime(time.Now().Truncate(time.Second))

		// Start a test server that returns successfully and asserts various properties of the request.
		caBundle, endpoint := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, "/apis/login.concierge.pinniped.dev/v1alpha1/tokencredentialrequests", r.URL.Path)
			require.Equal(t, "application/json", r.Header.Get("content-type"))

			body, err := ioutil.ReadAll(r.Body)
			require.NoError(t, err)
			require.JSONEq(t,
				`{
				  "kind": "TokenCredentialRequest",
				  "apiVersion": "login.concierge.pinniped.dev/v1alpha1",
				  "metadata": {
					"creationTimestamp": null
				  },
				  "spec": {
					"token": "test-token",
					"authenticator": {
						"apiGroup": "authentication.concierge.pinniped.dev",
						"kind": "WebhookAuthenticator",
						"name": "test-webhook"
					}
				  },
				  "status": {}
				}`,
				string(body),
			)

			w.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(w).Encode(&loginv1alpha1.TokenCredentialRequest{
				TypeMeta: metav1.TypeMeta{APIVersion: "login.concierge.pinniped.dev/v1alpha1", Kind: "TokenCredentialRequest"},
				Status: loginv1alpha1.TokenCredentialRequestStatus{
					Credential: &loginv1alpha1.ClusterCredential{
						ExpirationTimestamp:   expires,
						ClientCertificateData: "test-certificate",
						ClientKeyData:         "test-key",
					},
				},
			})
		})

		cache := mockCredCache{t: t}
		client, err := New(
			WithEndpoint(endpoint),
			WithCABundle(caBundle),
			WithAuthenticator("webhook", "test-webhook"),
			WithCache(&cache),
		)
		require.NoError(t, err)

		got, err := client.ExchangeToken(ctx, "test-token")
		require.NoError(t, err)
		require.Equal(t, &clientauthenticationv1beta1.ExecCredential{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ExecCredential",
				APIVersion: "client.authentication.k8s.io/v1beta1",
			},
			Status: &clientauthenticationv1beta1.ExecCredentialStatus{
				ClientCertificateData: "test-certificate",
				ClientKeyData:         "test-key",
				ExpirationTimestamp:   &expires,
			},
		}, got)
		require.Len(t, cache.sawPutCreds, 1)
		require.Equal(t, cache.sawPutCreds[0].ClientCertificateData, "test-certificate")
	})
}

// mockCredCache exists to avoid an import cycle if we generate mocks into another package.
type mockCredCache struct {
	t              *testing.T
	sawGetKeys     []string
	getReturnsCred *clientauthenticationv1beta1.ExecCredentialStatus
	sawPutKeys     []string
	sawPutCreds    []*clientauthenticationv1beta1.ExecCredentialStatus
}

func (m *mockCredCache) GetClusterCredential(key string) *clientauthenticationv1beta1.ExecCredentialStatus {
	m.t.Logf("saw mock GetClusterCredential() with key %s", key)
	m.sawGetKeys = append(m.sawGetKeys, key)
	return m.getReturnsCred
}

func (m *mockCredCache) PutClusterCredential(key string, cred *clientauthenticationv1beta1.ExecCredentialStatus) {
	m.t.Logf("saw mock PutClusterCredential() with key %s and cred %s", key, cred)
	m.sawPutKeys = append(m.sawPutKeys, key)
	m.sawPutCreds = append(m.sawPutCreds, cred)
}
