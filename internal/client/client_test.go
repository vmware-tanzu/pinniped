// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	loginv1alpha1 "go.pinniped.dev/generated/1.19/apis/concierge/login/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/1.19/apis/idp/v1alpha1"
	"go.pinniped.dev/internal/testutil"
)

func TestExchangeToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testIDP := corev1.TypedLocalObjectReference{
		APIGroup: &idpv1alpha1.SchemeGroupVersion.Group,
		Kind:     "WebhookIdentityProvider",
		Name:     "test-webhook",
	}

	t.Run("invalid configuration", func(t *testing.T) {
		t.Parallel()
		got, err := ExchangeToken(ctx, "test-namespace", testIDP, "", "", "")
		require.EqualError(t, err, "could not get API client: invalid configuration: no configuration has been provided, try setting KUBERNETES_MASTER environment variable")
		require.Nil(t, got)
	})

	t.Run("server error", func(t *testing.T) {
		t.Parallel()
		// Start a test server that returns only 500 errors.
		caBundle, endpoint := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("some server error"))
		})

		got, err := ExchangeToken(ctx, "test-namespace", testIDP, "", caBundle, endpoint)
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

		got, err := ExchangeToken(ctx, "test-namespace", testIDP, "", caBundle, endpoint)
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

		got, err := ExchangeToken(ctx, "test-namespace", testIDP, "", caBundle, endpoint)
		require.EqualError(t, err, `login failed: unknown`)
		require.Nil(t, got)
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		expires := metav1.NewTime(time.Now().Truncate(time.Second))

		// Start a test server that returns successfully and asserts various properties of the request.
		caBundle, endpoint := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, "/apis/login.concierge.pinniped.dev/v1alpha1/namespaces/test-namespace/tokencredentialrequests", r.URL.Path)
			require.Equal(t, "application/json", r.Header.Get("content-type"))

			body, err := ioutil.ReadAll(r.Body)
			require.NoError(t, err)
			require.JSONEq(t,
				`{
				  "kind": "TokenCredentialRequest",
				  "apiVersion": "login.concierge.pinniped.dev/v1alpha1",
				  "metadata": {
					"creationTimestamp": null,
					"namespace": "test-namespace"
				  },
				  "spec": {
					"token": "test-token",
					"identityProvider": {
						"apiGroup": "idp.pinniped.dev",
						"kind": "WebhookIdentityProvider",
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

		got, err := ExchangeToken(ctx, "test-namespace", testIDP, "test-token", caBundle, endpoint)
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
	})
}
