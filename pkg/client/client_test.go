/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	placeholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder/v1alpha1"
)

func startTestServer(t *testing.T, handler http.HandlerFunc) (string, string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	caBundle := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.TLS.Certificates[0].Certificate[0],
	}))
	return caBundle, server.URL
}

func TestExchangeToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("invalid configuration", func(t *testing.T) {
		t.Parallel()
		got, err := ExchangeToken(ctx, "", "", "")
		require.EqualError(t, err, "could not get API client: invalid configuration: no configuration has been provided, try setting KUBERNETES_MASTER environment variable")
		require.Nil(t, got)
	})

	t.Run("server error", func(t *testing.T) {
		t.Parallel()
		// Start a test server that returns only 500 errors.
		caBundle, endpoint := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("some server error"))
		})

		got, err := ExchangeToken(ctx, "", caBundle, endpoint)
		require.EqualError(t, err, `could not login: an error on the server ("some server error") has prevented the request from succeeding (post loginrequests.placeholder.suzerain-io.github.io)`)
		require.Nil(t, got)
	})

	t.Run("login failure", func(t *testing.T) {
		t.Parallel()
		// Start a test server that returns success but with an error message
		caBundle, endpoint := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(w).Encode(&placeholderv1alpha1.LoginRequest{
				TypeMeta: metav1.TypeMeta{APIVersion: "placeholder.suzerain-io.github.io/v1alpha1", Kind: "LoginRequest"},
				Status:   placeholderv1alpha1.LoginRequestStatus{Message: "some login failure"},
			})
		})

		got, err := ExchangeToken(ctx, "", caBundle, endpoint)
		require.EqualError(t, err, `login failed: some login failure`)
		require.Nil(t, got)
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		// Start a test server that returns successfully and asserts various properties of the request.
		caBundle, endpoint := startTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, "/apis/placeholder.suzerain-io.github.io/v1alpha1/loginrequests", r.URL.Path)
			require.Equal(t, "application/json", r.Header.Get("content-type"))

			body, err := ioutil.ReadAll(r.Body)
			require.NoError(t, err)
			require.JSONEq(t,
				`{
				  "kind": "LoginRequest",
				  "apiVersion": "placeholder.suzerain-io.github.io/v1alpha1",
				  "metadata": {
					"creationTimestamp": null
				  },
				  "spec": {
					"type": "token",
					"token": {}
				  },
				  "status": {}
				}`,
				string(body),
			)

			w.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(w).Encode(&placeholderv1alpha1.LoginRequest{
				TypeMeta: metav1.TypeMeta{APIVersion: "placeholder.suzerain-io.github.io/v1alpha1", Kind: "LoginRequest"},
				Status: placeholderv1alpha1.LoginRequestStatus{
					Credential: &placeholderv1alpha1.LoginRequestCredential{
						ClientCertificateData: "test-certificate",
						ClientKeyData:         "test-key",
					},
				},
			})
		})

		got, err := ExchangeToken(ctx, "", caBundle, endpoint)
		require.NoError(t, err)
		require.Equal(t, &clientauthenticationv1beta1.ExecCredential{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ExecCredential",
				APIVersion: "client.authentication.k8s.io/v1beta1",
			},
			Status: &clientauthenticationv1beta1.ExecCredentialStatus{
				ClientCertificateData: "test-certificate",
				ClientKeyData:         "test-key",
			},
		}, got)
	})
}
