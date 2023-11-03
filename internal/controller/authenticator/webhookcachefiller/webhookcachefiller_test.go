// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package webhookcachefiller

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	auth1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
)

func TestController(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		syncKey          controllerlib.Key
		webhooks         []runtime.Object
		wantErr          string
		wantLog          string
		wantCacheEntries int
	}{
		{
			name:    "not found",
			syncKey: controllerlib.Key{Name: "test-name"},
			wantLog: "Sync() found that the WebhookAuthenticator does not exist yet or was deleted",
		},
		{
			name:    "invalid webhook",
			syncKey: controllerlib.Key{Name: "test-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-name",
					},
					Spec: auth1alpha1.WebhookAuthenticatorSpec{
						Endpoint: "invalid url",
					},
				},
			},
			wantErr: `failed to build webhook config: parse "http://invalid url": invalid character " " in host name`,
		},
		{
			name:    "valid webhook",
			syncKey: controllerlib.Key{Name: "other-name"},
			webhooks: []runtime.Object{
				&auth1alpha1.WebhookAuthenticator{
					TypeMeta: metav1.TypeMeta{
						Kind: "WebhookAuthenticatorKind",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "other-name",
					},
					Spec: auth1alpha1.WebhookAuthenticatorSpec{
						Endpoint: "https://example.com",
						TLS:      &auth1alpha1.TLSSpec{CertificateAuthorityData: ""},
					},
				},
			},
			wantLog:          `"message":"added new webhook authenticator","webhook":{"name":"other-name"},"endpoint":"https://example.com"`,
			wantCacheEntries: 1,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fakeClient := pinnipedfake.NewSimpleClientset(tt.webhooks...)
			informers := pinnipedinformers.NewSharedInformerFactory(fakeClient, 0)
			cache := authncache.New()

			var log bytes.Buffer
			controller := New(
				cache,
				informers.Authentication().V1alpha1().WebhookAuthenticators(),
				plog.TestLogger(t, &log),
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			informers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: tt.syncKey}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Contains(t, log.String(), tt.wantLog)
			require.Equal(t, tt.wantCacheEntries, len(cache.Keys()))
			if len(cache.Keys()) > 0 {
				cacheKey := authncache.Key{
					APIGroup: "authentication.concierge.pinniped.dev",
					Kind:     tt.webhooks[0].GetObjectKind().GroupVersionKind().Kind,
					Name:     tt.syncKey.Name,
				}
				require.NotNil(t, cache.Get(cacheKey))
			}
		})
	}
}

func TestNewWebhookAuthenticator(t *testing.T) {
	t.Run("temp file failure", func(t *testing.T) {
		brokenTempFile := func(_ string, _ string) (*os.File, error) { return nil, fmt.Errorf("some temp file error") }
		res, err := newWebhookTokenAuthenticator(nil, brokenTempFile, clientcmd.WriteToFile)
		require.Nil(t, res)
		require.EqualError(t, err, "unable to create temporary file: some temp file error")
	})

	t.Run("marshal failure", func(t *testing.T) {
		marshalError := func(_ clientcmdapi.Config, _ string) error { return fmt.Errorf("some marshal error") }
		res, err := newWebhookTokenAuthenticator(&auth1alpha1.WebhookAuthenticatorSpec{}, os.CreateTemp, marshalError)
		require.Nil(t, res)
		require.EqualError(t, err, "unable to marshal kubeconfig: some marshal error")
	})

	t.Run("invalid base64", func(t *testing.T) {
		res, err := newWebhookTokenAuthenticator(&auth1alpha1.WebhookAuthenticatorSpec{
			Endpoint: "https://example.com",
			TLS:      &auth1alpha1.TLSSpec{CertificateAuthorityData: "invalid-base64"},
		}, os.CreateTemp, clientcmd.WriteToFile)
		require.Nil(t, res)
		require.EqualError(t, err, "invalid TLS configuration: illegal base64 data at input byte 7")
	})

	t.Run("invalid pem data", func(t *testing.T) {
		res, err := newWebhookTokenAuthenticator(&auth1alpha1.WebhookAuthenticatorSpec{
			Endpoint: "https://example.com",
			TLS:      &auth1alpha1.TLSSpec{CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte("bad data"))},
		}, os.CreateTemp, clientcmd.WriteToFile)
		require.Nil(t, res)
		require.EqualError(t, err, "invalid TLS configuration: certificateAuthorityData is not valid PEM: data does not contain any valid RSA or ECDSA certificates")
	})

	t.Run("valid config with no TLS spec", func(t *testing.T) {
		res, err := newWebhookTokenAuthenticator(&auth1alpha1.WebhookAuthenticatorSpec{
			Endpoint: "https://example.com",
		}, os.CreateTemp, clientcmd.WriteToFile)
		require.NotNil(t, res)
		require.NoError(t, err)
	})

	t.Run("success", func(t *testing.T) {
		caBundle, url := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.Contains(t, string(body), "test-token")
			_, err = w.Write([]byte(`{}`))
			require.NoError(t, err)
		})
		spec := &auth1alpha1.WebhookAuthenticatorSpec{
			Endpoint: url,
			TLS: &auth1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(caBundle)),
			},
		}
		res, err := newWebhookTokenAuthenticator(spec, os.CreateTemp, clientcmd.WriteToFile)
		require.NoError(t, err)
		require.NotNil(t, res)

		resp, authenticated, err := res.AuthenticateToken(context.Background(), "test-token")
		require.NoError(t, err)
		require.Nil(t, resp)
		require.False(t, authenticated)
	})
}
