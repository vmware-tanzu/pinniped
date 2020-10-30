// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package webhookcachefiller

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	idpv1alpha1 "go.pinniped.dev/generated/1.19/apis/concierge/idp/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/1.19/client/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/1.19/client/informers/externalversions"
	"go.pinniped.dev/internal/controller/identityprovider/idpcache"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/testlogger"
)

func TestController(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		syncKey          controllerlib.Key
		webhookIDPs      []runtime.Object
		wantErr          string
		wantLogs         []string
		wantCacheEntries int
	}{
		{
			name:    "not found",
			syncKey: controllerlib.Key{Namespace: "test-namespace", Name: "test-name"},
			wantLogs: []string{
				`webhookcachefiller-controller "level"=0 "msg"="Sync() found that the WebhookIdentityProvider does not exist yet or was deleted"`,
			},
		},
		{
			name:    "invalid webhook",
			syncKey: controllerlib.Key{Namespace: "test-namespace", Name: "test-name"},
			webhookIDPs: []runtime.Object{
				&idpv1alpha1.WebhookIdentityProvider{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test-namespace",
						Name:      "test-name",
					},
					Spec: idpv1alpha1.WebhookIdentityProviderSpec{
						Endpoint: "invalid url",
					},
				},
			},
			wantErr: `failed to build webhook config: parse "http://invalid url": invalid character " " in host name`,
		},
		{
			name:    "valid webhook",
			syncKey: controllerlib.Key{Namespace: "test-namespace", Name: "test-name"},
			webhookIDPs: []runtime.Object{
				&idpv1alpha1.WebhookIdentityProvider{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test-namespace",
						Name:      "test-name",
					},
					Spec: idpv1alpha1.WebhookIdentityProviderSpec{
						Endpoint: "https://example.com",
						TLS:      &idpv1alpha1.TLSSpec{CertificateAuthorityData: ""},
					},
				},
			},
			wantLogs: []string{
				`webhookcachefiller-controller "level"=0 "msg"="added new webhook IDP" "endpoint"="https://example.com" "idp"={"name":"test-name","namespace":"test-namespace"}`,
			},
			wantCacheEntries: 1,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fakeClient := pinnipedfake.NewSimpleClientset(tt.webhookIDPs...)
			informers := pinnipedinformers.NewSharedInformerFactory(fakeClient, 0)
			cache := idpcache.New()
			testLog := testlogger.New(t)

			controller := New(cache, informers.IDP().V1alpha1().WebhookIdentityProviders(), testLog)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			informers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: tt.syncKey}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantLogs, testLog.Lines())
			require.Equal(t, tt.wantCacheEntries, len(cache.Keys()))
		})
	}
}

func TestNewWebhookAuthenticator(t *testing.T) {
	t.Run("temp file failure", func(t *testing.T) {
		brokenTempFile := func(_ string, _ string) (*os.File, error) { return nil, fmt.Errorf("some temp file error") }
		res, err := newWebhookAuthenticator(nil, brokenTempFile, clientcmd.WriteToFile)
		require.Nil(t, res)
		require.EqualError(t, err, "unable to create temporary file: some temp file error")
	})

	t.Run("marshal failure", func(t *testing.T) {
		marshalError := func(_ clientcmdapi.Config, _ string) error { return fmt.Errorf("some marshal error") }
		res, err := newWebhookAuthenticator(&idpv1alpha1.WebhookIdentityProviderSpec{}, ioutil.TempFile, marshalError)
		require.Nil(t, res)
		require.EqualError(t, err, "unable to marshal kubeconfig: some marshal error")
	})

	t.Run("invalid base64", func(t *testing.T) {
		res, err := newWebhookAuthenticator(&idpv1alpha1.WebhookIdentityProviderSpec{
			Endpoint: "https://example.com",
			TLS:      &idpv1alpha1.TLSSpec{CertificateAuthorityData: "invalid-base64"},
		}, ioutil.TempFile, clientcmd.WriteToFile)
		require.Nil(t, res)
		require.EqualError(t, err, "invalid TLS configuration: illegal base64 data at input byte 7")
	})

	t.Run("valid config with no TLS spec", func(t *testing.T) {
		res, err := newWebhookAuthenticator(&idpv1alpha1.WebhookIdentityProviderSpec{
			Endpoint: "https://example.com",
		}, ioutil.TempFile, clientcmd.WriteToFile)
		require.NotNil(t, res)
		require.NoError(t, err)
	})

	t.Run("success", func(t *testing.T) {
		caBundle, url := testutil.TLSTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			body, err := ioutil.ReadAll(r.Body)
			require.NoError(t, err)
			require.Contains(t, string(body), "test-token")
			_, err = w.Write([]byte(`{}`))
			require.NoError(t, err)
		})
		spec := &idpv1alpha1.WebhookIdentityProviderSpec{
			Endpoint: url,
			TLS: &idpv1alpha1.TLSSpec{
				CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(caBundle)),
			},
		}
		res, err := newWebhookAuthenticator(spec, ioutil.TempFile, clientcmd.WriteToFile)
		require.NoError(t, err)
		require.NotNil(t, res)

		resp, authenticated, err := res.AuthenticateToken(context.Background(), "test-token")
		require.NoError(t, err)
		require.Nil(t, resp)
		require.False(t, authenticated)
	})
}
