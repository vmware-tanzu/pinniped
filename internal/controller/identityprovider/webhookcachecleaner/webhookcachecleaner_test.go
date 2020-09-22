// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package webhookcachecleaner

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	idpv1alpha "go.pinniped.dev/generated/1.19/apis/idp/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/1.19/client/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/1.19/client/informers/externalversions"
	"go.pinniped.dev/internal/controller/identityprovider/idpcache"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil/testlogger"
)

func TestController(t *testing.T) {
	t.Parallel()

	testKey1 := idpcache.Key{
		APIGroup:  "idp.pinniped.dev",
		Kind:      "WebhookIdentityProvider",
		Namespace: "test-namespace",
		Name:      "test-name-one",
	}
	testKey2 := idpcache.Key{
		APIGroup:  "idp.pinniped.dev",
		Kind:      "WebhookIdentityProvider",
		Namespace: "test-namespace",
		Name:      "test-name-two",
	}
	testKeyNonwebhook := idpcache.Key{
		APIGroup:  "idp.pinniped.dev",
		Kind:      "SomeOtherIdentityProvider",
		Namespace: "test-namespace",
		Name:      "test-name-one",
	}

	tests := []struct {
		name          string
		webhookIDPs   []runtime.Object
		initialCache  map[idpcache.Key]idpcache.Value
		wantErr       string
		wantLogs      []string
		wantCacheKeys []idpcache.Key
	}{
		{
			name:         "no change",
			initialCache: map[idpcache.Key]idpcache.Value{testKey1: nil},
			webhookIDPs: []runtime.Object{
				&idpv1alpha.WebhookIdentityProvider{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testKey1.Namespace,
						Name:      testKey1.Name,
					},
				},
			},
			wantCacheKeys: []idpcache.Key{testKey1},
		},
		{
			name:         "IDPs not yet added",
			initialCache: nil,
			webhookIDPs: []runtime.Object{
				&idpv1alpha.WebhookIdentityProvider{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testKey1.Namespace,
						Name:      testKey1.Name,
					},
				},
				&idpv1alpha.WebhookIdentityProvider{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testKey2.Namespace,
						Name:      testKey2.Name,
					},
				},
			},
			wantCacheKeys: []idpcache.Key{},
		},
		{
			name: "successful cleanup",
			initialCache: map[idpcache.Key]idpcache.Value{
				testKey1:          nil,
				testKey2:          nil,
				testKeyNonwebhook: nil,
			},
			webhookIDPs: []runtime.Object{
				&idpv1alpha.WebhookIdentityProvider{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testKey1.Namespace,
						Name:      testKey1.Name,
					},
				},
			},
			wantLogs: []string{
				`webhookcachecleaner-controller "level"=0 "msg"="deleting webhook IDP from cache" "idp"={"name":"test-name-two","namespace":"test-namespace"}`,
			},
			wantCacheKeys: []idpcache.Key{testKey1, testKeyNonwebhook},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fakeClient := pinnipedfake.NewSimpleClientset(tt.webhookIDPs...)
			informers := pinnipedinformers.NewSharedInformerFactory(fakeClient, 0)
			cache := idpcache.New()
			for k, v := range tt.initialCache {
				cache.Store(k, v)
			}
			testLog := testlogger.New(t)

			controller := New(cache, informers.IDP().V1alpha1().WebhookIdentityProviders(), testLog)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			informers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{
				Context: ctx,
				Key: controllerlib.Key{
					Namespace: "test-namespace",
					Name:      "test-name-one",
				},
			}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantLogs, testLog.Lines())
			require.ElementsMatch(t, tt.wantCacheKeys, cache.Keys())
		})
	}
}
