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

	authv1alpha "go.pinniped.dev/generated/1.19/apis/concierge/authentication/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/1.19/client/concierge/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/1.19/client/concierge/informers/externalversions"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil/testlogger"
)

func TestController(t *testing.T) {
	t.Parallel()

	testKey1 := authncache.Key{
		APIGroup:  "authentication.concierge.pinniped.dev",
		Kind:      "WebhookAuthenticator",
		Namespace: "test-namespace",
		Name:      "test-name-one",
	}
	testKey2 := authncache.Key{
		APIGroup:  "authentication.concierge.pinniped.dev",
		Kind:      "WebhookAuthenticator",
		Namespace: "test-namespace",
		Name:      "test-name-two",
	}
	testKeyNonwebhook := authncache.Key{
		APIGroup:  "authentication.concierge.pinniped.dev",
		Kind:      "SomeOtherAuthenticator",
		Namespace: "test-namespace",
		Name:      "test-name-one",
	}

	tests := []struct {
		name          string
		webhooks      []runtime.Object
		initialCache  map[authncache.Key]authncache.Value
		wantErr       string
		wantLogs      []string
		wantCacheKeys []authncache.Key
	}{
		{
			name:         "no change",
			initialCache: map[authncache.Key]authncache.Value{testKey1: nil},
			webhooks: []runtime.Object{
				&authv1alpha.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testKey1.Namespace,
						Name:      testKey1.Name,
					},
				},
			},
			wantCacheKeys: []authncache.Key{testKey1},
		},
		{
			name:         "authenticators not yet added",
			initialCache: nil,
			webhooks: []runtime.Object{
				&authv1alpha.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testKey1.Namespace,
						Name:      testKey1.Name,
					},
				},
				&authv1alpha.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testKey2.Namespace,
						Name:      testKey2.Name,
					},
				},
			},
			wantCacheKeys: []authncache.Key{},
		},
		{
			name: "successful cleanup",
			initialCache: map[authncache.Key]authncache.Value{
				testKey1:          nil,
				testKey2:          nil,
				testKeyNonwebhook: nil,
			},
			webhooks: []runtime.Object{
				&authv1alpha.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testKey1.Namespace,
						Name:      testKey1.Name,
					},
				},
			},
			wantLogs: []string{
				`webhookcachecleaner-controller "level"=0 "msg"="deleting webhook authenticator from cache" "webhook"={"name":"test-name-two","namespace":"test-namespace"}`,
			},
			wantCacheKeys: []authncache.Key{testKey1, testKeyNonwebhook},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fakeClient := pinnipedfake.NewSimpleClientset(tt.webhooks...)
			informers := pinnipedinformers.NewSharedInformerFactory(fakeClient, 0)
			cache := authncache.New()
			for k, v := range tt.initialCache {
				cache.Store(k, v)
			}
			testLog := testlogger.New(t)

			controller := New(cache, informers.Authentication().V1alpha1().WebhookAuthenticators(), testLog)

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
