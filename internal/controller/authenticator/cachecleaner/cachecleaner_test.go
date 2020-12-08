// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cachecleaner

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

	testWebhookKey1 := authncache.Key{
		APIGroup:  "authentication.concierge.pinniped.dev",
		Kind:      "WebhookAuthenticator",
		Namespace: "test-namespace",
		Name:      "test-webhook-name-one",
	}
	testWebhookKey2 := authncache.Key{
		APIGroup:  "authentication.concierge.pinniped.dev",
		Kind:      "WebhookAuthenticator",
		Namespace: "test-namespace",
		Name:      "test-webhook-name-two",
	}
	testJWTAuthenticatorKey1 := authncache.Key{
		APIGroup:  "authentication.concierge.pinniped.dev",
		Kind:      "JWTAuthenticator",
		Namespace: "test-namespace",
		Name:      "test-jwt-authenticator-name-one",
	}
	testJWTAuthenticatorKey2 := authncache.Key{
		APIGroup:  "authentication.concierge.pinniped.dev",
		Kind:      "JWTAuthenticator",
		Namespace: "test-namespace",
		Name:      "test-jwt-authenticator-name-two",
	}
	testKeyUnknownType := authncache.Key{
		APIGroup:  "authentication.concierge.pinniped.dev",
		Kind:      "SomeOtherAuthenticator",
		Namespace: "test-namespace",
		Name:      "test-name-one",
	}

	tests := []struct {
		name          string
		objects       []runtime.Object
		initialCache  map[authncache.Key]authncache.Value
		wantErr       string
		wantLogs      []string
		wantCacheKeys []authncache.Key
	}{
		{
			name: "no change",
			initialCache: map[authncache.Key]authncache.Value{
				testWebhookKey1:          nil,
				testJWTAuthenticatorKey1: nil,
			},
			objects: []runtime.Object{
				&authv1alpha.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testWebhookKey1.Namespace,
						Name:      testWebhookKey1.Name,
					},
				},
				&authv1alpha.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testJWTAuthenticatorKey1.Namespace,
						Name:      testJWTAuthenticatorKey1.Name,
					},
				},
			},
			wantCacheKeys: []authncache.Key{testWebhookKey1, testJWTAuthenticatorKey1},
		},
		{
			name:         "authenticators not yet added",
			initialCache: nil,
			objects: []runtime.Object{
				&authv1alpha.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testWebhookKey1.Namespace,
						Name:      testWebhookKey1.Name,
					},
				},
				&authv1alpha.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testWebhookKey2.Namespace,
						Name:      testWebhookKey2.Name,
					},
				},
				&authv1alpha.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testJWTAuthenticatorKey1.Namespace,
						Name:      testJWTAuthenticatorKey1.Name,
					},
				},
				&authv1alpha.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testJWTAuthenticatorKey2.Namespace,
						Name:      testJWTAuthenticatorKey2.Name,
					},
				},
			},
			wantCacheKeys: []authncache.Key{},
		},
		{
			name: "successful cleanup",
			initialCache: map[authncache.Key]authncache.Value{
				testWebhookKey1:          nil,
				testWebhookKey2:          nil,
				testJWTAuthenticatorKey1: newClosableCacheValue(t, "closable1", 0),
				testJWTAuthenticatorKey2: newClosableCacheValue(t, "closable2", 1),
				testKeyUnknownType:       nil,
			},
			objects: []runtime.Object{
				&authv1alpha.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testWebhookKey1.Namespace,
						Name:      testWebhookKey1.Name,
					},
				},
				&authv1alpha.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testJWTAuthenticatorKey1.Namespace,
						Name:      testJWTAuthenticatorKey1.Name,
					},
				},
			},
			wantLogs: []string{
				`cachecleaner-controller "level"=0 "msg"="deleting authenticator from cache" "authenticator"={"name":"test-jwt-authenticator-name-two","namespace":"test-namespace"} "kind"="JWTAuthenticator"`,
				`cachecleaner-controller "level"=0 "msg"="deleting authenticator from cache" "authenticator"={"name":"test-webhook-name-two","namespace":"test-namespace"} "kind"="WebhookAuthenticator"`,
			},
			wantCacheKeys: []authncache.Key{testWebhookKey1, testJWTAuthenticatorKey1, testKeyUnknownType},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// When we have t.Parallel() here, this test blocks pretty consistently...y tho?

			fakeClient := pinnipedfake.NewSimpleClientset(tt.objects...)
			informers := pinnipedinformers.NewSharedInformerFactory(fakeClient, 0)
			cache := authncache.New()
			for k, v := range tt.initialCache {
				cache.Store(k, v)
			}
			testLog := testlogger.New(t)

			webhooks := informers.Authentication().V1alpha1().WebhookAuthenticators()
			jwtAuthenticators := informers.Authentication().V1alpha1().JWTAuthenticators()
			controller := New(cache, webhooks, jwtAuthenticators, testLog)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			informers.Start(ctx.Done())
			informers.WaitForCacheSync(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{
				Context: ctx,
				Key: controllerlib.Key{
					Namespace: "test-namespace",
					Name:      "test-webhook-name-one",
				},
			}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.ElementsMatch(t, tt.wantLogs, testLog.Lines())
			require.ElementsMatch(t, tt.wantCacheKeys, cache.Keys())
		})
	}
}

func newClosableCacheValue(t *testing.T, name string, wantCloses int) authncache.Value {
	t.Helper()
	c := &closableCacheValue{}
	t.Cleanup(func() {
		require.Equalf(t, wantCloses, c.closeCallCount, "expected %s.Close() to be called %d times", name, wantCloses)
	})
	return c
}

type closableCacheValue struct {
	authncache.Value
	closeCallCount int
}

func (c *closableCacheValue) Close() {
	c.closeCallCount++
}
