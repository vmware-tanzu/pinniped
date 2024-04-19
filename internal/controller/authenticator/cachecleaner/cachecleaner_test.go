// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cachecleaner

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/authenticator"

	authv1alpha "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions"
	controllerAuthenticator "go.pinniped.dev/internal/controller/authenticator"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil/testlogger"
)

func TestController(t *testing.T) {
	t.Parallel()

	testWebhookKey1 := authncache.Key{
		APIGroup: "authentication.concierge.pinniped.dev",
		Kind:     "WebhookAuthenticator",
		Name:     "test-webhook-name-one",
	}
	testWebhookKey2 := authncache.Key{
		APIGroup: "authentication.concierge.pinniped.dev",
		Kind:     "WebhookAuthenticator",
		Name:     "test-webhook-name-two",
	}
	testJWTAuthenticatorKey1 := authncache.Key{
		APIGroup: "authentication.concierge.pinniped.dev",
		Kind:     "JWTAuthenticator",
		Name:     "test-jwt-authenticator-name-one",
	}
	testJWTAuthenticatorKey2 := authncache.Key{
		APIGroup: "authentication.concierge.pinniped.dev",
		Kind:     "JWTAuthenticator",
		Name:     "test-jwt-authenticator-name-two",
	}
	testKeyUnknownType := authncache.Key{
		APIGroup: "authentication.concierge.pinniped.dev",
		Kind:     "SomeOtherAuthenticator",
		Name:     "test-name-one",
	}

	tests := []struct {
		name          string
		objects       []runtime.Object
		initialCache  func(t *testing.T, cache *authncache.Cache)
		wantErr       string
		wantLogs      []string
		wantCacheKeys []authncache.Key
	}{
		{
			name: "no change",
			initialCache: func(t *testing.T, cache *authncache.Cache) {
				cache.Store(testWebhookKey1, nil)
				cache.Store(testJWTAuthenticatorKey1, nil)
			},
			objects: []runtime.Object{
				&authv1alpha.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: testWebhookKey1.Name,
					},
				},
				&authv1alpha.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: testJWTAuthenticatorKey1.Name,
					},
				},
			},
			wantCacheKeys: []authncache.Key{testWebhookKey1, testJWTAuthenticatorKey1},
		},
		{
			name: "authenticators not yet added",
			objects: []runtime.Object{
				&authv1alpha.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: testWebhookKey1.Name,
					},
				},
				&authv1alpha.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: testWebhookKey2.Name,
					},
				},
				&authv1alpha.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: testJWTAuthenticatorKey1.Name,
					},
				},
				&authv1alpha.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: testJWTAuthenticatorKey2.Name,
					},
				},
			},
			wantCacheKeys: []authncache.Key{},
		},
		{
			name: "successful cleanup",
			initialCache: func(t *testing.T, cache *authncache.Cache) {
				cache.Store(testWebhookKey1, nil)
				cache.Store(testWebhookKey2, nil)
				cache.Store(testJWTAuthenticatorKey1, newClosableCacheValue(t, false))
				cache.Store(testJWTAuthenticatorKey2, newClosableCacheValue(t, true))
				cache.Store(testKeyUnknownType, nil)
			},
			objects: []runtime.Object{
				&authv1alpha.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: testWebhookKey1.Name,
					},
				},
				&authv1alpha.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: testJWTAuthenticatorKey1.Name,
					},
				},
			},
			wantLogs: []string{
				`cachecleaner-controller "level"=0 "msg"="deleting authenticator from cache" "authenticator"={"name":"test-jwt-authenticator-name-two"} "kind"="JWTAuthenticator"`,
				`cachecleaner-controller "level"=0 "msg"="deleting authenticator from cache" "authenticator"={"name":"test-webhook-name-two"} "kind"="WebhookAuthenticator"`,
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
			if tt.initialCache != nil {
				tt.initialCache(t, cache)
			}
			testLog := testlogger.NewLegacy(t) //nolint:staticcheck  // old test with lots of log statements

			webhooks := informers.Authentication().V1alpha1().WebhookAuthenticators()
			jwtAuthenticators := informers.Authentication().V1alpha1().JWTAuthenticators()
			controller := New(cache, webhooks, jwtAuthenticators, testLog.Logger)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			informers.Start(ctx.Done())
			informers.WaitForCacheSync(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{
				Context: ctx,
				Key: controllerlib.Key{
					Name: "test-webhook-name-one",
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

type mockValue struct {
	wasClosed bool
}

func (m *mockValue) Close() {
	m.wasClosed = true
}

func (m *mockValue) AuthenticateToken(_ context.Context, _ string) (*authenticator.Response, bool, error) {
	panic("implement me")
}

var _ authncache.Value = (*mockValue)(nil)
var _ controllerAuthenticator.Closer = (*mockValue)(nil)

func newClosableCacheValue(t *testing.T, wantClose bool) authncache.Value {
	t.Helper()
	mock := &mockValue{}

	t.Cleanup(func() {
		require.Equal(t, wantClose, mock.wasClosed)
	})

	return mock
}
