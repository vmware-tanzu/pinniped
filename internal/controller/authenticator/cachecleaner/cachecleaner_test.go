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

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	conciergefake "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned/fake"
	conciergeinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions"
	controllerAuthenticator "go.pinniped.dev/internal/controller/authenticator"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
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
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: testWebhookKey1.Name,
					},
				},
				&authenticationv1alpha1.JWTAuthenticator{
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
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: testWebhookKey1.Name,
					},
				},
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: testWebhookKey2.Name,
					},
				},
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: testJWTAuthenticatorKey1.Name,
					},
				},
				&authenticationv1alpha1.JWTAuthenticator{
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
				&authenticationv1alpha1.WebhookAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: testWebhookKey1.Name,
					},
				},
				&authenticationv1alpha1.JWTAuthenticator{
					ObjectMeta: metav1.ObjectMeta{
						Name: testJWTAuthenticatorKey1.Name,
					},
				},
			},
			wantLogs: []string{
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"cachecleaner-controller","caller":"cachecleaner/cachecleaner.go:<line>$cachecleaner.(*controller).Sync","message":"deleting authenticator from cache","authenticator":{"name":"test-jwt-authenticator-name-two"},"kind":"JWTAuthenticator"}`,
				`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"cachecleaner-controller","caller":"cachecleaner/cachecleaner.go:<line>$cachecleaner.(*controller).Sync","message":"deleting authenticator from cache","authenticator":{"name":"test-webhook-name-two"},"kind":"WebhookAuthenticator"}`,
			},
			wantCacheKeys: []authncache.Key{testWebhookKey1, testJWTAuthenticatorKey1, testKeyUnknownType},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When we have t.Parallel() here, this test blocks pretty consistently...y tho?

			fakeClient := conciergefake.NewSimpleClientset(tt.objects...)
			informers := conciergeinformers.NewSharedInformerFactory(fakeClient, 0)
			cache := authncache.New()
			if tt.initialCache != nil {
				tt.initialCache(t, cache)
			}
			webhooks := informers.Authentication().V1alpha1().WebhookAuthenticators()
			jwtAuthenticators := informers.Authentication().V1alpha1().JWTAuthenticators()
			logger, log := plog.TestLogger(t)

			controller := New(cache, webhooks, jwtAuthenticators, logger)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			informers.Start(ctx.Done())
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
			require.ElementsMatch(t, tt.wantLogs, testutil.SplitByNewline(log.String()))
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
