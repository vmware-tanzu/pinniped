/*
Copyright 2020 the Pinniped contributors. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package webhookcachecleaner

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/authenticator"

	idpv1alpha "github.com/suzerain-io/pinniped/generated/1.19/apis/idp/v1alpha1"
	pinnipedfake "github.com/suzerain-io/pinniped/generated/1.19/client/clientset/versioned/fake"
	pinnipedinformers "github.com/suzerain-io/pinniped/generated/1.19/client/informers/externalversions"
	"github.com/suzerain-io/pinniped/internal/controller/identityprovider/idpcache"
	"github.com/suzerain-io/pinniped/internal/controllerlib"
	"github.com/suzerain-io/pinniped/internal/testutil/testlogger"
)

func TestController(t *testing.T) {
	t.Parallel()

	testKey1 := controllerlib.Key{Namespace: "test-namespace", Name: "test-name-one"}
	testKey2 := controllerlib.Key{Namespace: "test-namespace", Name: "test-name-two"}

	tests := []struct {
		name          string
		syncKey       controllerlib.Key
		webhookIDPs   []runtime.Object
		initialCache  map[controllerlib.Key]authenticator.Token
		wantErr       string
		wantLogs      []string
		wantCacheKeys []controllerlib.Key
	}{
		{
			name:         "no change",
			syncKey:      testKey1,
			initialCache: map[controllerlib.Key]authenticator.Token{testKey1: nil},
			webhookIDPs: []runtime.Object{
				&idpv1alpha.WebhookIdentityProvider{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: testKey1.Namespace,
						Name:      testKey1.Name,
					},
				},
			},
			wantCacheKeys: []controllerlib.Key{testKey1},
		},
		{
			name:         "IDPs not yet added",
			syncKey:      testKey1,
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
			wantCacheKeys: []controllerlib.Key{},
		},
		{
			name:    "successful cleanup",
			syncKey: testKey1,
			initialCache: map[controllerlib.Key]authenticator.Token{
				testKey1: nil,
				testKey2: nil,
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
			wantCacheKeys: []controllerlib.Key{testKey1},
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

			syncCtx := controllerlib.Context{Context: ctx, Key: tt.syncKey}

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
