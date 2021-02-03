// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ownerref

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/testutil"
)

func TestOwnerReferenceMiddleware(t *testing.T) {
	ref1 := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "earth", Namespace: "some-namespace", UID: "0x11"}}
	ref2 := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "mars", Namespace: "some-namespace", UID: "0x12"}}
	ref3 := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "sun", Namespace: "some-namespace", UID: "0x13"}}
	clusterRef := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "bananas", UID: "0x13"}}

	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "twizzlers", Namespace: "some-namespace"}}
	secretOtherNamespace := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "twizzlers", Namespace: "some-other-namespace"}}
	configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "pandas", Namespace: "some-namespace"}}
	clusterRole := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "bananas"}}

	secretWithOwner := withOwnerRef(t, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "twizzlers", Namespace: "some-namespace"}}, ref3)
	configMapWithOwner := withOwnerRef(t, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "pandas", Namespace: "some-namespace"}}, ref3)

	namespaceRef := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "solar-system", UID: "0x42"}}
	secretInSameNamespaceAsNamespaceRef := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "venus", Namespace: "solar-system", UID: "0x11"}}

	type args struct {
		ref         kubeclient.Object
		httpMethod  string
		subresource string
		obj         kubeclient.Object
	}
	tests := []struct {
		name                     string
		args                     args
		wantHandles, wantMutates bool
		wantObj                  kubeclient.Object
	}{
		{
			name: "on update",
			args: args{
				ref:        ref1,
				httpMethod: http.MethodPut,
				obj:        secret.DeepCopy(),
			},
			wantHandles: false,
			wantMutates: false,
		},
		{
			name: "on get",
			args: args{
				ref:        ref1,
				httpMethod: http.MethodGet,
				obj:        secret.DeepCopy(),
			},
			wantHandles: false,
			wantMutates: false,
		},
		{
			name: "on delete",
			args: args{
				ref:        ref1,
				httpMethod: http.MethodDelete,
				obj:        secret.DeepCopy(),
			},
			wantHandles: false,
			wantMutates: false,
		},
		{
			name: "on patch",
			args: args{
				ref:        ref1,
				httpMethod: http.MethodPatch,
				obj:        secret.DeepCopy(),
			},
			wantHandles: false,
			wantMutates: false,
		},
		{
			name: "on create",
			args: args{
				ref:        ref1,
				httpMethod: http.MethodPost,
				obj:        secret.DeepCopy(),
			},
			wantHandles: true,
			wantMutates: true,
			wantObj:     withOwnerRef(t, secret, ref1),
		},
		{
			name: "on create when the ref object is a namespace",
			args: args{
				ref:        namespaceRef,
				httpMethod: http.MethodPost,
				obj:        secretInSameNamespaceAsNamespaceRef.DeepCopy(),
			},
			wantHandles: true,
			wantMutates: true,
			wantObj:     withOwnerRef(t, secretInSameNamespaceAsNamespaceRef, namespaceRef),
		},
		{
			name: "on create config map",
			args: args{
				ref:        ref2,
				httpMethod: http.MethodPost,
				obj:        configMap.DeepCopy(),
			},
			wantHandles: true,
			wantMutates: true,
			wantObj:     withOwnerRef(t, configMap, ref2),
		},
		{
			name: "on create with cluster-scoped owner",
			args: args{
				ref:        clusterRef,
				httpMethod: http.MethodPost,
				obj:        secret.DeepCopy(),
			},
			wantHandles: true,
			wantMutates: true,
			wantObj:     withOwnerRef(t, secret, clusterRef),
		},
		{
			name: "on create of cluster-scoped resource with namespace-scoped owner",
			args: args{
				ref:        ref1,
				httpMethod: http.MethodPost,
				obj:        clusterRole.DeepCopy(),
			},
			wantHandles: false,
			wantMutates: false,
		},
		{
			name: "on create of cluster-scoped resource with cluster-scoped owner",
			args: args{
				ref:        clusterRef,
				httpMethod: http.MethodPost,
				obj:        clusterRole.DeepCopy(),
			},
			wantHandles: true,
			wantMutates: true,
			wantObj:     withOwnerRef(t, clusterRole, clusterRef),
		},
		{
			name: "on create with pre-existing ref",
			args: args{
				ref:        ref1,
				httpMethod: http.MethodPost,
				obj:        secretWithOwner.DeepCopyObject().(kubeclient.Object),
			},
			wantHandles: true,
			wantMutates: false,
		},
		{
			name: "on create with pre-existing ref config map",
			args: args{
				ref:        ref2,
				httpMethod: http.MethodPost,
				obj:        configMapWithOwner.DeepCopyObject().(kubeclient.Object),
			},
			wantHandles: true,
			wantMutates: false,
		},
		{
			name: "on create of subresource",
			args: args{
				ref:         ref2,
				httpMethod:  http.MethodPost,
				subresource: "some-subresource",
				obj:         configMapWithOwner.DeepCopyObject().(kubeclient.Object),
			},
			wantHandles: false,
			wantMutates: false,
		},
		{
			name: "on create with namespace mismatch",
			args: args{
				ref:        ref2,
				httpMethod: http.MethodPost,
				obj:        secretOtherNamespace.DeepCopyObject().(kubeclient.Object),
			},
			wantHandles: false,
			wantMutates: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			middleware := New(tt.args.ref)

			rt := (&testutil.RoundTrip{}).
				WithVerb(verb(t, tt.args.httpMethod)).
				WithNamespace(tt.args.obj.GetNamespace()).
				WithSubresource(tt.args.subresource)
			middleware.Handle(context.Background(), rt)
			require.Empty(t, rt.MutateResponses, 1)
			if !tt.wantHandles {
				require.Empty(t, rt.MutateRequests)
				return
			}
			require.Len(t, rt.MutateRequests, 1)

			orig := tt.args.obj.DeepCopyObject().(kubeclient.Object)
			for _, mutateRequest := range rt.MutateRequests {
				mutateRequest := mutateRequest
				mutateRequest(tt.args.obj)
			}
			if !tt.wantMutates {
				require.Equal(t, orig, tt.args.obj)
			} else {
				require.NotEqual(t, orig, tt.args.obj)
				require.Equal(t, tt.wantObj, tt.args.obj)
			}
		})
	}
}

func withOwnerRef(t *testing.T, obj kubeclient.Object, ref kubeclient.Object) kubeclient.Object {
	t.Helper()

	ownerRef := metav1.OwnerReference{
		Name: ref.GetName(),
		UID:  ref.GetUID(),
	}

	obj = obj.DeepCopyObject().(kubeclient.Object)
	require.Len(t, obj.GetOwnerReferences(), 0)
	obj.SetOwnerReferences([]metav1.OwnerReference{ownerRef})

	return obj
}

func verb(t *testing.T, v string) kubeclient.Verb {
	t.Helper()
	switch v {
	case http.MethodGet:
		return kubeclient.VerbGet
	case http.MethodPut:
		return kubeclient.VerbUpdate
	case http.MethodPost:
		return kubeclient.VerbCreate
	case http.MethodDelete:
		return kubeclient.VerbDelete
	case http.MethodPatch:
		return kubeclient.VerbPatch
	default:
		require.FailNowf(t, "unknown verb", "unknown verb: %q", v)
		return kubeclient.VerbGet // shouldn't get here
	}
}
