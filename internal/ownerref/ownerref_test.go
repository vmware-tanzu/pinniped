// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ownerref

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestOwnerReferenceMiddleware(t *testing.T) {
	ref1 := metav1.OwnerReference{
		Name: "earth",
		UID:  "0x11",
	}
	ref2 := metav1.OwnerReference{
		Name: "mars",
		UID:  "0x12",
	}
	ref3 := metav1.OwnerReference{
		Name: "sun",
		UID:  "0x13",
	}

	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "twizzlers"}}
	configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "pandas"}}

	secretWithOwner := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "twizzlers", OwnerReferences: []metav1.OwnerReference{ref3}}}
	configMapWithOwner := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "pandas", OwnerReferences: []metav1.OwnerReference{ref3}}}

	type args struct {
		ref        metav1.OwnerReference
		httpMethod string
		obj        metav1.Object
	}
	tests := []struct {
		name                     string
		args                     args
		wantHandles, wantMutates bool
		wantObj                  metav1.Object
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
			wantObj:     nil,
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
			name: "on create with pre-existing ref",
			args: args{
				ref:        ref1,
				httpMethod: http.MethodPost,
				obj:        secretWithOwner.DeepCopy(),
			},
			wantHandles: true,
			wantMutates: false,
			wantObj:     nil,
		},
		{
			name: "on create with pre-existing ref config map",
			args: args{
				ref:        ref2,
				httpMethod: http.MethodPost,
				obj:        configMapWithOwner.DeepCopy(),
			},
			wantHandles: true,
			wantMutates: false,
			wantObj:     nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			middleware := New(tt.args.ref)

			handles := middleware.Handles(tt.args.httpMethod)
			require.Equal(t, tt.wantHandles, handles)

			if !handles {
				return
			}

			orig := tt.args.obj.(runtime.Object).DeepCopyObject()

			mutates := middleware.Mutate(tt.args.obj)
			require.Equal(t, tt.wantMutates, mutates)

			if mutates {
				require.NotEqual(t, orig, tt.args.obj)
				require.Equal(t, tt.wantObj, tt.args.obj)
			} else {
				require.Equal(t, orig, tt.args.obj)
			}
		})
	}
}

func withOwnerRef(t *testing.T, obj runtime.Object, ref metav1.OwnerReference) metav1.Object {
	t.Helper()

	obj = obj.DeepCopyObject()
	accessor, err := meta.Accessor(obj)
	require.NoError(t, err)

	require.Len(t, accessor.GetOwnerReferences(), 0)
	accessor.SetOwnerReferences([]metav1.OwnerReference{ref})

	return accessor
}
