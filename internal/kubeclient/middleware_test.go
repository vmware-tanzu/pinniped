// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func Test_request_mutate(t *testing.T) {
	tests := []struct {
		name     string
		reqFuncs []func(Object)
		obj      Object
		want     *mutationResult
		wantObj  Object
		wantErr  string
	}{
		{
			name: "mutate config map data",
			reqFuncs: []func(Object){
				func(obj Object) {
					cm := obj.(*corev1.ConfigMap)
					cm.Data = map[string]string{"new": "stuff"}
				},
			},
			obj: &corev1.ConfigMap{
				TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
				Data:       map[string]string{"old": "things"},
				BinaryData: map[string][]byte{"weee": nil},
			},
			want: &mutationResult{
				origGVK:    schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
				newGVK:     schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
				gvkChanged: false,
				mutated:    true,
			},
			wantObj: &corev1.ConfigMap{
				TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
				Data:       map[string]string{"new": "stuff"},
				BinaryData: map[string][]byte{"weee": nil},
			},
			wantErr: "",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			r := &request{reqFuncs: tt.reqFuncs}
			orig := tt.obj.DeepCopyObject()

			got, err := r.mutateRequest(tt.obj)

			if len(tt.wantErr) > 0 {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, tt.want, got)

			if tt.wantObj != nil {
				require.Equal(t, tt.wantObj, tt.obj)
			} else {
				require.Equal(t, orig, tt.obj)
			}
		})
	}
}
