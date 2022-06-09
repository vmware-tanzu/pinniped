// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scheme

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	oauthapi "go.pinniped.dev/generated/latest/apis/supervisor/virtual/oauth"
	oauthv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/virtual/oauth/v1alpha1"
)

func TestNew(t *testing.T) {
	// the standard group
	regularOAuthGV := schema.GroupVersion{
		Group:   "oauth.virtual.supervisor.pinniped.dev",
		Version: "v1alpha1",
	}
	regularOAuthGVInternal := schema.GroupVersion{
		Group:   "oauth.virtual.supervisor.pinniped.dev",
		Version: runtime.APIVersionInternal,
	}

	// the canonical other group
	otherOAuthGV := schema.GroupVersion{
		Group:   "oauth.virtual.supervisor.walrus.tld",
		Version: "v1alpha1",
	}
	otherOAuthGVInternal := schema.GroupVersion{
		Group:   "oauth.virtual.supervisor.walrus.tld",
		Version: runtime.APIVersionInternal,
	}

	// kube's core internal
	internalGV := schema.GroupVersion{
		Group:   "",
		Version: runtime.APIVersionInternal,
	}

	tests := []struct {
		name                  string
		apiGroupSuffix        string
		want                  map[schema.GroupVersionKind]reflect.Type
		wantOAuthGroupVersion schema.GroupVersion
	}{
		{
			name:           "regular api group",
			apiGroupSuffix: "pinniped.dev",
			want: map[schema.GroupVersionKind]reflect.Type{
				// all the types that are in the aggregated API group

				regularOAuthGV.WithKind("OIDCClientSecretRequest"): reflect.TypeOf(&oauthv1alpha1.OIDCClientSecretRequest{}).Elem(),

				regularOAuthGVInternal.WithKind("OIDCClientSecretRequest"): reflect.TypeOf(&oauthapi.OIDCClientSecretRequest{}).Elem(),

				regularOAuthGV.WithKind("CreateOptions"): reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				regularOAuthGV.WithKind("DeleteOptions"): reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				regularOAuthGV.WithKind("GetOptions"):    reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				regularOAuthGV.WithKind("ListOptions"):   reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				regularOAuthGV.WithKind("PatchOptions"):  reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				regularOAuthGV.WithKind("UpdateOptions"): reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				regularOAuthGV.WithKind("WatchEvent"):    reflect.TypeOf(&metav1.WatchEvent{}).Elem(),

				regularOAuthGVInternal.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

				// the types below this line do not really matter to us because they are in the core group

				internalGV.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

				metav1.Unversioned.WithKind("APIGroup"):        reflect.TypeOf(&metav1.APIGroup{}).Elem(),
				metav1.Unversioned.WithKind("APIGroupList"):    reflect.TypeOf(&metav1.APIGroupList{}).Elem(),
				metav1.Unversioned.WithKind("APIResourceList"): reflect.TypeOf(&metav1.APIResourceList{}).Elem(),
				metav1.Unversioned.WithKind("APIVersions"):     reflect.TypeOf(&metav1.APIVersions{}).Elem(),
				metav1.Unversioned.WithKind("CreateOptions"):   reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				metav1.Unversioned.WithKind("DeleteOptions"):   reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				metav1.Unversioned.WithKind("GetOptions"):      reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				metav1.Unversioned.WithKind("ListOptions"):     reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				metav1.Unversioned.WithKind("PatchOptions"):    reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				metav1.Unversioned.WithKind("Status"):          reflect.TypeOf(&metav1.Status{}).Elem(),
				metav1.Unversioned.WithKind("UpdateOptions"):   reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				metav1.Unversioned.WithKind("WatchEvent"):      reflect.TypeOf(&metav1.WatchEvent{}).Elem(),
			},
			wantOAuthGroupVersion: regularOAuthGV,
		},
		{
			name:           "other api group",
			apiGroupSuffix: "walrus.tld",
			want: map[schema.GroupVersionKind]reflect.Type{
				// all the types that are in the aggregated API group

				otherOAuthGV.WithKind("OIDCClientSecretRequest"): reflect.TypeOf(&oauthv1alpha1.OIDCClientSecretRequest{}).Elem(),

				otherOAuthGVInternal.WithKind("OIDCClientSecretRequest"): reflect.TypeOf(&oauthapi.OIDCClientSecretRequest{}).Elem(),

				otherOAuthGV.WithKind("CreateOptions"): reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				otherOAuthGV.WithKind("DeleteOptions"): reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				otherOAuthGV.WithKind("GetOptions"):    reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				otherOAuthGV.WithKind("ListOptions"):   reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				otherOAuthGV.WithKind("PatchOptions"):  reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				otherOAuthGV.WithKind("UpdateOptions"): reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				otherOAuthGV.WithKind("WatchEvent"):    reflect.TypeOf(&metav1.WatchEvent{}).Elem(),

				otherOAuthGVInternal.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

				// the types below this line do not really matter to us because they are in the core group

				internalGV.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

				metav1.Unversioned.WithKind("APIGroup"):        reflect.TypeOf(&metav1.APIGroup{}).Elem(),
				metav1.Unversioned.WithKind("APIGroupList"):    reflect.TypeOf(&metav1.APIGroupList{}).Elem(),
				metav1.Unversioned.WithKind("APIResourceList"): reflect.TypeOf(&metav1.APIResourceList{}).Elem(),
				metav1.Unversioned.WithKind("APIVersions"):     reflect.TypeOf(&metav1.APIVersions{}).Elem(),
				metav1.Unversioned.WithKind("CreateOptions"):   reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				metav1.Unversioned.WithKind("DeleteOptions"):   reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				metav1.Unversioned.WithKind("GetOptions"):      reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				metav1.Unversioned.WithKind("ListOptions"):     reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				metav1.Unversioned.WithKind("PatchOptions"):    reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				metav1.Unversioned.WithKind("Status"):          reflect.TypeOf(&metav1.Status{}).Elem(),
				metav1.Unversioned.WithKind("UpdateOptions"):   reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				metav1.Unversioned.WithKind("WatchEvent"):      reflect.TypeOf(&metav1.WatchEvent{}).Elem(),
			},
			wantOAuthGroupVersion: otherOAuthGV,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			scheme, oauthGV := New(tt.apiGroupSuffix)
			require.Equal(t, tt.want, scheme.AllKnownTypes())
			require.Equal(t, tt.wantOAuthGroupVersion, oauthGV)
		})
	}
}
