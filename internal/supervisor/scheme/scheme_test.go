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

	clientsecretapi "go.pinniped.dev/generated/latest/apis/supervisor/clientsecret"
	clientsecretv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/clientsecret/v1alpha1"
)

func TestNew(t *testing.T) {
	// the standard group
	regularClientSecretGV := schema.GroupVersion{
		Group:   "clientsecret.supervisor.pinniped.dev",
		Version: "v1alpha1",
	}
	regularClientSecretGVInternal := schema.GroupVersion{
		Group:   "clientsecret.supervisor.pinniped.dev",
		Version: runtime.APIVersionInternal,
	}

	// the canonical other group
	otherClientSecretGV := schema.GroupVersion{
		Group:   "clientsecret.supervisor.walrus.tld",
		Version: "v1alpha1",
	}
	otherClientSecretGVInternal := schema.GroupVersion{
		Group:   "clientsecret.supervisor.walrus.tld",
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

				regularClientSecretGV.WithKind("OIDCClientSecretRequest"): reflect.TypeOf(&clientsecretv1alpha1.OIDCClientSecretRequest{}).Elem(),

				regularClientSecretGVInternal.WithKind("OIDCClientSecretRequest"): reflect.TypeOf(&clientsecretapi.OIDCClientSecretRequest{}).Elem(),

				regularClientSecretGV.WithKind("CreateOptions"): reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				regularClientSecretGV.WithKind("DeleteOptions"): reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				regularClientSecretGV.WithKind("GetOptions"):    reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				regularClientSecretGV.WithKind("ListOptions"):   reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				regularClientSecretGV.WithKind("PatchOptions"):  reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				regularClientSecretGV.WithKind("UpdateOptions"): reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				regularClientSecretGV.WithKind("WatchEvent"):    reflect.TypeOf(&metav1.WatchEvent{}).Elem(),

				regularClientSecretGVInternal.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

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
			wantOAuthGroupVersion: regularClientSecretGV,
		},
		{
			name:           "other api group",
			apiGroupSuffix: "walrus.tld",
			want: map[schema.GroupVersionKind]reflect.Type{
				// all the types that are in the aggregated API group

				otherClientSecretGV.WithKind("OIDCClientSecretRequest"): reflect.TypeOf(&clientsecretv1alpha1.OIDCClientSecretRequest{}).Elem(),

				otherClientSecretGVInternal.WithKind("OIDCClientSecretRequest"): reflect.TypeOf(&clientsecretapi.OIDCClientSecretRequest{}).Elem(),

				otherClientSecretGV.WithKind("CreateOptions"): reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				otherClientSecretGV.WithKind("DeleteOptions"): reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				otherClientSecretGV.WithKind("GetOptions"):    reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				otherClientSecretGV.WithKind("ListOptions"):   reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				otherClientSecretGV.WithKind("PatchOptions"):  reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				otherClientSecretGV.WithKind("UpdateOptions"): reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				otherClientSecretGV.WithKind("WatchEvent"):    reflect.TypeOf(&metav1.WatchEvent{}).Elem(),

				otherClientSecretGVInternal.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

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
			wantOAuthGroupVersion: otherClientSecretGV,
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
