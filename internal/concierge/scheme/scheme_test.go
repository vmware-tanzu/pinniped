// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scheme

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	identityapi "go.pinniped.dev/generated/latest/apis/concierge/identity"
	identityv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/identity/v1alpha1"
	loginapi "go.pinniped.dev/generated/latest/apis/concierge/login"
	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
)

func TestNew(t *testing.T) {
	// the standard group
	regularLoginGV := schema.GroupVersion{
		Group:   "login.concierge.pinniped.dev",
		Version: "v1alpha1",
	}
	regularLoginGVInternal := schema.GroupVersion{
		Group:   "login.concierge.pinniped.dev",
		Version: runtime.APIVersionInternal,
	}
	regularIdentityGV := schema.GroupVersion{
		Group:   "identity.concierge.pinniped.dev",
		Version: "v1alpha1",
	}
	regularIdentityGVInternal := schema.GroupVersion{
		Group:   "identity.concierge.pinniped.dev",
		Version: runtime.APIVersionInternal,
	}

	// the canonical other group
	otherLoginGV := schema.GroupVersion{
		Group:   "login.concierge.walrus.tld",
		Version: "v1alpha1",
	}
	otherLoginGVInternal := schema.GroupVersion{
		Group:   "login.concierge.walrus.tld",
		Version: runtime.APIVersionInternal,
	}
	otherIdentityGV := schema.GroupVersion{
		Group:   "identity.concierge.walrus.tld",
		Version: "v1alpha1",
	}
	otherIdentityGVInternal := schema.GroupVersion{
		Group:   "identity.concierge.walrus.tld",
		Version: runtime.APIVersionInternal,
	}

	// kube's core internal
	internalGV := schema.GroupVersion{
		Group:   "",
		Version: runtime.APIVersionInternal,
	}

	tests := []struct {
		name                     string
		apiGroupSuffix           string
		want                     map[schema.GroupVersionKind]reflect.Type
		wantLoginGroupVersion    schema.GroupVersion
		wantIdentityGroupVersion schema.GroupVersion
	}{
		{
			name:           "regular api group",
			apiGroupSuffix: "pinniped.dev",
			want: map[schema.GroupVersionKind]reflect.Type{
				// all the types that are in the aggregated API group

				regularLoginGV.WithKind("TokenCredentialRequest"):     reflect.TypeOf(&loginv1alpha1.TokenCredentialRequest{}).Elem(),
				regularLoginGV.WithKind("TokenCredentialRequestList"): reflect.TypeOf(&loginv1alpha1.TokenCredentialRequestList{}).Elem(),

				regularLoginGVInternal.WithKind("TokenCredentialRequest"):     reflect.TypeOf(&loginapi.TokenCredentialRequest{}).Elem(),
				regularLoginGVInternal.WithKind("TokenCredentialRequestList"): reflect.TypeOf(&loginapi.TokenCredentialRequestList{}).Elem(),

				regularIdentityGV.WithKind("WhoAmIRequest"):     reflect.TypeOf(&identityv1alpha1.WhoAmIRequest{}).Elem(),
				regularIdentityGV.WithKind("WhoAmIRequestList"): reflect.TypeOf(&identityv1alpha1.WhoAmIRequestList{}).Elem(),

				regularIdentityGVInternal.WithKind("WhoAmIRequest"):     reflect.TypeOf(&identityapi.WhoAmIRequest{}).Elem(),
				regularIdentityGVInternal.WithKind("WhoAmIRequestList"): reflect.TypeOf(&identityapi.WhoAmIRequestList{}).Elem(),

				regularLoginGV.WithKind("CreateOptions"): reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				regularLoginGV.WithKind("DeleteOptions"): reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				regularLoginGV.WithKind("ExportOptions"): reflect.TypeOf(&metav1.ExportOptions{}).Elem(),
				regularLoginGV.WithKind("GetOptions"):    reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				regularLoginGV.WithKind("ListOptions"):   reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				regularLoginGV.WithKind("PatchOptions"):  reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				regularLoginGV.WithKind("UpdateOptions"): reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				regularLoginGV.WithKind("WatchEvent"):    reflect.TypeOf(&metav1.WatchEvent{}).Elem(),

				regularIdentityGV.WithKind("CreateOptions"): reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				regularIdentityGV.WithKind("DeleteOptions"): reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				regularIdentityGV.WithKind("ExportOptions"): reflect.TypeOf(&metav1.ExportOptions{}).Elem(),
				regularIdentityGV.WithKind("GetOptions"):    reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				regularIdentityGV.WithKind("ListOptions"):   reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				regularIdentityGV.WithKind("PatchOptions"):  reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				regularIdentityGV.WithKind("UpdateOptions"): reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				regularIdentityGV.WithKind("WatchEvent"):    reflect.TypeOf(&metav1.WatchEvent{}).Elem(),

				regularLoginGVInternal.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

				regularIdentityGVInternal.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

				// the types below this line do not really matter to us because they are in the core group

				internalGV.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

				metav1.Unversioned.WithKind("APIGroup"):        reflect.TypeOf(&metav1.APIGroup{}).Elem(),
				metav1.Unversioned.WithKind("APIGroupList"):    reflect.TypeOf(&metav1.APIGroupList{}).Elem(),
				metav1.Unversioned.WithKind("APIResourceList"): reflect.TypeOf(&metav1.APIResourceList{}).Elem(),
				metav1.Unversioned.WithKind("APIVersions"):     reflect.TypeOf(&metav1.APIVersions{}).Elem(),
				metav1.Unversioned.WithKind("CreateOptions"):   reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				metav1.Unversioned.WithKind("DeleteOptions"):   reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				metav1.Unversioned.WithKind("ExportOptions"):   reflect.TypeOf(&metav1.ExportOptions{}).Elem(),
				metav1.Unversioned.WithKind("GetOptions"):      reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				metav1.Unversioned.WithKind("ListOptions"):     reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				metav1.Unversioned.WithKind("PatchOptions"):    reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				metav1.Unversioned.WithKind("Status"):          reflect.TypeOf(&metav1.Status{}).Elem(),
				metav1.Unversioned.WithKind("UpdateOptions"):   reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				metav1.Unversioned.WithKind("WatchEvent"):      reflect.TypeOf(&metav1.WatchEvent{}).Elem(),
			},
			wantLoginGroupVersion:    regularLoginGV,
			wantIdentityGroupVersion: regularIdentityGV,
		},
		{
			name:           "other api group",
			apiGroupSuffix: "walrus.tld",
			want: map[schema.GroupVersionKind]reflect.Type{
				// all the types that are in the aggregated API group

				otherLoginGV.WithKind("TokenCredentialRequest"):     reflect.TypeOf(&loginv1alpha1.TokenCredentialRequest{}).Elem(),
				otherLoginGV.WithKind("TokenCredentialRequestList"): reflect.TypeOf(&loginv1alpha1.TokenCredentialRequestList{}).Elem(),

				otherLoginGVInternal.WithKind("TokenCredentialRequest"):     reflect.TypeOf(&loginapi.TokenCredentialRequest{}).Elem(),
				otherLoginGVInternal.WithKind("TokenCredentialRequestList"): reflect.TypeOf(&loginapi.TokenCredentialRequestList{}).Elem(),

				otherIdentityGV.WithKind("WhoAmIRequest"):     reflect.TypeOf(&identityv1alpha1.WhoAmIRequest{}).Elem(),
				otherIdentityGV.WithKind("WhoAmIRequestList"): reflect.TypeOf(&identityv1alpha1.WhoAmIRequestList{}).Elem(),

				otherIdentityGVInternal.WithKind("WhoAmIRequest"):     reflect.TypeOf(&identityapi.WhoAmIRequest{}).Elem(),
				otherIdentityGVInternal.WithKind("WhoAmIRequestList"): reflect.TypeOf(&identityapi.WhoAmIRequestList{}).Elem(),

				otherLoginGV.WithKind("CreateOptions"): reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				otherLoginGV.WithKind("DeleteOptions"): reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				otherLoginGV.WithKind("ExportOptions"): reflect.TypeOf(&metav1.ExportOptions{}).Elem(),
				otherLoginGV.WithKind("GetOptions"):    reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				otherLoginGV.WithKind("ListOptions"):   reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				otherLoginGV.WithKind("PatchOptions"):  reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				otherLoginGV.WithKind("UpdateOptions"): reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				otherLoginGV.WithKind("WatchEvent"):    reflect.TypeOf(&metav1.WatchEvent{}).Elem(),

				otherIdentityGV.WithKind("CreateOptions"): reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				otherIdentityGV.WithKind("DeleteOptions"): reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				otherIdentityGV.WithKind("ExportOptions"): reflect.TypeOf(&metav1.ExportOptions{}).Elem(),
				otherIdentityGV.WithKind("GetOptions"):    reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				otherIdentityGV.WithKind("ListOptions"):   reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				otherIdentityGV.WithKind("PatchOptions"):  reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				otherIdentityGV.WithKind("UpdateOptions"): reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				otherIdentityGV.WithKind("WatchEvent"):    reflect.TypeOf(&metav1.WatchEvent{}).Elem(),

				otherLoginGVInternal.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

				otherIdentityGVInternal.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

				// the types below this line do not really matter to us because they are in the core group

				internalGV.WithKind("WatchEvent"): reflect.TypeOf(&metav1.InternalEvent{}).Elem(),

				metav1.Unversioned.WithKind("APIGroup"):        reflect.TypeOf(&metav1.APIGroup{}).Elem(),
				metav1.Unversioned.WithKind("APIGroupList"):    reflect.TypeOf(&metav1.APIGroupList{}).Elem(),
				metav1.Unversioned.WithKind("APIResourceList"): reflect.TypeOf(&metav1.APIResourceList{}).Elem(),
				metav1.Unversioned.WithKind("APIVersions"):     reflect.TypeOf(&metav1.APIVersions{}).Elem(),
				metav1.Unversioned.WithKind("CreateOptions"):   reflect.TypeOf(&metav1.CreateOptions{}).Elem(),
				metav1.Unversioned.WithKind("DeleteOptions"):   reflect.TypeOf(&metav1.DeleteOptions{}).Elem(),
				metav1.Unversioned.WithKind("ExportOptions"):   reflect.TypeOf(&metav1.ExportOptions{}).Elem(),
				metav1.Unversioned.WithKind("GetOptions"):      reflect.TypeOf(&metav1.GetOptions{}).Elem(),
				metav1.Unversioned.WithKind("ListOptions"):     reflect.TypeOf(&metav1.ListOptions{}).Elem(),
				metav1.Unversioned.WithKind("PatchOptions"):    reflect.TypeOf(&metav1.PatchOptions{}).Elem(),
				metav1.Unversioned.WithKind("Status"):          reflect.TypeOf(&metav1.Status{}).Elem(),
				metav1.Unversioned.WithKind("UpdateOptions"):   reflect.TypeOf(&metav1.UpdateOptions{}).Elem(),
				metav1.Unversioned.WithKind("WatchEvent"):      reflect.TypeOf(&metav1.WatchEvent{}).Elem(),
			},
			wantLoginGroupVersion:    otherLoginGV,
			wantIdentityGroupVersion: otherIdentityGV,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			scheme, loginGV, identityGV := New(tt.apiGroupSuffix)
			require.Equal(t, tt.want, scheme.AllKnownTypes())
			require.Equal(t, tt.wantLoginGroupVersion, loginGV)
			require.Equal(t, tt.wantIdentityGroupVersion, identityGV)

			// make a credential request like a client would send
			authenticationConciergeAPIGroup := "authentication.concierge." + tt.apiGroupSuffix
			credentialRequest := &loginv1alpha1.TokenCredentialRequest{
				Spec: loginv1alpha1.TokenCredentialRequestSpec{
					Authenticator: corev1.TypedLocalObjectReference{
						APIGroup: &authenticationConciergeAPIGroup,
					},
				},
			}

			// run defaulting on it
			scheme.Default(credentialRequest)

			// make sure the group is restored if needed
			require.Equal(t, "authentication.concierge.pinniped.dev", *credentialRequest.Spec.Authenticator.APIGroup)

			// make a credential request in the standard group
			defaultAuthenticationConciergeAPIGroup := "authentication.concierge.pinniped.dev"
			defaultCredentialRequest := &loginv1alpha1.TokenCredentialRequest{
				Spec: loginv1alpha1.TokenCredentialRequestSpec{
					Authenticator: corev1.TypedLocalObjectReference{
						APIGroup: &defaultAuthenticationConciergeAPIGroup,
					},
				},
			}

			// run defaulting on it
			scheme.Default(defaultCredentialRequest)

			if tt.apiGroupSuffix == "pinniped.dev" { // when using the standard group, this should just work
				require.Equal(t, "authentication.concierge.pinniped.dev", *defaultCredentialRequest.Spec.Authenticator.APIGroup)
			} else { // when using any other group, this should always be a cache miss
				require.True(t, strings.HasPrefix(*defaultCredentialRequest.Spec.Authenticator.APIGroup, "_INVALID_API_GROUP_2"))
			}
		})
	}
}
