// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	aggregatorclientscheme "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"

	loginv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/login/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/1.20/apis/supervisor/idp/v1alpha1"
	pinnipedconciergeclientsetscheme "go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned/scheme"
	pinnipedsupervisorclientsetscheme "go.pinniped.dev/generated/1.20/client/supervisor/clientset/versioned/scheme"
)

func Test_schemeRestMapper(t *testing.T) {
	type args struct {
		scheme *runtime.Scheme
		gvr    schema.GroupVersionResource
		v      Verb
	}
	tests := []struct {
		name string
		args args
		want schema.GroupVersionKind
	}{
		{
			name: "config map get",
			args: args{
				scheme: kubescheme.Scheme,
				gvr:    corev1.SchemeGroupVersion.WithResource("configmaps"),
				v:      VerbGet,
			},
			want: corev1.SchemeGroupVersion.WithKind("ConfigMap"),
		},
		{
			name: "config map list",
			args: args{
				scheme: kubescheme.Scheme,
				gvr:    corev1.SchemeGroupVersion.WithResource("configmaps"),
				v:      VerbList,
			},
			want: corev1.SchemeGroupVersion.WithKind("ConfigMapList"),
		},
		{
			name: "endpoints patch",
			args: args{
				scheme: kubescheme.Scheme,
				gvr:    corev1.SchemeGroupVersion.WithResource("endpoints"),
				v:      VerbPatch,
			},
			want: corev1.SchemeGroupVersion.WithKind("Endpoints"),
		},
		{
			name: "endpoints list",
			args: args{
				scheme: kubescheme.Scheme,
				gvr:    corev1.SchemeGroupVersion.WithResource("endpoints"),
				v:      VerbList,
			},
			want: corev1.SchemeGroupVersion.WithKind("EndpointsList"),
		},
		{
			name: "api service create",
			args: args{
				scheme: aggregatorclientscheme.Scheme,
				gvr:    apiregistrationv1.SchemeGroupVersion.WithResource("apiservices"),
				v:      VerbCreate,
			},
			want: apiregistrationv1.SchemeGroupVersion.WithKind("APIService"),
		},
		{
			name: "api service create - wrong scheme",
			args: args{
				scheme: kubescheme.Scheme,
				gvr:    apiregistrationv1.SchemeGroupVersion.WithResource("apiservices"),
				v:      VerbCreate,
			},
		},
		{
			name: "api service list",
			args: args{
				scheme: aggregatorclientscheme.Scheme,
				gvr:    apiregistrationv1.SchemeGroupVersion.WithResource("apiservices"),
				v:      VerbList,
			},
			want: apiregistrationv1.SchemeGroupVersion.WithKind("APIServiceList"),
		},
		{
			name: "token credential delete",
			args: args{
				scheme: pinnipedconciergeclientsetscheme.Scheme,
				gvr:    loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests"),
				v:      VerbDelete,
			},
			want: loginv1alpha1.SchemeGroupVersion.WithKind("TokenCredentialRequest"),
		},
		{
			name: "token credential list",
			args: args{
				scheme: pinnipedconciergeclientsetscheme.Scheme,
				gvr:    loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests"),
				v:      VerbList,
			},
			want: loginv1alpha1.SchemeGroupVersion.WithKind("TokenCredentialRequestList"),
		},
		{
			name: "oidc idp update",
			args: args{
				scheme: pinnipedsupervisorclientsetscheme.Scheme,
				gvr:    idpv1alpha1.SchemeGroupVersion.WithResource("oidcidentityproviders"),
				v:      VerbUpdate,
			},
			want: idpv1alpha1.SchemeGroupVersion.WithKind("OIDCIdentityProvider"),
		},
		{
			name: "oidc idp list",
			args: args{
				scheme: pinnipedsupervisorclientsetscheme.Scheme,
				gvr:    idpv1alpha1.SchemeGroupVersion.WithResource("oidcidentityproviders"),
				v:      VerbList,
			},
			want: idpv1alpha1.SchemeGroupVersion.WithKind("OIDCIdentityProviderList"),
		},
		{
			name: "oidc idp list - wrong scheme",
			args: args{
				scheme: pinnipedconciergeclientsetscheme.Scheme,
				gvr:    idpv1alpha1.SchemeGroupVersion.WithResource("oidcidentityproviders"),
				v:      VerbList,
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			schemeRestMapperFunc := schemeRestMapper(tt.args.scheme)
			gvk, ok := schemeRestMapperFunc(tt.args.gvr, tt.args.v)

			if tt.want.Empty() {
				require.True(t, gvk.Empty())
				require.False(t, ok)
			} else {
				require.Equal(t, tt.want, gvk)
				require.True(t, ok)
			}
		})
	}
}
