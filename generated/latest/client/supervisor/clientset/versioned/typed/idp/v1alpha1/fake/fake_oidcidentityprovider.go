// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	idpv1alpha1 "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/typed/idp/v1alpha1"
	gentype "k8s.io/client-go/gentype"
)

// fakeOIDCIdentityProviders implements OIDCIdentityProviderInterface
type fakeOIDCIdentityProviders struct {
	*gentype.FakeClientWithList[*v1alpha1.OIDCIdentityProvider, *v1alpha1.OIDCIdentityProviderList]
	Fake *FakeIDPV1alpha1
}

func newFakeOIDCIdentityProviders(fake *FakeIDPV1alpha1, namespace string) idpv1alpha1.OIDCIdentityProviderInterface {
	return &fakeOIDCIdentityProviders{
		gentype.NewFakeClientWithList[*v1alpha1.OIDCIdentityProvider, *v1alpha1.OIDCIdentityProviderList](
			fake.Fake,
			namespace,
			v1alpha1.SchemeGroupVersion.WithResource("oidcidentityproviders"),
			v1alpha1.SchemeGroupVersion.WithKind("OIDCIdentityProvider"),
			func() *v1alpha1.OIDCIdentityProvider { return &v1alpha1.OIDCIdentityProvider{} },
			func() *v1alpha1.OIDCIdentityProviderList { return &v1alpha1.OIDCIdentityProviderList{} },
			func(dst, src *v1alpha1.OIDCIdentityProviderList) { dst.ListMeta = src.ListMeta },
			func(list *v1alpha1.OIDCIdentityProviderList) []*v1alpha1.OIDCIdentityProvider {
				return gentype.ToPointerSlice(list.Items)
			},
			func(list *v1alpha1.OIDCIdentityProviderList, items []*v1alpha1.OIDCIdentityProvider) {
				list.Items = gentype.FromPointerSlice(items)
			},
		),
		fake,
	}
}
