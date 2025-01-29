// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1alpha1 "go.pinniped.dev/generated/1.32/apis/supervisor/config/v1alpha1"
	configv1alpha1 "go.pinniped.dev/generated/1.32/client/supervisor/clientset/versioned/typed/config/v1alpha1"
	gentype "k8s.io/client-go/gentype"
)

// fakeFederationDomains implements FederationDomainInterface
type fakeFederationDomains struct {
	*gentype.FakeClientWithList[*v1alpha1.FederationDomain, *v1alpha1.FederationDomainList]
	Fake *FakeConfigV1alpha1
}

func newFakeFederationDomains(fake *FakeConfigV1alpha1, namespace string) configv1alpha1.FederationDomainInterface {
	return &fakeFederationDomains{
		gentype.NewFakeClientWithList[*v1alpha1.FederationDomain, *v1alpha1.FederationDomainList](
			fake.Fake,
			namespace,
			v1alpha1.SchemeGroupVersion.WithResource("federationdomains"),
			v1alpha1.SchemeGroupVersion.WithKind("FederationDomain"),
			func() *v1alpha1.FederationDomain { return &v1alpha1.FederationDomain{} },
			func() *v1alpha1.FederationDomainList { return &v1alpha1.FederationDomainList{} },
			func(dst, src *v1alpha1.FederationDomainList) { dst.ListMeta = src.ListMeta },
			func(list *v1alpha1.FederationDomainList) []*v1alpha1.FederationDomain {
				return gentype.ToPointerSlice(list.Items)
			},
			func(list *v1alpha1.FederationDomainList, items []*v1alpha1.FederationDomain) {
				list.Items = gentype.FromPointerSlice(items)
			},
		),
		fake,
	}
}
