// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	idpv1alpha1 "go.pinniped.dev/generated/1.32/apis/supervisor/idp/v1alpha1"
	labels "k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers"
	cache "k8s.io/client-go/tools/cache"
)

// ActiveDirectoryIdentityProviderLister helps list ActiveDirectoryIdentityProviders.
// All objects returned here must be treated as read-only.
type ActiveDirectoryIdentityProviderLister interface {
	// List lists all ActiveDirectoryIdentityProviders in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*idpv1alpha1.ActiveDirectoryIdentityProvider, err error)
	// ActiveDirectoryIdentityProviders returns an object that can list and get ActiveDirectoryIdentityProviders.
	ActiveDirectoryIdentityProviders(namespace string) ActiveDirectoryIdentityProviderNamespaceLister
	ActiveDirectoryIdentityProviderListerExpansion
}

// activeDirectoryIdentityProviderLister implements the ActiveDirectoryIdentityProviderLister interface.
type activeDirectoryIdentityProviderLister struct {
	listers.ResourceIndexer[*idpv1alpha1.ActiveDirectoryIdentityProvider]
}

// NewActiveDirectoryIdentityProviderLister returns a new ActiveDirectoryIdentityProviderLister.
func NewActiveDirectoryIdentityProviderLister(indexer cache.Indexer) ActiveDirectoryIdentityProviderLister {
	return &activeDirectoryIdentityProviderLister{listers.New[*idpv1alpha1.ActiveDirectoryIdentityProvider](indexer, idpv1alpha1.Resource("activedirectoryidentityprovider"))}
}

// ActiveDirectoryIdentityProviders returns an object that can list and get ActiveDirectoryIdentityProviders.
func (s *activeDirectoryIdentityProviderLister) ActiveDirectoryIdentityProviders(namespace string) ActiveDirectoryIdentityProviderNamespaceLister {
	return activeDirectoryIdentityProviderNamespaceLister{listers.NewNamespaced[*idpv1alpha1.ActiveDirectoryIdentityProvider](s.ResourceIndexer, namespace)}
}

// ActiveDirectoryIdentityProviderNamespaceLister helps list and get ActiveDirectoryIdentityProviders.
// All objects returned here must be treated as read-only.
type ActiveDirectoryIdentityProviderNamespaceLister interface {
	// List lists all ActiveDirectoryIdentityProviders in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*idpv1alpha1.ActiveDirectoryIdentityProvider, err error)
	// Get retrieves the ActiveDirectoryIdentityProvider from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*idpv1alpha1.ActiveDirectoryIdentityProvider, error)
	ActiveDirectoryIdentityProviderNamespaceListerExpansion
}

// activeDirectoryIdentityProviderNamespaceLister implements the ActiveDirectoryIdentityProviderNamespaceLister
// interface.
type activeDirectoryIdentityProviderNamespaceLister struct {
	listers.ResourceIndexer[*idpv1alpha1.ActiveDirectoryIdentityProvider]
}
