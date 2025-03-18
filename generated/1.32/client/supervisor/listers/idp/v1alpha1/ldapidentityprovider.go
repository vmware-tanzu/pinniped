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

// LDAPIdentityProviderLister helps list LDAPIdentityProviders.
// All objects returned here must be treated as read-only.
type LDAPIdentityProviderLister interface {
	// List lists all LDAPIdentityProviders in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*idpv1alpha1.LDAPIdentityProvider, err error)
	// LDAPIdentityProviders returns an object that can list and get LDAPIdentityProviders.
	LDAPIdentityProviders(namespace string) LDAPIdentityProviderNamespaceLister
	LDAPIdentityProviderListerExpansion
}

// lDAPIdentityProviderLister implements the LDAPIdentityProviderLister interface.
type lDAPIdentityProviderLister struct {
	listers.ResourceIndexer[*idpv1alpha1.LDAPIdentityProvider]
}

// NewLDAPIdentityProviderLister returns a new LDAPIdentityProviderLister.
func NewLDAPIdentityProviderLister(indexer cache.Indexer) LDAPIdentityProviderLister {
	return &lDAPIdentityProviderLister{listers.New[*idpv1alpha1.LDAPIdentityProvider](indexer, idpv1alpha1.Resource("ldapidentityprovider"))}
}

// LDAPIdentityProviders returns an object that can list and get LDAPIdentityProviders.
func (s *lDAPIdentityProviderLister) LDAPIdentityProviders(namespace string) LDAPIdentityProviderNamespaceLister {
	return lDAPIdentityProviderNamespaceLister{listers.NewNamespaced[*idpv1alpha1.LDAPIdentityProvider](s.ResourceIndexer, namespace)}
}

// LDAPIdentityProviderNamespaceLister helps list and get LDAPIdentityProviders.
// All objects returned here must be treated as read-only.
type LDAPIdentityProviderNamespaceLister interface {
	// List lists all LDAPIdentityProviders in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*idpv1alpha1.LDAPIdentityProvider, err error)
	// Get retrieves the LDAPIdentityProvider from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*idpv1alpha1.LDAPIdentityProvider, error)
	LDAPIdentityProviderNamespaceListerExpansion
}

// lDAPIdentityProviderNamespaceLister implements the LDAPIdentityProviderNamespaceLister
// interface.
type lDAPIdentityProviderNamespaceLister struct {
	listers.ResourceIndexer[*idpv1alpha1.LDAPIdentityProvider]
}
