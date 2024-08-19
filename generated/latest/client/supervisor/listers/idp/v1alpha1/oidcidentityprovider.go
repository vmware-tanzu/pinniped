// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// OIDCIdentityProviderLister helps list OIDCIdentityProviders.
// All objects returned here must be treated as read-only.
type OIDCIdentityProviderLister interface {
	// List lists all OIDCIdentityProviders in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.OIDCIdentityProvider, err error)
	// OIDCIdentityProviders returns an object that can list and get OIDCIdentityProviders.
	OIDCIdentityProviders(namespace string) OIDCIdentityProviderNamespaceLister
	OIDCIdentityProviderListerExpansion
}

// oIDCIdentityProviderLister implements the OIDCIdentityProviderLister interface.
type oIDCIdentityProviderLister struct {
	listers.ResourceIndexer[*v1alpha1.OIDCIdentityProvider]
}

// NewOIDCIdentityProviderLister returns a new OIDCIdentityProviderLister.
func NewOIDCIdentityProviderLister(indexer cache.Indexer) OIDCIdentityProviderLister {
	return &oIDCIdentityProviderLister{listers.New[*v1alpha1.OIDCIdentityProvider](indexer, v1alpha1.Resource("oidcidentityprovider"))}
}

// OIDCIdentityProviders returns an object that can list and get OIDCIdentityProviders.
func (s *oIDCIdentityProviderLister) OIDCIdentityProviders(namespace string) OIDCIdentityProviderNamespaceLister {
	return oIDCIdentityProviderNamespaceLister{listers.NewNamespaced[*v1alpha1.OIDCIdentityProvider](s.ResourceIndexer, namespace)}
}

// OIDCIdentityProviderNamespaceLister helps list and get OIDCIdentityProviders.
// All objects returned here must be treated as read-only.
type OIDCIdentityProviderNamespaceLister interface {
	// List lists all OIDCIdentityProviders in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.OIDCIdentityProvider, err error)
	// Get retrieves the OIDCIdentityProvider from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.OIDCIdentityProvider, error)
	OIDCIdentityProviderNamespaceListerExpansion
}

// oIDCIdentityProviderNamespaceLister implements the OIDCIdentityProviderNamespaceLister
// interface.
type oIDCIdentityProviderNamespaceLister struct {
	listers.ResourceIndexer[*v1alpha1.OIDCIdentityProvider]
}
