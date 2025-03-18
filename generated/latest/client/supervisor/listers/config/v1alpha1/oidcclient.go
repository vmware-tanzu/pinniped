// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	labels "k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers"
	cache "k8s.io/client-go/tools/cache"
)

// OIDCClientLister helps list OIDCClients.
// All objects returned here must be treated as read-only.
type OIDCClientLister interface {
	// List lists all OIDCClients in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*configv1alpha1.OIDCClient, err error)
	// OIDCClients returns an object that can list and get OIDCClients.
	OIDCClients(namespace string) OIDCClientNamespaceLister
	OIDCClientListerExpansion
}

// oIDCClientLister implements the OIDCClientLister interface.
type oIDCClientLister struct {
	listers.ResourceIndexer[*configv1alpha1.OIDCClient]
}

// NewOIDCClientLister returns a new OIDCClientLister.
func NewOIDCClientLister(indexer cache.Indexer) OIDCClientLister {
	return &oIDCClientLister{listers.New[*configv1alpha1.OIDCClient](indexer, configv1alpha1.Resource("oidcclient"))}
}

// OIDCClients returns an object that can list and get OIDCClients.
func (s *oIDCClientLister) OIDCClients(namespace string) OIDCClientNamespaceLister {
	return oIDCClientNamespaceLister{listers.NewNamespaced[*configv1alpha1.OIDCClient](s.ResourceIndexer, namespace)}
}

// OIDCClientNamespaceLister helps list and get OIDCClients.
// All objects returned here must be treated as read-only.
type OIDCClientNamespaceLister interface {
	// List lists all OIDCClients in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*configv1alpha1.OIDCClient, err error)
	// Get retrieves the OIDCClient from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*configv1alpha1.OIDCClient, error)
	OIDCClientNamespaceListerExpansion
}

// oIDCClientNamespaceLister implements the OIDCClientNamespaceLister
// interface.
type oIDCClientNamespaceLister struct {
	listers.ResourceIndexer[*configv1alpha1.OIDCClient]
}
