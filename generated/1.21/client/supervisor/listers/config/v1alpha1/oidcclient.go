// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "go.pinniped.dev/generated/1.21/apis/supervisor/config/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// OIDCClientLister helps list OIDCClients.
// All objects returned here must be treated as read-only.
type OIDCClientLister interface {
	// List lists all OIDCClients in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.OIDCClient, err error)
	// OIDCClients returns an object that can list and get OIDCClients.
	OIDCClients(namespace string) OIDCClientNamespaceLister
	OIDCClientListerExpansion
}

// oIDCClientLister implements the OIDCClientLister interface.
type oIDCClientLister struct {
	indexer cache.Indexer
}

// NewOIDCClientLister returns a new OIDCClientLister.
func NewOIDCClientLister(indexer cache.Indexer) OIDCClientLister {
	return &oIDCClientLister{indexer: indexer}
}

// List lists all OIDCClients in the indexer.
func (s *oIDCClientLister) List(selector labels.Selector) (ret []*v1alpha1.OIDCClient, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.OIDCClient))
	})
	return ret, err
}

// OIDCClients returns an object that can list and get OIDCClients.
func (s *oIDCClientLister) OIDCClients(namespace string) OIDCClientNamespaceLister {
	return oIDCClientNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// OIDCClientNamespaceLister helps list and get OIDCClients.
// All objects returned here must be treated as read-only.
type OIDCClientNamespaceLister interface {
	// List lists all OIDCClients in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.OIDCClient, err error)
	// Get retrieves the OIDCClient from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.OIDCClient, error)
	OIDCClientNamespaceListerExpansion
}

// oIDCClientNamespaceLister implements the OIDCClientNamespaceLister
// interface.
type oIDCClientNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all OIDCClients in the indexer for a given namespace.
func (s oIDCClientNamespaceLister) List(selector labels.Selector) (ret []*v1alpha1.OIDCClient, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.OIDCClient))
	})
	return ret, err
}

// Get retrieves the OIDCClient from the indexer for a given namespace and name.
func (s oIDCClientNamespaceLister) Get(name string) (*v1alpha1.OIDCClient, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("oidcclient"), name)
	}
	return obj.(*v1alpha1.OIDCClient), nil
}
