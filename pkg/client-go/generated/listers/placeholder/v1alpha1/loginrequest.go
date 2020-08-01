/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/suzerain-io/placeholder-name/pkg/api/placeholder/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// LoginRequestLister helps list LoginRequests.
// All objects returned here must be treated as read-only.
type LoginRequestLister interface {
	// List lists all LoginRequests in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.LoginRequest, err error)
	// Get retrieves the LoginRequest from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.LoginRequest, error)
	LoginRequestListerExpansion
}

// loginRequestLister implements the LoginRequestLister interface.
type loginRequestLister struct {
	indexer cache.Indexer
}

// NewLoginRequestLister returns a new LoginRequestLister.
func NewLoginRequestLister(indexer cache.Indexer) LoginRequestLister {
	return &loginRequestLister{indexer: indexer}
}

// List lists all LoginRequests in the indexer.
func (s *loginRequestLister) List(selector labels.Selector) (ret []*v1alpha1.LoginRequest, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.LoginRequest))
	})
	return ret, err
}

// Get retrieves the LoginRequest from the index for a given name.
func (s *loginRequestLister) Get(name string) (*v1alpha1.LoginRequest, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("loginrequest"), name)
	}
	return obj.(*v1alpha1.LoginRequest), nil
}
