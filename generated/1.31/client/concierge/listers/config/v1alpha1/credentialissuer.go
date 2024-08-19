// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "go.pinniped.dev/generated/1.31/apis/concierge/config/v1alpha1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// CredentialIssuerLister helps list CredentialIssuers.
// All objects returned here must be treated as read-only.
type CredentialIssuerLister interface {
	// List lists all CredentialIssuers in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.CredentialIssuer, err error)
	// Get retrieves the CredentialIssuer from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.CredentialIssuer, error)
	CredentialIssuerListerExpansion
}

// credentialIssuerLister implements the CredentialIssuerLister interface.
type credentialIssuerLister struct {
	listers.ResourceIndexer[*v1alpha1.CredentialIssuer]
}

// NewCredentialIssuerLister returns a new CredentialIssuerLister.
func NewCredentialIssuerLister(indexer cache.Indexer) CredentialIssuerLister {
	return &credentialIssuerLister{listers.New[*v1alpha1.CredentialIssuer](indexer, v1alpha1.Resource("credentialissuer"))}
}
