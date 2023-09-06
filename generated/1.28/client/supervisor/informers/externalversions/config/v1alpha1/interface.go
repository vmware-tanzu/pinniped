// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	internalinterfaces "go.pinniped.dev/generated/1.28/client/supervisor/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// FederationDomains returns a FederationDomainInformer.
	FederationDomains() FederationDomainInformer
	// OIDCClients returns a OIDCClientInformer.
	OIDCClients() OIDCClientInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// FederationDomains returns a FederationDomainInformer.
func (v *version) FederationDomains() FederationDomainInformer {
	return &federationDomainInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// OIDCClients returns a OIDCClientInformer.
func (v *version) OIDCClients() OIDCClientInformer {
	return &oIDCClientInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}