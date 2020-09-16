// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	internalinterfaces "github.com/suzerain-io/pinniped/generated/1.18/client/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// CredentialRequests returns a CredentialRequestInformer.
	CredentialRequests() CredentialRequestInformer
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

// CredentialRequests returns a CredentialRequestInformer.
func (v *version) CredentialRequests() CredentialRequestInformer {
	return &credentialRequestInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}
