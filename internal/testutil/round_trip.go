// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"k8s.io/apimachinery/pkg/runtime/schema"

	"go.pinniped.dev/internal/kubeclient"
)

// RoundTrip is an implementation of kubeclient.RoundTrip that is easy to use in tests.
type RoundTrip struct {
	verb            kubeclient.Verb
	namespace       string
	namespaceScoped bool
	resource        schema.GroupVersionResource
	subresource     string

	MutateRequests, MutateResponses []func(kubeclient.Object)
}

func (rt *RoundTrip) WithVerb(verb kubeclient.Verb) *RoundTrip {
	rt.verb = verb
	return rt
}

func (rt *RoundTrip) Verb() kubeclient.Verb {
	return rt.verb
}

func (rt *RoundTrip) WithNamespace(namespace string) *RoundTrip {
	rt.namespace = namespace
	rt.namespaceScoped = len(namespace) != 0
	return rt
}

func (rt *RoundTrip) Namespace() string {
	return rt.namespace
}

func (rt *RoundTrip) NamespaceScoped() bool {
	return rt.namespaceScoped
}

func (rt *RoundTrip) WithResource(resource schema.GroupVersionResource) *RoundTrip {
	rt.resource = resource
	return rt
}

func (rt *RoundTrip) Resource() schema.GroupVersionResource {
	return rt.resource
}

func (rt *RoundTrip) WithSubresource(subresource string) *RoundTrip {
	rt.subresource = subresource
	return rt
}

func (rt *RoundTrip) Subresource() string {
	return rt.subresource
}

func (rt *RoundTrip) MutateRequest(fn func(kubeclient.Object)) {
	rt.MutateRequests = append(rt.MutateRequests, fn)
}

func (rt *RoundTrip) MutateResponse(fn func(kubeclient.Object)) {
	rt.MutateResponses = append(rt.MutateResponses, fn)
}
