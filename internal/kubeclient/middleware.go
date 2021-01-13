// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type Middleware interface {
	Handle(ctx context.Context, rt RoundTrip)
}

var _ Middleware = MiddlewareFunc(nil)

type MiddlewareFunc func(ctx context.Context, rt RoundTrip)

func (f MiddlewareFunc) Handle(ctx context.Context, rt RoundTrip) {
	f(ctx, rt)
}

var _ Middleware = Middlewares{}

type Middlewares []Middleware

func (m Middlewares) Handle(ctx context.Context, rt RoundTrip) {
	for _, middleware := range m {
		middleware := middleware
		middleware.Handle(ctx, rt)
	}
}

type RoundTrip interface {
	Verb() Verb
	Namespace() string // this is the only valid way to check namespace, Object.GetNamespace() will almost always be empty
	NamespaceScoped() bool
	Resource() schema.GroupVersionResource
	Subresource() string
	MutateRequest(f func(obj Object))
	MutateResponse(f func(obj Object))
}

type Object interface {
	runtime.Object // generic access to TypeMeta
	metav1.Object  // generic access to ObjectMeta
}

var _ RoundTrip = &request{}

type request struct {
	verb                Verb
	namespace           string
	resource            schema.GroupVersionResource
	reqFuncs, respFuncs []func(obj Object)
	subresource         string
}

func (r *request) Verb() Verb {
	return r.verb
}

func (r *request) Namespace() string {
	return r.namespace
}

//nolint: gochecknoglobals
var namespaceGVR = corev1.SchemeGroupVersion.WithResource("namespaces")

func (r *request) NamespaceScoped() bool {
	if r.Resource() == namespaceGVR {
		return false // always consider namespaces to be cluster scoped
	}

	return len(r.Namespace()) != 0
}

func (r *request) Resource() schema.GroupVersionResource {
	return r.resource
}

func (r *request) Subresource() string {
	return r.subresource
}

func (r *request) MutateRequest(f func(obj Object)) {
	r.reqFuncs = append(r.reqFuncs, f)
}

func (r *request) MutateResponse(f func(obj Object)) {
	r.respFuncs = append(r.respFuncs, f)
}

type mutationResult struct {
	origGVK, newGVK     schema.GroupVersionKind
	gvkChanged, mutated bool
}

func (r *request) mutateRequest(obj Object) (*mutationResult, error) {
	origGVK := obj.GetObjectKind().GroupVersionKind()
	if origGVK.Empty() {
		return nil, fmt.Errorf("invalid empty orig GVK for %T: %#v", obj, r)
	}

	origObj, ok := obj.DeepCopyObject().(Object)
	if !ok {
		return nil, fmt.Errorf("invalid deep copy semantics for %T: %#v", obj, r)
	}

	for _, reqFunc := range r.reqFuncs {
		reqFunc := reqFunc
		reqFunc(obj)
	}

	newGVK := obj.GetObjectKind().GroupVersionKind()
	if newGVK.Empty() {
		return nil, fmt.Errorf("invalid empty new GVK for %T: %#v", obj, r)
	}

	return &mutationResult{
		origGVK:    origGVK,
		newGVK:     newGVK,
		gvkChanged: origGVK != newGVK,
		mutated:    len(r.respFuncs) != 0 || !apiequality.Semantic.DeepEqual(origObj, obj),
	}, nil
}

func (r *request) mutateResponse(obj Object) (bool, error) {
	origObj, ok := obj.DeepCopyObject().(Object)
	if !ok {
		return false, fmt.Errorf("invalid deep copy semantics for %T: %#v", obj, r)
	}

	for _, respFunc := range r.respFuncs {
		respFunc := respFunc
		respFunc(obj)
	}

	mutated := !apiequality.Semantic.DeepEqual(origObj, obj)
	return mutated, nil
}
