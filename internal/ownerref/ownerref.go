// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ownerref

import (
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/kubeclient"
)

func New(ref metav1.OwnerReference) kubeclient.Middleware {
	return ownerRefMiddleware(ref)
}

var _ kubeclient.Middleware = ownerRefMiddleware(metav1.OwnerReference{})

type ownerRefMiddleware metav1.OwnerReference

func (o ownerRefMiddleware) Handles(httpMethod string) bool {
	return httpMethod == http.MethodPost // only handle create requests
}

// TODO this func assumes all objects are namespace scoped and are in the same namespace.
//  i.e. it assumes all objects are safe to set an owner ref on
//  i.e. the owner could be namespace scoped and thus cannot own a cluster scoped object
//  this could be fixed by using a rest mapper to confirm the REST scoping
//  or we could always use an owner ref to a cluster scoped object
func (o ownerRefMiddleware) Mutate(obj metav1.Object) (mutated bool) {
	// we only want to set the owner ref on create and when one is not already present
	if len(obj.GetOwnerReferences()) != 0 {
		return false
	}

	obj.SetOwnerReferences([]metav1.OwnerReference{metav1.OwnerReference(o)})
	return true
}
