// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ownerref

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/kubeclient"
)

func New(refObj kubeclient.Object) kubeclient.Middleware {
	ref := metav1.OwnerReference{
		Name: refObj.GetName(),
		UID:  refObj.GetUID(),
	}
	ref.APIVersion, ref.Kind = refObj.GetObjectKind().GroupVersionKind().ToAPIVersionAndKind()
	refNamespace := refObj.GetNamespace()

	// if refNamespace is empty, we assume the owner ref is to a cluster scoped object which can own any object
	refIsNamespaced := len(refNamespace) != 0

	// special handling of namespaces to treat them as namespace scoped to themselves
	if isNamespace(refObj) {
		refNamespace = refObj.GetName()
		refIsNamespaced = true
	}

	return kubeclient.MiddlewareFunc(func(_ context.Context, rt kubeclient.RoundTrip) {
		// we should not mess with owner refs on things we did not create
		if rt.Verb() != kubeclient.VerbCreate {
			return
		}

		// we probably do not want to set an owner ref on a subresource
		if len(rt.Subresource()) != 0 {
			return
		}

		// when ref is not cluster scoped, we ignore cluster scoped resources
		if refIsNamespaced && !rt.NamespaceScoped() {
			return
		}

		// when ref is not cluster scoped, we require refNamespace to match
		// the request namespace since cross namespace ownership is disallowed
		if refIsNamespaced && refNamespace != rt.Namespace() {
			return
		}

		rt.MutateRequest(func(obj kubeclient.Object) {
			// we only want to set the owner ref on create and when one is not already present
			if len(obj.GetOwnerReferences()) != 0 {
				return
			}

			obj.SetOwnerReferences([]metav1.OwnerReference{ref})
		})
	})
}

//nolint: gochecknoglobals
var namespaceGVK = corev1.SchemeGroupVersion.WithKind("Namespace")

func isNamespace(obj kubeclient.Object) bool {
	_, ok := obj.(*corev1.Namespace)
	return ok || obj.GetObjectKind().GroupVersionKind() == namespaceGVK
}
