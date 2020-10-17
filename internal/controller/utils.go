// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/controllerlib"
)

func NameAndNamespaceExactMatchFilterFactory(name, namespace string) controllerlib.Filter {
	return SimpleFilter(func(obj metav1.Object) bool {
		return obj.GetName() == name && obj.GetNamespace() == namespace
	})
}

// MatchAnythingFilter returns a controllerlib.Filter that allows all objects.
func MatchAnythingFilter() controllerlib.Filter {
	return SimpleFilter(func(object metav1.Object) bool { return true })
}

// SimpleFilter takes a single boolean match function on a metav1.Object and wraps it into a proper controllerlib.Filter.
func SimpleFilter(match func(metav1.Object) bool) controllerlib.Filter {
	return controllerlib.FilterFuncs{
		AddFunc:    match,
		UpdateFunc: func(oldObj, newObj metav1.Object) bool { return match(oldObj) || match(newObj) },
		DeleteFunc: match,
	}
}

// Same signature as controllerlib.WithInformer().
type WithInformerOptionFunc func(
	getter controllerlib.InformerGetter,
	filter controllerlib.Filter,
	opt controllerlib.InformerOption) controllerlib.Option

// Same signature as controllerlib.WithInitialEvent().
type WithInitialEventOptionFunc func(key controllerlib.Key) controllerlib.Option
