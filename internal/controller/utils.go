/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/suzerain-io/controller-go"
)

func NameAndNamespaceExactMatchFilterFactory(name, namespace string) controller.FilterFuncs {
	objMatchesFunc := func(obj metav1.Object) bool {
		return obj.GetName() == name && obj.GetNamespace() == namespace
	}
	return controller.FilterFuncs{
		AddFunc: objMatchesFunc,
		UpdateFunc: func(oldObj, newObj metav1.Object) bool {
			return objMatchesFunc(oldObj) || objMatchesFunc(newObj)
		},
		DeleteFunc: objMatchesFunc,
	}
}

// Same signature as controller.WithInformer().
type WithInformerOptionFunc func(
	getter controller.InformerGetter,
	filter controller.Filter,
	opt controller.InformerOption) controller.Option
