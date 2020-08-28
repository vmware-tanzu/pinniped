/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/suzerain-io/pinniped/internal/controllerlib"
)

func NameAndNamespaceExactMatchFilterFactory(name, namespace string) controllerlib.FilterFuncs {
	objMatchesFunc := func(obj metav1.Object) bool {
		return obj.GetName() == name && obj.GetNamespace() == namespace
	}
	return controllerlib.FilterFuncs{
		AddFunc: objMatchesFunc,
		UpdateFunc: func(oldObj, newObj metav1.Object) bool {
			return objMatchesFunc(oldObj) || objMatchesFunc(newObj)
		},
		DeleteFunc: objMatchesFunc,
	}
}

// Same signature as controllerlib.WithInformer().
type WithInformerOptionFunc func(
	getter controllerlib.InformerGetter,
	filter controllerlib.Filter,
	opt controllerlib.InformerOption) controllerlib.Option

// Same signature as controllerlib.WithInitialEvent().
type WithInitialEventOptionFunc func(key controllerlib.Key) controllerlib.Option
