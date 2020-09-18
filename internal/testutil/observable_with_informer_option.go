// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import "go.pinniped.dev/internal/controllerlib"

type ObservableWithInformerOption struct {
	informerToFilterMap map[controllerlib.InformerGetter]controllerlib.Filter
}

func NewObservableWithInformerOption() *ObservableWithInformerOption {
	return &ObservableWithInformerOption{
		informerToFilterMap: make(map[controllerlib.InformerGetter]controllerlib.Filter),
	}
}

func (i *ObservableWithInformerOption) WithInformer(
	getter controllerlib.InformerGetter,
	filter controllerlib.Filter,
	opt controllerlib.InformerOption,
) controllerlib.Option {
	i.informerToFilterMap[getter] = filter
	return controllerlib.WithInformer(getter, filter, opt)
}

func (i *ObservableWithInformerOption) GetFilterForInformer(getter controllerlib.InformerGetter) controllerlib.Filter {
	return i.informerToFilterMap[getter]
}
