/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package testutil

import "github.com/suzerain-io/controller-go"

type ObservableWithInitialEventOption struct {
	key controller.Key
}

func NewObservableWithInitialEventOption() *ObservableWithInitialEventOption {
	return &ObservableWithInitialEventOption{}
}

func (i *ObservableWithInitialEventOption) WithInitialEvent(key controller.Key) controller.Option {
	i.key = key
	return controller.WithInitialEvent(key)
}

func (i *ObservableWithInitialEventOption) GetInitialEventKey() controller.Key {
	return i.key
}
