/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package controllerlib

import (
	"testing"

	"k8s.io/client-go/tools/cache"
)

type getter bool

func (g *getter) Informer() cache.SharedIndexInformer {
	*g = true
	return nil
}

func TestInformerCalled(t *testing.T) {
	g := getter(false)
	_ = New(Config{}, WithInformer(&g, FilterByNames(nil), InformerOption{}))
	if !g {
		t.Error("expected InformerGetter.Informer() to be called")
	}
}
