// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controllerinit

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"time"
)

// Runner is something that can be run such as a series of controllers.  Blocks until context is canceled.
type Runner func(context.Context)

// RunnerWrapper takes a Runner and wraps its execution with other logic.  Blocks until context is canceled.
// RunnerWrapper is responsible for the lifetime of the passed in Runner.
type RunnerWrapper func(context.Context, Runner)

// RunnerBuilder is a function that can be used to construct a Runner.
// It is expected to be called in the main go routine since the construction can fail.
type RunnerBuilder func(context.Context) (Runner, error)

// Informer is the subset of SharedInformerFactory needed for starting an informer cache and waiting for it to sync.
type Informer interface {
	Start(stopCh <-chan struct{})
	WaitForCacheSync(stopCh <-chan struct{}) map[reflect.Type]bool
}

// Prepare returns RunnerBuilder that, when called:
//   1. Starts all provided informers and waits for them sync (and fails if they hang)
//   2. Returns a Runner that combines the Runner and RunnerWrapper passed into Prepare
func Prepare(controllers Runner, controllersWrapper RunnerWrapper, informers ...Informer) RunnerBuilder {
	return func(ctx context.Context) (Runner, error) {
		for _, informer := range informers {
			informer := informer

			informer.Start(ctx.Done())

			// prevent us from blocking forever due to a broken informer
			waitCtx, waitCancel := context.WithTimeout(ctx, time.Minute)
			defer waitCancel()

			// wait until the caches are synced before returning
			status := informer.WaitForCacheSync(waitCtx.Done())

			if unsynced := unsyncedInformers(status); len(unsynced) > 0 {
				return nil, fmt.Errorf("failed to sync informers of %s: %v", anyToFullname(informer), unsynced)
			}
		}

		return func(controllerCtx context.Context) {
			controllersWrapper(controllerCtx, controllers)
		}, nil
	}
}

func unsyncedInformers(status map[reflect.Type]bool) []string {
	if len(status) == 0 {
		return []string{"all:empty"}
	}

	var names []string

	for typ, synced := range status {
		if !synced {
			names = append(names, typeToFullname(typ))
		}
	}

	sort.Strings(names)

	return names
}

func anyToFullname(any interface{}) string {
	typ := reflect.TypeOf(any)
	return typeToFullname(typ)
}

func typeToFullname(typ reflect.Type) string {
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	return typ.PkgPath() + "." + typ.Name()
}
