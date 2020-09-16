// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controllerlib

import (
	"context"

	"k8s.io/client-go/tools/events"
)

var _ Syncer = SyncFunc(nil)

type Syncer interface {
	Sync(ctx Context) error
}

type SyncFunc func(ctx Context) error

func (s SyncFunc) Sync(ctx Context) error {
	return s(ctx)
}

type Context struct {
	Context  context.Context
	Name     string
	Key      Key
	Queue    Queue
	Recorder events.EventRecorder
}

type Key struct {
	Namespace string
	Name      string

	// TODO determine if it makes sense to add a field like:
	//  Extra interface{}
	//  This would allow a custom ParentFunc to pass extra data through to the Syncer
	//  The boxed type would have to be comparable (i.e. usable as a map key)
}

type SyncWrapperFunc func(syncer Syncer) Syncer
