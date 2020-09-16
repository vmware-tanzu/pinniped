// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controllerlib

import "k8s.io/client-go/tools/cache"

type InformerGetter interface {
	Informer() cache.SharedIndexInformer
}

type InformerOption struct {
	SkipSync   bool
	SkipEvents bool

	// TODO maybe add a field like:
	//  ResyncPeriod time.Duration
	//  to support using AddEventHandlerWithResyncPeriod
	//  this field would be mutually exclusive with SkipEvents
	//  I suspect we do not need this level of flexibility and resyncs can mask bugs in controller logic
	//  A related change could be an Option such as WithResyncSchedule to allow for cron style control loops
	//  It is unclear to me if we would ever need that since we assume that all events come from a Kube watch
}
