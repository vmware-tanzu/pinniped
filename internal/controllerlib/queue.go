// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controllerlib

import (
	"time"

	"k8s.io/client-go/util/workqueue"
)

type Queue interface {
	// Add immediately adds a key to the queue and marks it as needing processing.
	Add(key Key)

	// AddRateLimited adds a key to the queue after the rate limiter says it is ok.
	AddRateLimited(key Key)

	// AddAfter adds a key to the queue after the indicated duration has passed.
	AddAfter(key Key, duration time.Duration)
}

var _ Queue = &queueWrapper{}

type queueWrapper struct {
	queue workqueue.TypedRateLimitingInterface[any]
}

func (q *queueWrapper) Add(key Key) {
	q.queue.Add(key)
}

func (q *queueWrapper) AddRateLimited(key Key) {
	q.queue.AddRateLimited(key)
}

func (q *queueWrapper) AddAfter(key Key, duration time.Duration) {
	q.queue.AddAfter(key, duration)
}
