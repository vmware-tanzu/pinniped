// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package backoff

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

type Stepper interface {
	Step() time.Duration
}

func wrapConditionWithNoPanics(ctx context.Context, condition wait.ConditionWithContextFunc) (done bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			if err2, ok := r.(error); ok {
				err = err2
				return
			}
		}
	}()

	return condition(ctx)
}

func WithContext(ctx context.Context, backoff Stepper, condition wait.ConditionWithContextFunc) error {
	// Loop forever, unless we reach one of the return statements below.
	for {
		// Stop if the context is done.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Stop trying unless the condition function returns false.
		// Allow cancellation during the attempt if the condition function respects the ctx.
		if ok, err := wrapConditionWithNoPanics(ctx, condition); err != nil || ok {
			return err
		}

		// Calculate how long to wait before the next step.
		waitBeforeRetry := backoff.Step()

		// Wait before running again, allowing cancellation during the wait.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitBeforeRetry):
		}
	}
}
