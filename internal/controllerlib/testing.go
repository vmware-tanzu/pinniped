// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controllerlib

import (
	"testing"
)

func TestSync(t *testing.T, controller Controller, ctx Context) error {
	t.Helper() // force testing import to discourage external use
	return controller.sync(ctx)
}

func TestWrap(t *testing.T, controller Controller, wrapper SyncWrapperFunc) {
	t.Helper() // force testing import to discourage external use
	controller.wrap(wrapper)
}

// Just enough of the internal implementation of controller.Run() to allow
// "running" the controller without any goroutines being involved. For use
// in synchronous unit tests that wish to invoke TestSync() directly.
func TestRunSynchronously(t *testing.T, controller Controller) {
	t.Helper() // force testing import to discourage external use
	controller.invokeAllRunOpts()
	controller.waitForCacheSyncWithTimeout()
}
