/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package controller

import "testing"

func TestSync(t *testing.T, controller Controller, ctx Context) error {
	t.Helper() // force testing import to discourage external use
	return controller.sync(ctx)
}

func TestWrap(t *testing.T, controller Controller, wrapper SyncWrapperFunc) {
	t.Helper() // force testing import to discourage external use
	controller.wrap(wrapper)
}
