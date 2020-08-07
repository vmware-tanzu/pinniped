/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package library

import "testing"

// SkipUnlessIntegration skips the current test if `-short` has been passed to `go test`.
func SkipUnlessIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test because of '-short' flag")
	}
}
