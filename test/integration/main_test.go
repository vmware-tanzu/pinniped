/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

// force users to opt-in to running the integration tests.
// this prevents them from running if someone does `go test ./...`
// these tests could be destructive to the cluster under test.
const magicIntegrationTestsEnvVar = "NAME_TEST_INTEGRATION"

var shouldRunIntegrationTests = func() bool {
	b, _ := strconv.ParseBool(os.Getenv(magicIntegrationTestsEnvVar))
	return b
}()

func TestMain(m *testing.M) {
	if !shouldRunIntegrationTests {
		fmt.Printf("SKIP: %s=true env var must be explicitly set for integration tests to run\n", magicIntegrationTestsEnvVar)
		os.Exit(0)
	}

	os.Exit(m.Run())
}
