// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"go.pinniped.dev/test/testlib"
)

func TestMain(m *testing.M) {
	splitIntegrationTestsIntoBuckets(m)
	os.Exit(m.Run())
}

func splitIntegrationTestsIntoBuckets(m *testing.M) {
	// this is some dark magic to set a private field
	testsField := reflect.ValueOf(m).Elem().FieldByName("tests")
	testsPointer := (*[]testing.InternalTest)(unsafe.Pointer(testsField.UnsafeAddr()))

	tests := *testsPointer

	if len(tests) == 0 {
		return
	}

	var serialTests, parallelTests, finalTests []testing.InternalTest

	for _, test := range tests {
		test := test

		// top level integration tests the end with the string _Parallel
		// are indicating that they are safe to run in parallel with
		// other serial tests (which Go does not let you easily express).
		// top level tests that want the standard Go behavior of only running
		// parallel tests with other parallel tests should use the regular
		// t.Parallel() approach. this has no effect on any subtest.
		if strings.HasSuffix(test.Name, "_Parallel") {
			parallelTests = append(parallelTests, test)
		} else {
			serialTests = append(serialTests, test)
		}
	}

	serialTest := testing.InternalTest{
		Name: "TestIntegrationSerial",
		F: func(t *testing.T) {
			_ = testlib.IntegrationEnv(t) // make sure these tests do not run during unit tests
			t.Parallel()                  // outer test runs in parallel always

			for _, test := range serialTests {
				test := test
				t.Run(test.Name, func(t *testing.T) {
					test.F(t) // inner serial tests do not run in parallel
				})
			}
		},
	}

	parallelTest := testing.InternalTest{
		Name: "TestIntegrationParallel",
		F: func(t *testing.T) {
			_ = testlib.IntegrationEnv(t) // make sure these tests do not run during unit tests
			t.Parallel()                  // outer test runs in parallel always

			for _, test := range parallelTests {
				test := test
				t.Run(test.Name, func(t *testing.T) {
					t.Parallel() // inner parallel tests do run in parallel

					test.F(t)
				})
			}
		},
	}

	if len(serialTests) > 0 {
		finalTests = append(finalTests, serialTest)
	}

	if len(parallelTests) > 0 {
		finalTests = append(finalTests, parallelTest)
	}

	*testsPointer = finalTests
}
