// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
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
	if os.Getenv("PINNIPED_TEST_GOLAND_RUNNER") != "true" {
		// When running integration tests from inside GoLand, do not modify them.
		// If the test gets nested under TestIntegrationSerial or the other groups,
		// then you cannot run/debug a focused integration test in GoLand because the
		// name of the test changes in a way that GoLand does not expect due to
		// the nesting.
		splitIntegrationTestsIntoBuckets(m)
	}
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

	var serialTests, parallelTests, disruptiveTests, finalTests []testing.InternalTest

	for _, test := range tests {
		// top level integration tests the end with the string _Parallel
		// are indicating that they are safe to run in parallel with
		// other serial tests (which Go does not let you easily express).
		// top level tests that want the standard Go behavior of only running
		// parallel tests with other parallel tests should use the regular
		// t.Parallel() approach. this has no effect on any subtest.
		switch {
		case strings.HasSuffix(test.Name, "_Parallel"):
			parallelTests = append(parallelTests, test)

		// top level integration tests the end with the string _Disruptive
		// are indicating that they are never safe to run with any other
		// test because they break the underlying cluster in some way.
		case strings.HasSuffix(test.Name, "_Disruptive"):
			disruptiveTests = append(disruptiveTests, test)

		default:
			serialTests = append(serialTests, test)
		}
	}

	serialTest := testing.InternalTest{
		Name: "TestIntegrationSerial",
		F: func(t *testing.T) {
			testlib.SkipUnlessIntegration(t) // make sure these tests do not run during unit tests
			t.Parallel()                     // outer test always runs in parallel for this bucket

			for _, test := range serialTests {
				t.Run(test.Name, func(t *testing.T) {
					test.F(t) // inner serial tests do not run in parallel
				})
			}
		},
	}

	parallelTest := testing.InternalTest{
		Name: "TestIntegrationParallel",
		F: func(t *testing.T) {
			testlib.SkipUnlessIntegration(t) // make sure these tests do not run during unit tests
			t.Parallel()                     // outer test always runs in parallel for this bucket

			for _, test := range parallelTests {
				t.Run(test.Name, func(t *testing.T) {
					t.Parallel() // inner parallel tests do run in parallel

					test.F(t)
				})
			}
		},
	}

	disruptiveTest := testing.InternalTest{
		Name: "TestIntegrationDisruptive",
		F: func(t *testing.T) {
			testlib.SkipUnlessIntegration(t) // make sure these tests do not run during unit tests
			// outer test never runs in parallel for this bucket

			for _, test := range disruptiveTests {
				t.Run(test.Name, func(t *testing.T) {
					test.F(t) // inner disruptive tests do not run in parallel
				})
			}
		},
	}

	if len(parallelTests) > 0 {
		finalTests = append(finalTests, parallelTest)
	}

	if len(serialTests) > 0 {
		finalTests = append(finalTests, serialTest)
	}

	if len(disruptiveTests) > 0 {
		finalTests = append(finalTests, disruptiveTest)
	}

	*testsPointer = finalTests
}
