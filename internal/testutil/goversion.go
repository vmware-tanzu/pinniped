// Copyright 2026 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"go/version"
	"runtime"
)

// GoVersionDependentString describes a string whose value depends on which version of Go is
// running the test. GoVersion should be a Go language version, e.g. "go1.27". BeforeVersion is
// the value to use on older versions of Go, and SinceVersion is the value to use on GoVersion
// and on newer versions of Go.
type GoVersionDependentString struct {
	GoVersion     string
	BeforeVersion string
	SinceVersion  string
}

// StringBasedOnGoVersion returns the value of the given GoVersionDependentString for the version
// of Go which is running the test.
func StringBasedOnGoVersion(s GoVersionDependentString) string {
	lang := version.Lang(runtime.Version())
	if lang == "" {
		// Not a released version of Go, e.g. a development build, so assume that it is the newest behavior.
		return s.SinceVersion
	}
	if version.Compare(lang, version.Lang(s.GoVersion)) >= 0 {
		return s.SinceVersion
	}
	return s.BeforeVersion
}
