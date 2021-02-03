// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plog

import (
	"strconv"

	"k8s.io/component-base/logs"

	"go.pinniped.dev/internal/constable"
)

// LogLevel is an enum that controls verbosity of logs.
// Valid values in order of increasing verbosity are leaving it unset, info, debug, trace and all.
type LogLevel string

const (
	// LevelWarning (i.e. leaving the log level unset) maps to klog log level 0.
	LevelWarning LogLevel = ""
	// LevelInfo maps to klog log level 2.
	LevelInfo LogLevel = "info"
	// LevelDebug maps to klog log level 4.
	LevelDebug LogLevel = "debug"
	// LevelTrace maps to klog log level 6.
	LevelTrace LogLevel = "trace"
	// LevelAll maps to klog log level 100 (conceptually it is log level 8).
	LevelAll LogLevel = "all"

	errInvalidLogLevel = constable.Error("invalid log level, valid choices are the empty string, info, debug, trace and all")
)

const (
	klogLevelWarning = iota * 2
	klogLevelInfo
	klogLevelDebug
	klogLevelTrace
	klogLevelAll
)

func ValidateAndSetLogLevelGlobally(level LogLevel) error {
	klogLevel := klogLevelForPlogLevel(level)
	if klogLevel < 0 {
		return errInvalidLogLevel
	}

	if _, err := logs.GlogSetter(strconv.Itoa(int(klogLevel))); err != nil {
		panic(err) // programmer error
	}

	return nil
}

// Enabled returns whether the provided plog level is enabled, i.e., whether print statements at the
// provided level will show up.
func Enabled(level LogLevel) bool {
	return getKlogLevel() >= klogLevelForPlogLevel(level)
}
