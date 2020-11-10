// Copyright 2020 the Pinniped contributors. All Rights Reserved.
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
	var klogLogLevel int

	switch level {
	case LevelWarning:
		klogLogLevel = klogLevelWarning // unset means minimal logs (Error and Warning)
	case LevelInfo:
		klogLogLevel = klogLevelInfo
	case LevelDebug:
		klogLogLevel = klogLevelDebug
	case LevelTrace:
		klogLogLevel = klogLevelTrace
	case LevelAll:
		klogLogLevel = klogLevelAll + 100 // make all really mean all
	default:
		return errInvalidLogLevel
	}

	if _, err := logs.GlogSetter(strconv.Itoa(klogLogLevel)); err != nil {
		panic(err) // programmer error
	}

	return nil
}
