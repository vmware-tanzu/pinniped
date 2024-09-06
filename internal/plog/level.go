// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plog

import (
	"go.uber.org/zap/zapcore"
	"k8s.io/klog/v2"
)

// LogLevel is an enum that controls verbosity of logs.
// Valid values in order of increasing verbosity are leaving it unset, info, debug, trace and all.
type LogLevel string

func (l LogLevel) Enabled(_ zapcore.Level) bool {
	return Enabled(l) // this basically says "log if the global plog level is l or greater"
}

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
)

var _ zapcore.LevelEnabler = LevelWarning

const (
	klogLevelWarning = iota * 2
	KlogLevelInfo
	KlogLevelDebug
	KlogLevelTrace
	klogLevelAll
)

// Enabled returns whether the provided plog level is enabled, i.e., whether print statements at the
// provided level will show up.
func Enabled(level LogLevel) bool {
	l := klogLevelForPlogLevel(level)
	// check that both our global level and the klog global level agree that the plog level is enabled
	// klog levels are inverted when zap handles them
	//nolint:gosec // the range for klogLevel is [0,108]
	return globalLevel.Enabled(zapcore.Level(-l)) && klog.V(l).Enabled()
}

func klogLevelForPlogLevel(plogLevel LogLevel) klog.Level {
	switch plogLevel {
	case LevelWarning:
		return klogLevelWarning // unset means minimal logs (Error and Warning)
	case LevelInfo:
		return KlogLevelInfo
	case LevelDebug:
		return KlogLevelDebug
	case LevelTrace:
		return KlogLevelTrace
	case LevelAll:
		return klogLevelAll + 100 // make all really mean all
	default:
		return -1
	}
}
