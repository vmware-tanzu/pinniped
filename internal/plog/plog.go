// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package plog implements a thin layer over klog to help enforce pinniped's logging convention.
// Logs are always structured as a constant message with key and value pairs of related metadata.
//
// The logging levels in order of increasing verbosity are:
// error, warning, info, debug, trace and all.
//
// error and warning logs are always emitted (there is no way for the end user to disable them),
// and thus should be used sparingly.  Ideally, logs at these levels should be actionable.
//
// info should be reserved for "nice to know" information.  It should be possible to run a production
// pinniped server at the info log level with no performance degradation due to high log volume.
// debug should be used for information targeted at developers and to aid in support cases.  Care must
// be taken at this level to not leak any secrets into the log stream.  That is, even though debug may
// cause performance issues in production, it must not cause security issues in production.
//
// trace should be used to log information related to timing (i.e. the time it took a controller to sync).
// Just like debug, trace should not leak secrets into the log stream.  trace will likely leak information
// about the current state of the process, but that, along with performance degradation, is expected.
//
// all is reserved for the most verbose and security sensitive information.  At this level, full request
// metadata such as headers and parameters along with the body may be logged.  This level is completely
// unfit for production use both from a performance and security standpoint.  Using it is generally an
// act of desperation to determine why the system is broken.
package plog

import "k8s.io/klog/v2"

const errorKey = "error"

// Use Error to log an unexpected system error.
func Error(msg string, err error, keysAndValues ...interface{}) {
	klog.ErrorS(err, msg, keysAndValues...)
}

func Warning(msg string, keysAndValues ...interface{}) {
	// klog's structured logging has no concept of a warning (i.e. no WarningS function)
	// Thus we use info at log level zero as a proxy
	// klog's info logs have an I prefix and its warning logs have a W prefix
	// Since we lose the W prefix by using InfoS, just add a key to make these easier to find
	keysAndValues = append([]interface{}{"warning", "true"}, keysAndValues...)
	klog.V(klogLevelWarning).InfoS(msg, keysAndValues...)
}

// Use WarningErr to issue a Warning message with an error object as part of the message.
func WarningErr(msg string, err error, keysAndValues ...interface{}) {
	Warning(msg, append([]interface{}{errorKey, err}, keysAndValues...)...)
}

func Info(msg string, keysAndValues ...interface{}) {
	klog.V(klogLevelInfo).InfoS(msg, keysAndValues...)
}

// Use InfoErr to log an expected error, e.g. validation failure of an http parameter.
func InfoErr(msg string, err error, keysAndValues ...interface{}) {
	Info(msg, append([]interface{}{errorKey, err}, keysAndValues...)...)
}

func Debug(msg string, keysAndValues ...interface{}) {
	klog.V(klogLevelDebug).InfoS(msg, keysAndValues...)
}

// Use DebugErr to issue a Debug message with an error object as part of the message.
func DebugErr(msg string, err error, keysAndValues ...interface{}) {
	Debug(msg, append([]interface{}{errorKey, err}, keysAndValues...)...)
}

func Trace(msg string, keysAndValues ...interface{}) {
	klog.V(klogLevelTrace).InfoS(msg, keysAndValues...)
}

// Use TraceErr to issue a Trace message with an error object as part of the message.
func TraceErr(msg string, err error, keysAndValues ...interface{}) {
	Trace(msg, append([]interface{}{errorKey, err}, keysAndValues...)...)
}

func All(msg string, keysAndValues ...interface{}) {
	klog.V(klogLevelAll).InfoS(msg, keysAndValues...)
}
