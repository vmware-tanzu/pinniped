// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
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

import (
	"k8s.io/klog/v2"
)

const errorKey = "error"

type _ interface {
	Error(msg string, err error, keysAndValues ...interface{})
	Warning(msg string, keysAndValues ...interface{})
	WarningErr(msg string, err error, keysAndValues ...interface{})
	Info(msg string, keysAndValues ...interface{})
	InfoErr(msg string, err error, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
	DebugErr(msg string, err error, keysAndValues ...interface{})
	Trace(msg string, keysAndValues ...interface{})
	TraceErr(msg string, err error, keysAndValues ...interface{})
	All(msg string, keysAndValues ...interface{})
}

type PLogger struct {
	prefix string
	depth  int
}

func New(prefix string) PLogger {
	return PLogger{
		depth:  0,
		prefix: prefix,
	}
}

func (p *PLogger) Error(msg string, err error, keysAndValues ...interface{}) {
	klog.ErrorSDepth(p.depth+1, err, p.prefix+msg, keysAndValues...)
}

func (p *PLogger) warningDepth(msg string, depth int, keysAndValues ...interface{}) {
	// klog's structured logging has no concept of a warning (i.e. no WarningS function)
	// Thus we use info at log level zero as a proxy
	// klog's info logs have an I prefix and its warning logs have a W prefix
	// Since we lose the W prefix by using InfoS, just add a key to make these easier to find
	keysAndValues = append([]interface{}{"warning", "true"}, keysAndValues...)
	if klog.V(klogLevelWarning).Enabled() {
		klog.InfoSDepth(depth+1, p.prefix+msg, keysAndValues...)
	}
}

func (p *PLogger) Warning(msg string, keysAndValues ...interface{}) {
	p.warningDepth(msg, p.depth+1, keysAndValues...)
}

// Use WarningErr to issue a Warning message with an error object as part of the message.
func (p *PLogger) WarningErr(msg string, err error, keysAndValues ...interface{}) {
	p.warningDepth(msg, p.depth+1, append([]interface{}{errorKey, err}, keysAndValues...)...)
}

func (p *PLogger) infoDepth(msg string, depth int, keysAndValues ...interface{}) {
	if klog.V(klogLevelInfo).Enabled() {
		klog.InfoSDepth(depth+1, p.prefix+msg, keysAndValues...)
	}
}

func (p *PLogger) Info(msg string, keysAndValues ...interface{}) {
	p.infoDepth(msg, p.depth+1, keysAndValues...)
}

// Use InfoErr to log an expected error, e.g. validation failure of an http parameter.
func (p *PLogger) InfoErr(msg string, err error, keysAndValues ...interface{}) {
	p.infoDepth(msg, p.depth+1, append([]interface{}{errorKey, err}, keysAndValues...)...)
}

func (p *PLogger) debugDepth(msg string, depth int, keysAndValues ...interface{}) {
	if klog.V(klogLevelDebug).Enabled() {
		klog.InfoSDepth(depth+1, p.prefix+msg, keysAndValues...)
	}
}

func (p *PLogger) Debug(msg string, keysAndValues ...interface{}) {
	p.debugDepth(msg, p.depth+1, keysAndValues...)
}

// Use DebugErr to issue a Debug message with an error object as part of the message.
func (p *PLogger) DebugErr(msg string, err error, keysAndValues ...interface{}) {
	p.debugDepth(msg, p.depth+1, append([]interface{}{errorKey, err}, keysAndValues...)...)
}

func (p *PLogger) traceDepth(msg string, depth int, keysAndValues ...interface{}) {
	if klog.V(klogLevelTrace).Enabled() {
		klog.InfoSDepth(depth+1, p.prefix+msg, keysAndValues...)
	}
}

func (p *PLogger) Trace(msg string, keysAndValues ...interface{}) {
	p.traceDepth(msg, p.depth+1, keysAndValues...)
}

// Use TraceErr to issue a Trace message with an error object as part of the message.
func (p *PLogger) TraceErr(msg string, err error, keysAndValues ...interface{}) {
	p.traceDepth(msg, p.depth+1, append([]interface{}{errorKey, err}, keysAndValues...)...)
}

func (p *PLogger) All(msg string, keysAndValues ...interface{}) {
	if klog.V(klogLevelAll).Enabled() {
		klog.InfoSDepth(p.depth+1, p.prefix+msg, keysAndValues...)
	}
}

var pLogger = PLogger{ //nolint:gochecknoglobals
	depth: 1,
}

// Use Error to log an unexpected system error.
func Error(msg string, err error, keysAndValues ...interface{}) {
	pLogger.Error(msg, err, keysAndValues...)
}

func Warning(msg string, keysAndValues ...interface{}) {
	pLogger.Warning(msg, keysAndValues...)
}

// Use WarningErr to issue a Warning message with an error object as part of the message.
func WarningErr(msg string, err error, keysAndValues ...interface{}) {
	pLogger.WarningErr(msg, err, keysAndValues...)
}

func Info(msg string, keysAndValues ...interface{}) {
	pLogger.Info(msg, keysAndValues...)
}

// Use InfoErr to log an expected error, e.g. validation failure of an http parameter.
func InfoErr(msg string, err error, keysAndValues ...interface{}) {
	pLogger.InfoErr(msg, err, keysAndValues...)
}

func Debug(msg string, keysAndValues ...interface{}) {
	pLogger.Debug(msg, keysAndValues...)
}

// Use DebugErr to issue a Debug message with an error object as part of the message.
func DebugErr(msg string, err error, keysAndValues ...interface{}) {
	pLogger.DebugErr(msg, err, keysAndValues...)
}

func Trace(msg string, keysAndValues ...interface{}) {
	pLogger.Trace(msg, keysAndValues...)
}

// Use TraceErr to issue a Trace message with an error object as part of the message.
func TraceErr(msg string, err error, keysAndValues ...interface{}) {
	pLogger.TraceErr(msg, err, keysAndValues...)
}

func All(msg string, keysAndValues ...interface{}) {
	pLogger.All(msg, keysAndValues...)
}
