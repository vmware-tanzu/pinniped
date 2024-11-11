// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package plog implements a thin layer over logr to help enforce pinniped's logging convention.
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
//
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
	"context"
	"os"
	"slices"

	"github.com/go-logr/logr"
	"k8s.io/apiserver/pkg/audit"

	"go.pinniped.dev/internal/auditevent"
)

const errorKey = "error" // this matches zapr's default for .Error calls (which is asserted via tests)

type SessionIDGetter interface {
	GetID() string
}

// NoSessionPersisted means do not associate this audit event with a session ID.
// The session has not yet "started" and may or may not ever be persisted to permanent storage.
func NoSessionPersisted() SessionIDGetter {
	return nil
}

// NoHTTPRequestAvailable means there is no request context for this audit event.
// Use this when an audit event is emitted from a controller or some other place that does not have a request context.
func NoHTTPRequestAvailable() context.Context {
	return nil
}

// AuditLogger is only the audit logging part of Logger. There is no global function for Audit because
// that would make unit testing of audit logs harder.
type AuditLogger interface {
	// Audit writes an audit event to the log.
	// reqCtx and session may be null.
	// When possible, pass the http request's context as reqCtx, so we may read the audit ID from the context.
	// When possible, pass the fosite.Requester or fosite.Request as the session, so we can log the session ID.
	Audit(msg auditevent.Message, reqCtx context.Context, session SessionIDGetter, keysAndValues ...any)
}

// Logger implements the plog logging convention described above.  The global functions in this package
// such as Info should be used when one does not intend to write tests assertions for specific log messages.
// If test assertions are desired, Logger should be passed in as an input.  New should be used as the
// production implementation and TestLogger should be used to write test assertions.
type Logger interface {
	AuditLogger

	Error(msg string, err error, keysAndValues ...any)
	Warning(msg string, keysAndValues ...any)
	WarningErr(msg string, err error, keysAndValues ...any)
	Info(msg string, keysAndValues ...any)
	InfoErr(msg string, err error, keysAndValues ...any)
	Debug(msg string, keysAndValues ...any)
	DebugErr(msg string, err error, keysAndValues ...any)
	Trace(msg string, keysAndValues ...any)
	TraceErr(msg string, err error, keysAndValues ...any)
	All(msg string, keysAndValues ...any)
	Always(msg string, keysAndValues ...any)
	WithValues(keysAndValues ...any) Logger
	WithName(name string) Logger

	// does not include Fatal on purpose because that is not a method you should be using

	// for internal and test use only
	withDepth(d int) Logger
	withLogrMod(mod func(logr.Logger) logr.Logger) Logger
}

// MinLogger is the overlap between Logger and logr.Logger.
type MinLogger interface {
	Info(msg string, keysAndValues ...any)
}

var _ Logger = pLogger{}
var _, _, _ MinLogger = pLogger{}, logr.Logger{}, Logger(nil)

type pLogger struct {
	mods  []func(logr.Logger) logr.Logger
	depth int
}

func New() Logger {
	return pLogger{}
}

// Error logs show in the pod log output as `"level":"error","message":"some error msg"`
// where the message text comes from the err parameter.
// They also contain the standard `timestamp` and `caller` keys, along with any other keysAndValues.
// Only when the global log level is configured to "trace" or "all", then they will also include a `stacktrace` key.
// Error logs cannot be suppressed by the global log level configuration.
func (p pLogger) Error(msg string, err error, keysAndValues ...any) {
	p.logr().WithCallDepth(p.depth+1).Error(err, msg, keysAndValues...)
}

// Audit logs show in the pod log output as `"level":"info","message":"some msg","auditEvent":true`
// where the message text comes from the msg parameter.
// They also contain the standard `timestamp` and `caller` keys, along with any other keysAndValues.
// Only when the global log level is configured to "trace" or "all", then they will also include a `stacktrace` key.
// Audit logs cannot be suppressed by the global log level configuration, but rather can be disabled
// by their own separate configuration. This is because Audit logs should always be printed when they are desired
// by the admin, regardless of global log level, yet the admin should also have a way to entirely disable them
// when they want to avoid potential PII (e.g. usernames) in their pod logs.
func (p pLogger) Audit(msg auditevent.Message, reqCtx context.Context, session SessionIDGetter, keysAndValues ...any) {
	// Always add a key/value auditEvent=true.
	keysAndValues = slices.Concat([]any{"auditEvent", true}, keysAndValues)

	var auditID string
	if reqCtx != nil {
		auditID = audit.GetAuditIDTruncated(reqCtx)
	}
	if len(auditID) > 0 {
		keysAndValues = slices.Concat([]any{"auditID", auditID}, keysAndValues)
	}

	var sessionID string
	if session != nil {
		sessionID = session.GetID()
	}
	if len(sessionID) > 0 {
		keysAndValues = slices.Concat([]any{"sessionID", sessionID}, keysAndValues)
	}

	p.logr().V(klogLevelWarning).WithCallDepth(p.depth+1).Info(string(msg), keysAndValues...)
}

func (p pLogger) warningDepth(msg string, depth int, keysAndValues ...any) {
	if p.logr().V(klogLevelWarning).Enabled() {
		// klog's structured logging has no concept of a warning (i.e. no WarningS function)
		// Thus we use info at log level zero as a proxy
		// klog's info logs have an I prefix and its warning logs have a W prefix
		// Since we lose the W prefix by using InfoS, just add a key to make these easier to find
		keysAndValues = slices.Concat([]any{"warning", true}, keysAndValues)
		p.logr().V(klogLevelWarning).WithCallDepth(depth+1).Info(msg, keysAndValues...)
	}
}

// Warning logs show in the pod log output as `"level":"info","message":"some msg","warning":true`
// where the message text comes from the msg parameter.
// They also contain the standard `timestamp` and `caller` keys, along with any other keysAndValues.
// Only when the global log level is configured to "trace" or "all", then they will also include a `stacktrace` key.
// Warning logs cannot be suppressed by the global log level configuration.
func (p pLogger) Warning(msg string, keysAndValues ...any) {
	p.warningDepth(msg, p.depth+1, keysAndValues...)
}

// WarningErr logs show in the pod log output as `"level":"info","message":"some msg","warning":true,"error":"some error msg"`
// where the message text comes from the msg parameter and the error text comes from the err parameter.
// They also contain the standard `timestamp` and `caller` keys, along with any other keysAndValues.
// Only when the global log level is configured to "trace" or "all", then they will also include a `stacktrace` key.
// WarningErr logs cannot be suppressed by the global log level configuration.
func (p pLogger) WarningErr(msg string, err error, keysAndValues ...any) {
	p.warningDepth(msg, p.depth+1, slices.Concat([]any{errorKey, err}, keysAndValues)...)
}

func (p pLogger) infoDepth(msg string, depth int, keysAndValues ...any) {
	if p.logr().V(KlogLevelInfo).Enabled() {
		p.logr().V(KlogLevelInfo).WithCallDepth(depth+1).Info(msg, keysAndValues...)
	}
}

// Info logs show in the pod log output as `"level":"info","message":"some msg"`
// where the message text comes from the msg parameter.
// They also contain the standard `timestamp` and `caller` keys, along with any other keysAndValues.
// Only when the global log level is configured to "trace" or "all", then they will also include a `stacktrace` key.
// Info logs are suppressed by the global log level configuration, unless it is set to "info" or above.
func (p pLogger) Info(msg string, keysAndValues ...any) {
	p.infoDepth(msg, p.depth+1, keysAndValues...)
}

// InfoErr logs show in the pod log output as `"level":"info","message":"some msg","error":"some error msg"`
// where the message text comes from the msg parameter and the error text comes from the err parameter.
// They also contain the standard `timestamp` and `caller` keys, along with any other keysAndValues.
// Only when the global log level is configured to "trace" or "all", then they will also include a `stacktrace` key.
// InfoErr logs are suppressed by the global log level configuration, unless it is set to "info" or above.
func (p pLogger) InfoErr(msg string, err error, keysAndValues ...any) {
	p.infoDepth(msg, p.depth+1, slices.Concat([]any{errorKey, err}, keysAndValues)...)
}

func (p pLogger) debugDepth(msg string, depth int, keysAndValues ...any) {
	if p.logr().V(KlogLevelDebug).Enabled() {
		p.logr().V(KlogLevelDebug).WithCallDepth(depth+1).Info(msg, keysAndValues...)
	}
}

// Debug logs show in the pod log output as `"level":"debug","message":"some msg"`
// where the message text comes from the msg parameter.
// They also contain the standard `timestamp` and `caller` keys, along with any other keysAndValues.
// Only when the global log level is configured to "trace" or "all", then they will also include a `stacktrace` key.
// Debug logs are suppressed by the global log level configuration, unless it is set to "debug" or above.
func (p pLogger) Debug(msg string, keysAndValues ...any) {
	p.debugDepth(msg, p.depth+1, keysAndValues...)
}

// DebugErr logs show in the pod log output as `"level":"debug","message":"some msg","error":"some error msg"`
// where the message text comes from the msg parameter and the error text comes from the err parameter.
// They also contain the standard `timestamp` and `caller` keys, along with any other keysAndValues.
// Only when the global log level is configured to "trace" or "all", then they will also include a `stacktrace` key.
// DebugErr logs are suppressed by the global log level configuration, unless it is set to "debug" or above.
func (p pLogger) DebugErr(msg string, err error, keysAndValues ...any) {
	p.debugDepth(msg, p.depth+1, slices.Concat([]any{errorKey, err}, keysAndValues)...)
}

func (p pLogger) traceDepth(msg string, depth int, keysAndValues ...any) {
	if p.logr().V(KlogLevelTrace).Enabled() {
		p.logr().V(KlogLevelTrace).WithCallDepth(depth+1).Info(msg, keysAndValues...)
	}
}

// Trace logs show in the pod log output as `"level":"trace","message":"some msg"`
// where the message text comes from the msg parameter.
// They also contain the standard `timestamp` and `caller` keys, along with any other keysAndValues.
// Only when the global log level is configured to "trace" or "all", then they will also include a `stacktrace` key.
// Trace logs are suppressed by the global log level configuration, unless it is set to "trace" or above.
func (p pLogger) Trace(msg string, keysAndValues ...any) {
	p.traceDepth(msg, p.depth+1, keysAndValues...)
}

// TraceErr logs show in the pod log output as `"level":"trace","message":"some msg","error":"some error msg"`
// where the message text comes from the msg parameter and the error text comes from the err parameter.
// They also contain the standard `timestamp` and `caller` keys, along with any other keysAndValues.
// Only when the global log level is configured to "trace" or "all", then they will also include a `stacktrace` key.
// TraceErr logs are suppressed by the global log level configuration, unless it is set to "trace" or above.
func (p pLogger) TraceErr(msg string, err error, keysAndValues ...any) {
	p.traceDepth(msg, p.depth+1, slices.Concat([]any{errorKey, err}, keysAndValues)...)
}

// All logs show in the pod log output as `"level":"all","message":"some msg"`
// where the message text comes from the msg parameter.
// They also contain the standard `timestamp` and `caller` keys, along with any other keysAndValues.
// Only when the global log level is configured to "trace" or "all", then they will also include a `stacktrace` key.
// All logs are suppressed by the global log level configuration, unless it is set to "all" or above.
func (p pLogger) All(msg string, keysAndValues ...any) {
	if p.logr().V(klogLevelAll).Enabled() {
		p.logr().V(klogLevelAll).WithCallDepth(p.depth+1).Info(msg, keysAndValues...)
	}
}

// Always logs show in the pod log output exactly the same as an Info() message,
// except Always logs are always logged regardless of log level configuration.
// Only when the global log level is configured to "trace" or "all", then they will also include a `stacktrace` key.
// Always logs cannot be suppressed by the global log level configuration.
func (p pLogger) Always(msg string, keysAndValues ...any) {
	p.logr().WithCallDepth(p.depth+1).Info(msg, keysAndValues...)
}

func (p pLogger) WithValues(keysAndValues ...any) Logger {
	if len(keysAndValues) == 0 {
		return p
	}

	return p.withLogrMod(func(l logr.Logger) logr.Logger {
		return l.WithValues(keysAndValues...)
	})
}

func (p pLogger) WithName(name string) Logger {
	if len(name) == 0 {
		return p
	}

	return p.withLogrMod(func(l logr.Logger) logr.Logger {
		return l.WithName(name)
	})
}

func (p pLogger) withDepth(d int) Logger {
	out := p
	out.depth += d // out is a copy so this does not mutate p
	return out
}

func (p pLogger) withLogrMod(mod func(logr.Logger) logr.Logger) Logger {
	out := p // make a copy and carefully avoid mutating the mods slice
	mods := make([]func(logr.Logger) logr.Logger, 0, len(out.mods)+1)
	mods = slices.Concat(mods, out.mods)
	mods = append(mods, mod)
	out.mods = mods
	return out
}

func (p pLogger) logr() logr.Logger {
	l := globalLogger // grab the current global logger and its current config
	for _, mod := range p.mods {
		l = mod(l) // and then update it with all modifications
	}
	return l // this logger is guaranteed to have the latest config and all modifications
}

var logger = New().withDepth(1) //nolint:gochecknoglobals

func Error(msg string, err error, keysAndValues ...any) {
	logger.Error(msg, err, keysAndValues...)
}

func Warning(msg string, keysAndValues ...any) {
	logger.Warning(msg, keysAndValues...)
}

func WarningErr(msg string, err error, keysAndValues ...any) {
	logger.WarningErr(msg, err, keysAndValues...)
}

func Info(msg string, keysAndValues ...any) {
	logger.Info(msg, keysAndValues...)
}

func InfoErr(msg string, err error, keysAndValues ...any) {
	logger.InfoErr(msg, err, keysAndValues...)
}

func Debug(msg string, keysAndValues ...any) {
	logger.Debug(msg, keysAndValues...)
}

func DebugErr(msg string, err error, keysAndValues ...any) {
	logger.DebugErr(msg, err, keysAndValues...)
}

func Trace(msg string, keysAndValues ...any) {
	logger.Trace(msg, keysAndValues...)
}

func TraceErr(msg string, err error, keysAndValues ...any) {
	logger.TraceErr(msg, err, keysAndValues...)
}

func All(msg string, keysAndValues ...any) {
	logger.All(msg, keysAndValues...)
}

func Always(msg string, keysAndValues ...any) {
	logger.Always(msg, keysAndValues...)
}

func WithValues(keysAndValues ...any) Logger {
	// this looks weird but it is the same as New().WithValues(keysAndValues...) because it returns a new logger rooted at the call site
	return logger.withDepth(-1).WithValues(keysAndValues...)
}

func WithName(name string) Logger {
	// this looks weird but it is the same as New().WithName(name) because it returns a new logger rooted at the call site
	return logger.withDepth(-1).WithName(name)
}

func Fatal(err error, keysAndValues ...any) {
	logger.Error("unrecoverable error encountered", err, keysAndValues...)
	globalFlush()
	os.Exit(1)
}
