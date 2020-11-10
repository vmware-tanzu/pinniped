// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plog

import "k8s.io/klog/v2"

// Use Error to log an unexpected system error.
func Error(err error, msg string, keysAndValues ...interface{}) {
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

func Info(msg string, keysAndValues ...interface{}) {
	klog.V(klogLevelInfo).InfoS(msg, keysAndValues...)
}

// Use InfoErr to log an expected error, e.g. validation failure of an http parameter.
func InfoErr(msg string, err error, keysAndValues ...interface{}) {
	klog.V(klogLevelInfo).InfoS(msg, append([]interface{}{"error", err}, keysAndValues)...)
}

func Debug(msg string, keysAndValues ...interface{}) {
	klog.V(klogLevelDebug).InfoS(msg, keysAndValues...)
}

func Trace(msg string, keysAndValues ...interface{}) {
	klog.V(klogLevelTrace).InfoS(msg, keysAndValues...)
}

func All(msg string, keysAndValues ...interface{}) {
	klog.V(klogLevelAll).InfoS(msg, keysAndValues...)
}
