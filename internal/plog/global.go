// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plog

import (
	"context"
	"fmt"
	"net/url"
	"sync"

	"github.com/go-logr/logr"
	"go.uber.org/zap"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
)

//nolint:gochecknoglobals
var (
	// note that these globals have no locks on purpose - they are expected to be set at init and then again after config parsing.
	globalLevel  zap.AtomicLevel
	globalLogger logr.Logger
	globalFlush  func()

	// used as a temporary storage for a buffer per call of newLogr. see the init function below for more details.
	sinkMap sync.Map
)

//nolint:gochecknoinits
func init() {
	// make sure we always have a functional global logger
	globalLevel = zap.NewAtomicLevelAt(0) // log at the 0 verbosity level to start with, i.e. the "always" logs
	// use json encoding to start with
	// the context here is just used for test injection and thus can be ignored
	log, flush, err := newLogr(context.Background(), "json", 0)
	if err != nil {
		panic(err) // default logging config must always work
	}
	setGlobalLoggers(log, flush)

	// this is a little crazy but zap's builder code does not allow us to directly specify what
	// writer we want to use as our log sink.  to get around this limitation in tests, we use a
	// global map to temporarily hold the writer (the key is a random string that is generated
	// per invocation of newLogr).  we register a fake "pinniped" scheme so that we can lookup
	// the writer via pinniped:///<per newLogr invocation random string>.
	if err := zap.RegisterSink("pinniped", func(u *url.URL) (zap.Sink, error) {
		value, ok := sinkMap.Load(u.Path)
		if !ok {
			return nil, fmt.Errorf("key %q not in global sink", u.Path)
		}
		return value.(zap.Sink), nil
	}); err != nil {
		panic(err) // custom sink must always work
	}
}

// Deprecated: Use New instead.  This is meant for old code only.
// New provides a more ergonomic API and correctly responds to global log config change.
func Logr() logr.Logger {
	return globalLogger
}

func Setup() func() {
	logs.InitLogs()
	return func() {
		logs.FlushLogs()
		globalFlush()
	}
}

// setGlobalLoggers sets the plog and klog global loggers.  it is *not* go routine safe.
func setGlobalLoggers(log logr.Logger, flush func()) {
	// a contextual logger does its own level based enablement checks, which is true for all of our loggers
	klog.SetLoggerWithOptions(log, klog.ContextualLogger(true), klog.FlushLogger(flush))
	globalLogger = log
	globalFlush = flush
}
