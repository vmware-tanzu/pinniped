// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plog

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"go.uber.org/zap/zapcore"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/component-base/logs"

	"go.pinniped.dev/internal/constable"
)

type LogFormat string

func (l *LogFormat) UnmarshalJSON(b []byte) error {
	switch string(b) {
	case `""`, `"json"`:
		*l = FormatJSON
	// there is no "cli" case because it is not a supported option via our config
	default:
		return errInvalidLogFormat
	}
	return nil
}

const (
	FormatJSON LogFormat = "json"
	FormatCLI  LogFormat = "cli" // only used by the pinniped CLI and not the server components

	errInvalidLogLevel  = constable.Error("invalid log level, valid choices are the empty string, info, debug, trace and all")
	errInvalidLogFormat = constable.Error("invalid log format, valid choices are the empty string or 'json'")
)

var _ json.Unmarshaler = func() *LogFormat {
	var f LogFormat
	return &f
}()

type LogSpec struct {
	Level  LogLevel  `json:"level,omitempty"`
	Format LogFormat `json:"format,omitempty"`
}

func ValidateAndSetLogLevelAndFormatGlobally(ctx context.Context, spec LogSpec) error {
	klogLevel := klogLevelForPlogLevel(spec.Level)
	if klogLevel < 0 {
		return errInvalidLogLevel
	}

	// set the global log levels used by our code and the kube code underneath us
	if _, err := logs.GlogSetter(strconv.Itoa(int(klogLevel))); err != nil {
		panic(err) // programmer error
	}
	//nolint:gosec // the range for klogLevel is [0,108]
	globalLevel.SetLevel(zapcore.Level(-klogLevel)) // klog levels are inverted when zap handles them

	var encoding string
	switch spec.Format {
	case "", FormatJSON:
		encoding = "json"
	case FormatCLI:
		encoding = "console"
	default:
		return errInvalidLogFormat
	}

	log, flush, err := newLogr(ctx, encoding, klogLevel)
	if err != nil {
		return err
	}

	setGlobalLoggers(log, flush)

	if spec.Format == FormatCLI {
		return nil // do not spawn go routines on the CLI to allow the CLI to call this more than once
	}

	// do spawn go routines on the server
	go wait.UntilWithContext(ctx, func(_ context.Context) { flush() }, time.Minute)
	go func() {
		<-ctx.Done()
		flush() // best effort flush before shutdown as this is not coordinated with a wait group
	}()

	return nil
}
