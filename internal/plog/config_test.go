// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plog

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestFormat(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var buf bytes.Buffer

	scanner := bufio.NewScanner(&buf)

	fakeNow, err := time.Parse(time.RFC3339Nano, "2022-11-21T23:37:26.953313745Z")
	require.NoError(t, err)
	fakeClock := clocktesting.NewFakeClock(fakeNow)
	nowStr := fakeNow.Local().Format(time.RFC1123)

	ctx = AddZapOverridesToContext(ctx, t, &buf, nil, fakeClock)

	err = ValidateAndSetLogLevelAndFormatGlobally(ctx, LogSpec{Level: LevelDebug})
	require.NoError(t, err)

	wd, err := os.Getwd()
	require.NoError(t, err)

	Info("hello", "happy", "day", "duration", time.Hour+time.Minute)
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.JSONEq(t, fmt.Sprintf(`
{
  "level": "info",
  "timestamp": "2022-11-21T23:37:26.953313Z",
  "caller": "%s/config_test.go:%d$plog.TestFormat",
  "message": "hello",
  "happy": "day",
  "duration": "1h1m0s"
}`, wd, getLineNumberOfCaller()-11), scanner.Text())

	New().WithName("burrito").Error("wee", errInvalidLogLevel, "a", "b")
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.JSONEq(t, fmt.Sprintf(`
{
  "level": "error",
  "timestamp": "2022-11-21T23:37:26.953313Z",
  "caller": "%s/config_test.go:%d$plog.TestFormat",
  "message": "wee",
  "a": "b",
  "error": "invalid log level, valid choices are the empty string, info, debug, trace and all",
  "logger": "burrito"
}`, wd, getLineNumberOfCaller()-12), scanner.Text())

	New().Info("hey")
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.JSONEq(t, fmt.Sprintf(`
{
  "level": "info",
  "timestamp": "2022-11-21T23:37:26.953313Z",
  "caller": "%s/config_test.go:%d$plog.TestFormat",
  "message": "hey"
}`, wd, getLineNumberOfCaller()-9), scanner.Text())

	Warning("bad stuff") // note that this sets the custom warning key because it is via plog
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.JSONEq(t, fmt.Sprintf(`
{
  "level": "info",
  "timestamp": "2022-11-21T23:37:26.953313Z",
  "caller": "%s/config_test.go:%d$plog.TestFormat",
  "message": "bad stuff",
  "warning": true
}`, wd, getLineNumberOfCaller()-10), scanner.Text())

	func() { DebugErr("something happened", errInvalidLogFormat, "an", "item") }()
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.JSONEq(t, fmt.Sprintf(`
{
  "level": "debug",
  "timestamp": "2022-11-21T23:37:26.953313Z",
  "caller": "%s/config_test.go:%d$plog.TestFormat.func1",
  "message": "something happened",
  "error": "invalid log format, valid choices are the empty string or 'json'",
  "an": "item"
}`, wd, getLineNumberOfCaller()-11), scanner.Text())

	Trace("should not be logged", "for", "sure")
	require.Empty(t, buf.String())

	New().All("also should not be logged", "open", "close")
	require.Empty(t, buf.String())

	ctx = AddZapOverridesToContext(ctx, t, &buf, nil, fakeClock, zap.AddStacktrace(LevelInfo))

	err = ValidateAndSetLogLevelAndFormatGlobally(ctx, LogSpec{Level: LevelDebug})
	require.NoError(t, err)

	WithName("stacky").WithName("does").Info("has a stack trace!")
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())

	require.JSONEq(t, fmt.Sprintf(`
{
  "level": "info",
  "timestamp": "2022-11-21T23:37:26.953313Z",
  "caller": "%s/config_test.go:%d$plog.TestFormat",
  "message": "has a stack trace!",
  "logger": "stacky.does",
  "stacktrace": %s
}`, wd, getLineNumberOfCaller()-12,
		strconv.Quote(
			fmt.Sprintf(
				`go.pinniped.dev/internal/plog.TestFormat
	%s/config_test.go:%d
testing.tRunner
	%s/src/testing/testing.go:%d`,
				wd, getLineNumberOfCaller()-19, runtime.GOROOT(), getLineNumberOfCaller(2), //nolint:staticcheck // calling a deprecated function is good enough for this unit test
			),
		),
	), scanner.Text())

	ctx = AddZapOverridesToContext(ctx, t, &buf, nil, fakeClock)

	err = ValidateAndSetLogLevelAndFormatGlobally(ctx, LogSpec{Level: LevelDebug, Format: FormatCLI})
	require.NoError(t, err)

	DebugErr("something happened", errInvalidLogFormat, "an", "item")
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.Equal(t, fmt.Sprintf(nowStr+`  plog/config_test.go:%d  something happened  {"error": "invalid log format, valid choices are the empty string or 'json'", "an": "item"}`,
		getLineNumberOfCaller()-4), scanner.Text())

	New().WithName("burrito").Error("wee", errInvalidLogLevel, "a", "b", "slightly less than a year", 363*24*time.Hour, "slightly more than 2 years", 2*367*24*time.Hour)
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.Equal(t, fmt.Sprintf(nowStr+`  burrito  plog/config_test.go:%d  wee  {"a": "b", "slightly less than a year": "363d", "slightly more than 2 years": "2y4d", "error": "invalid log level, valid choices are the empty string, info, debug, trace and all"}`,
		getLineNumberOfCaller()-4), scanner.Text())

	require.False(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.Empty(t, scanner.Text())
	require.Empty(t, buf.String())
}

func TestValidateAndSetLogLevelGlobally(t *testing.T) {
	originalLogLevel := getKlogLevel()
	require.GreaterOrEqual(t, int(originalLogLevel), int(klog.Level(0)), "cannot get klog level")

	tests := []struct {
		name        string
		level       LogLevel
		wantLevel   klog.Level
		wantEnabled []LogLevel
		wantErr     string
	}{
		{
			name:        "unset",
			wantLevel:   0,
			wantEnabled: []LogLevel{LevelWarning},
		},
		{
			name:        "warning",
			level:       LevelWarning,
			wantLevel:   0,
			wantEnabled: []LogLevel{LevelWarning},
		},
		{
			name:        "info",
			level:       LevelInfo,
			wantLevel:   2,
			wantEnabled: []LogLevel{LevelWarning, LevelInfo},
		},
		{
			name:        "debug",
			level:       LevelDebug,
			wantLevel:   4,
			wantEnabled: []LogLevel{LevelWarning, LevelInfo, LevelDebug},
		},
		{
			name:        "trace",
			level:       LevelTrace,
			wantLevel:   6,
			wantEnabled: []LogLevel{LevelWarning, LevelInfo, LevelDebug, LevelTrace},
		},
		{
			name:        "all",
			level:       LevelAll,
			wantLevel:   108,
			wantEnabled: []LogLevel{LevelWarning, LevelInfo, LevelDebug, LevelTrace, LevelAll},
		},
		{
			name:      "invalid level",
			level:     "panda",
			wantLevel: originalLogLevel,
			wantErr:   errInvalidLogLevel.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				undoGlobalLogLevelChanges(t, originalLogLevel)
			}()

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			err := ValidateAndSetLogLevelAndFormatGlobally(ctx, LogSpec{Level: tt.level})
			require.Equal(t, tt.wantErr, errString(err))
			require.Equal(t, tt.wantLevel, getKlogLevel())

			if tt.wantEnabled != nil {
				allLevels := []LogLevel{LevelWarning, LevelInfo, LevelDebug, LevelTrace, LevelAll}
				for _, level := range allLevels {
					if contains(tt.wantEnabled, level) {
						require.Truef(t, Enabled(level), "wanted %q to be enabled", level)
					} else {
						require.False(t, Enabled(level), "did not want %q to be enabled", level)
					}
				}
			}
		})
	}

	require.Equal(t, originalLogLevel, getKlogLevel())
}

func contains(haystack []LogLevel, needle LogLevel) bool {
	for _, hay := range haystack {
		if hay == needle {
			return true
		}
	}
	return false
}

func errString(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}

func undoGlobalLogLevelChanges(t *testing.T, originalLogLevel klog.Level) {
	t.Helper()
	_, err := logs.GlogSetter(strconv.Itoa(int(originalLogLevel)))
	require.NoError(t, err)
}

func getKlogLevel() klog.Level {
	// hack around klog not exposing a Get method
	for i := klog.Level(0); i < 256; i++ {
		if klog.V(i).Enabled() {
			continue
		}
		return i - 1
	}

	return -1
}

// getLineNumberOfCaller returns the line number of the source code that invoked this function.
// If maybeSkip is provided, returns the line number from a different point in the call stack.
// This is useful to test log output that prints a call stack with line numbers.
func getLineNumberOfCaller(maybeSkip ...int) int {
	skip := 1
	if len(maybeSkip) > 0 {
		skip = maybeSkip[0]
	}

	if _, _, line, ok := runtime.Caller(skip); ok {
		return line
	}
	return -1
}
