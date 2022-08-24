// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
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
	"k8s.io/klog/v2/textlogger"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestFormat(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var buf bytes.Buffer

	scanner := bufio.NewScanner(&buf)

	now, err := time.Parse(time.RFC3339Nano, "2022-11-21T23:37:26.953313745Z")
	require.NoError(t, err)
	fakeClock := clocktesting.NewFakeClock(now)
	nowStr := now.Local().Format(time.RFC1123)

	ctx = TestZapOverrides(ctx, t, &buf, nil, zap.WithClock(ZapClock(fakeClock)))

	err = ValidateAndSetLogLevelAndFormatGlobally(ctx, LogSpec{Level: LevelDebug})
	require.NoError(t, err)

	wd, err := os.Getwd()
	require.NoError(t, err)

	const startLogLine = 46 // make this match the current line number

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
}`, wd, startLogLine+2), scanner.Text())

	Logr().WithName("burrito").Error(errInvalidLogLevel, "wee", "a", "b")
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
}`, wd, startLogLine+2+13), scanner.Text())

	Logr().V(klogLevelWarning).Info("hey") // note that this fails to set the custom warning key because it is not via plog
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.JSONEq(t, fmt.Sprintf(`
{
  "level": "info",
  "timestamp": "2022-11-21T23:37:26.953313Z",
  "caller": "%s/config_test.go:%d$plog.TestFormat",
  "message": "hey"
}`, wd, startLogLine+2+13+14), scanner.Text())

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
}`, wd, startLogLine+2+13+14+11), scanner.Text())

	func() { DebugErr("something happened", errInvalidLogFormat, "an", "item") }()
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.JSONEq(t, fmt.Sprintf(`
{
  "level": "debug",
  "timestamp": "2022-11-21T23:37:26.953313Z",
  "caller": "%s/config_test.go:%d$plog.TestFormat.func1",
  "message": "something happened",
  "error": "invalid log format, valid choices are the empty string, json and text",
  "an": "item"
}`, wd, startLogLine+2+13+14+11+12), scanner.Text())

	Trace("should not be logged", "for", "sure")
	require.Empty(t, buf.String())

	Logr().V(klogLevelAll).Info("also should not be logged", "open", "close")
	require.Empty(t, buf.String())

	ctx = TestZapOverrides(ctx, t, &buf, nil, zap.WithClock(ZapClock(fakeClock)), zap.AddStacktrace(LevelInfo))

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
}`, wd, startLogLine+2+13+14+11+12+24,
		strconv.Quote(
			fmt.Sprintf(
				`go.pinniped.dev/internal/plog.TestFormat
	%s/config_test.go:%d
testing.tRunner
	%s/src/testing/testing.go:1446`,
				wd, startLogLine+2+13+14+11+12+24, runtime.GOROOT(),
			),
		),
	), scanner.Text())

	ctx = TestZapOverrides(ctx, t, &buf, nil, zap.WithClock(ZapClock(fakeClock)))

	err = ValidateAndSetLogLevelAndFormatGlobally(ctx, LogSpec{Level: LevelDebug, Format: FormatCLI})
	require.NoError(t, err)

	DebugErr("something happened", errInvalidLogFormat, "an", "item")
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.Equal(t, fmt.Sprintf(nowStr+`  plog/config_test.go:%d  something happened  {"error": "invalid log format, valid choices are the empty string, json and text", "an": "item"}`,
		startLogLine+2+13+14+11+12+24+28), scanner.Text())

	Logr().WithName("burrito").Error(errInvalidLogLevel, "wee", "a", "b", "slightly less than a year", 363*24*time.Hour, "slightly more than 2 years", 2*367*24*time.Hour)
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.Equal(t, fmt.Sprintf(nowStr+`  burrito  plog/config_test.go:%d  wee  {"a": "b", "slightly less than a year": "363d", "slightly more than 2 years": "2y4d", "error": "invalid log level, valid choices are the empty string, info, debug, trace and all"}`,
		startLogLine+2+13+14+11+12+24+28+6), scanner.Text())

	origTimeNow := textlogger.TimeNow
	t.Cleanup(func() {
		textlogger.TimeNow = origTimeNow
	})
	textlogger.TimeNow = func() time.Time {
		return now
	}

	old := New().WithName("created before mode change").WithValues("is", "old")

	err = ValidateAndSetLogLevelAndFormatGlobally(ctx, LogSpec{Level: LevelDebug, Format: FormatText})
	require.NoError(t, err)
	pid := os.Getpid()

	// check for the deprecation warning
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.Equal(t, fmt.Sprintf(`I1121 23:37:26.953313%8d config.go:96] "setting log.format to 'text' is deprecated - this option will be removed in a future release" warning=true`,
		pid), scanner.Text())

	Debug("what is happening", "does klog", "work?")
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.Equal(t, fmt.Sprintf(`I1121 23:37:26.953313%8d config_test.go:%d] "what is happening" does klog="work?"`,
		pid, startLogLine+2+13+14+11+12+24+28+6+26), scanner.Text())

	Logr().WithName("panda").V(KlogLevelDebug).Info("are the best", "yes?", "yes.")
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.Equal(t, fmt.Sprintf(`I1121 23:37:26.953313%8d config_test.go:%d] "panda: are the best" yes?="yes."`,
		pid, startLogLine+2+13+14+11+12+24+28+6+26+6), scanner.Text())

	New().WithName("hi").WithName("there").WithValues("a", 1, "b", 2).Always("do it")
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.Equal(t, fmt.Sprintf(`I1121 23:37:26.953313%8d config_test.go:%d] "hi/there: do it" a=1 b=2`,
		pid, startLogLine+2+13+14+11+12+24+28+6+26+6+6), scanner.Text())

	l := WithValues("x", 33, "z", 22)
	l.Debug("what to do")
	l.Debug("and why")
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.Equal(t, fmt.Sprintf(`I1121 23:37:26.953313%8d config_test.go:%d] "what to do" x=33 z=22`,
		pid, startLogLine+2+13+14+11+12+24+28+6+26+6+6+7), scanner.Text())
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.Equal(t, fmt.Sprintf(`I1121 23:37:26.953313%8d config_test.go:%d] "and why" x=33 z=22`,
		pid, startLogLine+2+13+14+11+12+24+28+6+26+6+6+7+1), scanner.Text())

	old.Always("should be klog text format", "for", "sure")
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.Equal(t, fmt.Sprintf(`I1121 23:37:26.953313%8d config_test.go:%d] "created before mode change: should be klog text format" is="old" for="sure"`,
		pid, startLogLine+2+13+14+11+12+24+28+6+26+6+6+7+1+10), scanner.Text())

	// make sure child loggers do not share state
	old1 := old.WithValues("i am", "old1")
	old2 := old.WithName("old2")
	old1.Warning("warn")
	old2.Info("info")
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.Equal(t, fmt.Sprintf(`I1121 23:37:26.953313%8d config_test.go:%d] "created before mode change: warn" is="old" i am="old1" warning=true`,
		pid, startLogLine+2+13+14+11+12+24+28+6+26+6+6+7+1+10+9), scanner.Text())
	require.True(t, scanner.Scan())
	require.NoError(t, scanner.Err())
	require.Equal(t, fmt.Sprintf(`I1121 23:37:26.953313%8d config_test.go:%d] "created before mode change/old2: info" is="old"`,
		pid, startLogLine+2+13+14+11+12+24+28+6+26+6+6+7+1+10+9+1), scanner.Text())

	Trace("should not be logged", "for", "sure")
	require.Empty(t, buf.String())

	Logr().V(klogLevelAll).Info("also should not be logged", "open", "close")
	require.Empty(t, buf.String())

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
		tt := tt // capture range variable
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
