// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plog

import (
	"context"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
)

// contextKey type is unexported to prevent collisions.
type contextKey int

const zapOverridesKey contextKey = iota

func TestZapOverrides(ctx context.Context, t *testing.T, w io.Writer, f func(*zap.Config), opts ...zap.Option) context.Context {
	t.Helper() // discourage use outside of tests

	overrides := &testOverrides{
		t:    t,
		w:    w,
		f:    f,
		opts: opts,
	}
	return context.WithValue(ctx, zapOverridesKey, overrides)
}

func TestLogger(t *testing.T, w io.Writer) Logger {
	t.Helper()

	return New().withLogrMod(func(l logr.Logger) logr.Logger {
		return l.WithSink(TestZapr(t, w).GetSink())
	})
}

func TestZapr(t *testing.T, w io.Writer) logr.Logger {
	t.Helper()

	now, err := time.Parse(time.RFC3339Nano, "2099-08-08T13:57:36.123456789Z")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	ctx = TestZapOverrides(ctx, t, w,
		func(config *zap.Config) {
			config.Level = zap.NewAtomicLevelAt(math.MinInt8) // log everything during tests

			// make test assertions less painful to write while keeping them as close to the real thing as possible
			config.EncoderConfig.EncodeCaller = func(caller zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
				trimmed := caller.TrimmedPath()
				if idx := strings.LastIndexByte(trimmed, ':'); idx != -1 {
					trimmed = trimmed[:idx+1] + "<line>"
				}
				enc.AppendString(trimmed + funcEncoder(caller))
			}
		},
		zap.WithClock(ZapClock(clocktesting.NewFakeClock(now))), // have the clock be static during tests
		zap.AddStacktrace(nopLevelEnabler{}),                    // do not log stacktraces
	)

	// there is no buffering so we can ignore flush
	zl, _, err := newLogr(ctx, "json", 0)
	require.NoError(t, err)

	return zl
}

var _ zapcore.Clock = &clockAdapter{}

type clockAdapter struct {
	clock clock.Clock
}

func (c *clockAdapter) Now() time.Time {
	return c.clock.Now()
}

func (c *clockAdapter) NewTicker(duration time.Duration) *time.Ticker {
	return &time.Ticker{C: c.clock.Tick(duration)}
}

func ZapClock(c clock.Clock) zapcore.Clock {
	return &clockAdapter{clock: c}
}

var _ zap.Sink = nopCloserSink{}

type nopCloserSink struct{ zapcore.WriteSyncer }

func (nopCloserSink) Close() error { return nil }

// newSink returns a wrapper around the input writer that is safe for concurrent use.
func newSink(w io.Writer) zap.Sink {
	return nopCloserSink{WriteSyncer: zapcore.Lock(zapcore.AddSync(w))}
}

var _ zapcore.LevelEnabler = nopLevelEnabler{}

type nopLevelEnabler struct{}

func (nopLevelEnabler) Enabled(_ zapcore.Level) bool { return false }

type testOverrides struct {
	t    *testing.T
	w    io.Writer
	f    func(*zap.Config)
	opts []zap.Option
}
