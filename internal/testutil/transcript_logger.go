// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"fmt"
	"sync"
	"testing"

	"github.com/go-logr/logr"
)

type TranscriptLogger struct {
	t          *testing.T
	lock       sync.Mutex
	transcript []TranscriptLogMessage
}

var _ logr.LogSink = &TranscriptLogger{}

type TranscriptLogMessage struct {
	Level   string
	Message string
}

// Deprecated: Use plog.TestLogger or plog.TestZapr instead.  This is meant for old tests only.
func NewTranscriptLogger(t *testing.T) *TranscriptLogger {
	return &TranscriptLogger{t: t}
}

func (log *TranscriptLogger) Transcript() []TranscriptLogMessage {
	log.lock.Lock()
	defer log.lock.Unlock()
	result := make([]TranscriptLogMessage, 0, len(log.transcript))
	result = append(result, log.transcript...)
	return result
}

func (log *TranscriptLogger) Info(level int, msg string, keysAndValues ...interface{}) {
	log.lock.Lock()
	defer log.lock.Unlock()
	log.transcript = append(log.transcript, TranscriptLogMessage{
		Level:   "info",
		Message: fmt.Sprintf(msg, keysAndValues...),
	})
}

func (log *TranscriptLogger) Error(_ error, msg string, _ ...interface{}) {
	log.lock.Lock()
	defer log.lock.Unlock()
	log.transcript = append(log.transcript, TranscriptLogMessage{
		Level:   "error",
		Message: msg,
	})
}

func (log *TranscriptLogger) Enabled(level int) bool {
	return true
}

func (log *TranscriptLogger) V(_ int) logr.LogSink {
	return log
}

func (log *TranscriptLogger) WithName(_ string) logr.LogSink {
	return log
}

func (log *TranscriptLogger) WithValues(_ ...interface{}) logr.LogSink {
	return log
}

func (log *TranscriptLogger) Init(info logr.RuntimeInfo) {}
