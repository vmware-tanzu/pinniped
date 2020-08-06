/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	"fmt"
	"testing"

	"github.com/go-logr/logr"
)

type TranscriptLogger struct {
	t          *testing.T
	Transcript []TranscriptLogMessage
}

var _ logr.Logger = &TranscriptLogger{}

type TranscriptLogMessage struct {
	Level   string
	Message string
}

func NewTranscriptLogger(t *testing.T) *TranscriptLogger {
	return &TranscriptLogger{t: t}
}

func (log *TranscriptLogger) Info(msg string, keysAndValues ...interface{}) {
	log.Transcript = append(log.Transcript, TranscriptLogMessage{
		Level:   "info",
		Message: fmt.Sprintf(msg, keysAndValues...),
	})
}

func (log *TranscriptLogger) Error(err error, msg string, keysAndValues ...interface{}) {
	log.Transcript = append(log.Transcript, TranscriptLogMessage{
		Level:   "error",
		Message: fmt.Sprintf("%s: %v -- %v", msg, err, keysAndValues),
	})
}

func (*TranscriptLogger) Enabled() bool {
	return true
}

func (log *TranscriptLogger) V(_ int) logr.Logger {
	return log
}

func (log *TranscriptLogger) WithName(_ string) logr.Logger {
	return log
}

func (log *TranscriptLogger) WithValues(_ ...interface{}) logr.Logger {
	return log
}
