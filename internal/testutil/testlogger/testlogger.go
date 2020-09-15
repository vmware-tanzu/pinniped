/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package testlogger implements a logr.Logger suitable for writing test assertions.
package testlogger

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
)

// Logger implements logr.Logger in a way that captures logs for test assertions.
type Logger struct {
	logr.Logger
	t      *testing.T
	buffer syncBuffer
}

// New returns a new test Logger.
func New(t *testing.T) *Logger {
	res := Logger{t: t}
	res.Logger = stdr.New(log.New(&res.buffer, "", 0))
	return &res
}

// Lines returns the lines written to the test logger.
func (l *Logger) Lines() []string {
	l.t.Helper()
	l.buffer.mutex.Lock()
	defer l.buffer.mutex.Unlock()

	// Trim leading/trailing whitespace and omit empty lines.
	var result []string
	for _, line := range strings.Split(l.buffer.buffer.String(), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

// syncBuffer synchronizes access to a bytes.Buffer.
type syncBuffer struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (n int, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.buffer.Write(p)
}
