// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package library

import (
	"fmt"
	"io"
	"regexp"
	"testing"
)

// NewLoggerReader wraps an io.Reader to log its input and output. It also performs some heuristic token masking.
func NewLoggerReader(t *testing.T, name string, reader io.Reader) io.Reader {
	t.Helper()
	return &testlogReader{t: t, name: name, r: reader}
}

type testlogReader struct {
	t    *testing.T
	name string
	r    io.Reader
}

func (l *testlogReader) Read(p []byte) (n int, err error) {
	l.t.Helper()
	n, err = l.r.Read(p)
	if err != nil {
		l.t.Logf("%s > %q: %v", l.name, maskTokens(p[0:n]), err)
	} else {
		l.t.Logf("%s > %q", l.name, maskTokens(p[0:n]))
	}
	return
}

//nolint: gochecknoglobals
var tokenLike = regexp.MustCompile(`(?mi)[a-zA-Z0-9._-]{30,}|[a-zA-Z0-9]{20,}`)

func maskTokens(in []byte) string {
	return tokenLike.ReplaceAllStringFunc(string(in), func(t string) string {
		return fmt.Sprintf("[...%d bytes...]", len(t))
	})
}
