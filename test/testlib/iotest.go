// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testlib

import (
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
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
		l.t.Logf("%s > %q: %v", l.name, MaskTokens(string(p[0:n])), err)
	} else {
		l.t.Logf("%s > %q", l.name, MaskTokens(string(p[0:n])))
	}
	return
}

// MaskTokens makes a best-effort attempt to mask out things that look like secret tokens in test output.
// Provides more readable test output, but also obscures sensitive state params and authcodes from public test output.
func MaskTokens(in string) string {
	var tokenLike = regexp.MustCompile(`(?mi)[a-zA-Z0-9._-]{30,}|[a-zA-Z0-9]{20,}`)
	return tokenLike.ReplaceAllStringFunc(in, func(t string) string {
		// This is a silly heuristic, but things with multiple dots are more likely hostnames that we don't want masked.
		if strings.Count(t, ".") >= 4 {
			return t
		}
		// Another heuristic, things that start with "--" are probably CLI flags.
		if strings.HasPrefix(t, "--") {
			return t
		}
		return fmt.Sprintf("[...%d bytes...]", len(t))
	})
}

// Remove any potentially sensitive query param and fragment values for test logging.
func RedactURLParams(fullURL *url.URL) string {
	copyOfURL, _ := url.Parse(fullURL.String())
	if len(copyOfURL.RawQuery) > 0 {
		copyOfURL.RawQuery = "redacted"
	}
	if len(copyOfURL.Fragment) > 0 {
		copyOfURL.Fragment = "redacted"
	}
	return copyOfURL.String()
}
