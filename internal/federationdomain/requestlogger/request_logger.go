// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package requestlogger

import (
	"bufio"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	"k8s.io/apiserver/pkg/endpoints/responsewriter"
	"k8s.io/utils/clock"

	"go.pinniped.dev/internal/auditevent"
	"go.pinniped.dev/internal/config/supervisor"
	"go.pinniped.dev/internal/httputil/requestutil"
	"go.pinniped.dev/internal/plog"
)

func WithHTTPRequestAuditLogging(handler http.Handler, auditLogger plog.AuditLogger, auditInternalPathsCfg supervisor.AuditInternalPaths) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rl := newRequestLogger(req, w, auditLogger, time.Now(), auditInternalPathsCfg)

		rl.logRequestReceived()
		defer rl.logRequestComplete()

		statusCodeCapturingResponseWriter := responsewriter.WrapForHTTP1Or2(rl)
		handler.ServeHTTP(statusCodeCapturingResponseWriter, req)
	})
}

type requestLogger struct {
	startTime time.Time
	clock     clock.Clock // clock is used to calculate the response latency, and useful for unit tests.

	hijacked       bool
	statusRecorded bool
	status         int

	req       *http.Request
	userAgent string
	w         http.ResponseWriter

	auditLogger        plog.AuditLogger
	auditInternalPaths bool
}

func newRequestLogger(
	req *http.Request,
	w http.ResponseWriter,
	auditLogger plog.AuditLogger,
	startTime time.Time,
	auditInternalPathsCfg supervisor.AuditInternalPaths,
) *requestLogger {
	return &requestLogger{
		req:                req,
		w:                  w,
		startTime:          startTime,
		clock:              clock.RealClock{},
		userAgent:          req.UserAgent(), // cache this from the req to avoid any possibility of concurrent read/write problems with headers map
		auditLogger:        auditLogger,
		auditInternalPaths: auditInternalPathsCfg.Enabled(),
	}
}

func internalPaths() []string {
	return []string{
		"/healthz",
	}
}

func (rl *requestLogger) logRequestReceived() {
	r := rl.req

	if !rl.auditInternalPaths && slices.Contains(internalPaths(), r.URL.Path) {
		return
	}

	// Always log all other requests, including 404's caused by bad paths, for debugging purposes.
	rl.auditLogger.Audit(auditevent.HTTPRequestReceived, &plog.AuditParams{
		ReqCtx: r.Context(),
		KeysAndValues: []any{
			"proto", r.Proto,
			"method", r.Method,
			"host", r.Host,
			"serverName", requestutil.SNIServerName(r),
			"path", r.URL.Path,
			"userAgent", rl.userAgent,
			"remoteAddr", r.RemoteAddr,
		},
	})
}

func getLocationForAuditLogs(location string) string {
	if location == "" {
		return "no location header"
	}

	parsedLocation, err := url.Parse(location)
	if err != nil {
		return "unparsable location header"
	}

	// We don't know what this `Location` header is used for, so redact nearly all query parameters
	redactedParams := parsedLocation.Query()
	for k, v := range redactedParams {
		// Due to https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1,
		// authorize errors can have an 'error' and an 'error_description' parameter
		// which should never contain PII and is safe to log.
		// The 'err' parameter may be populated by the post_login_handler to indicate issues
		// when using Supervisor's built-in login page.
		if k == "error" || k == "error_description" || k == "err" {
			continue
		}
		for i := range v {
			redactedParams[k][i] = "redacted"
		}
	}
	parsedLocation.RawQuery = redactedParams.Encode()
	return parsedLocation.String()
}

func (rl *requestLogger) logRequestComplete() {
	r := rl.req

	if !rl.auditInternalPaths && slices.Contains(internalPaths(), r.URL.Path) {
		return
	}

	rl.auditLogger.Audit(auditevent.HTTPRequestCompleted, &plog.AuditParams{
		ReqCtx: r.Context(),
		KeysAndValues: []any{
			"path", r.URL.Path,
			"latency", rl.clock.Since(rl.startTime),
			"responseStatus", rl.status,
			"location", getLocationForAuditLogs(rl.Header().Get("Location")),
		},
	})
}

// Unwrap implements responsewriter.UserProvidedDecorator.
func (rl *requestLogger) Unwrap() http.ResponseWriter {
	return rl.w
}

// Header implements http.ResponseWriter.
func (rl *requestLogger) Header() http.Header {
	return rl.w.Header()
}

// Write implements http.ResponseWriter.
func (rl *requestLogger) Write(b []byte) (int, error) {
	if !rl.statusRecorded {
		rl.recordStatus(http.StatusOK) // Default if WriteHeader hasn't been called
	}
	return rl.w.Write(b)
}

// WriteHeader implements http.ResponseWriter.
func (rl *requestLogger) WriteHeader(status int) {
	rl.recordStatus(status)
	rl.w.WriteHeader(status)
}

// Hijack implements http.Hijacker.
func (rl *requestLogger) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rl.hijacked = true

	// the outer ResponseWriter object returned by WrapForHTTP1Or2 implements
	// http.Hijacker if the inner object (rl.w) implements http.Hijacker.
	return rl.w.(http.Hijacker).Hijack()
}

func (rl *requestLogger) recordStatus(status int) {
	rl.status = status
	rl.statusRecorded = true
}
