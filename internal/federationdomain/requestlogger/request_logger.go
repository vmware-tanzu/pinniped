// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package requestlogger

import (
	"bufio"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/types"
	apisaudit "k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/endpoints/responsewriter"

	"go.pinniped.dev/internal/httputil/requestutil"
	"go.pinniped.dev/internal/plog"
)

func WithAuditID(handler http.Handler) http.Handler {
	return withAuditID(handler, func() string {
		return uuid.New().String()
	})
}

func withAuditID(handler http.Handler, newAuditIDFunc func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := audit.WithAuditContext(r.Context())
		r = r.WithContext(ctx)

		auditID := newAuditIDFunc()
		audit.WithAuditID(ctx, types.UID(auditID))

		// Send the Audit-ID response header.
		w.Header().Set(apisaudit.HeaderAuditID, auditID)

		handler.ServeHTTP(w, r)
	})
}

func WithHTTPRequestAuditLogging(handler http.Handler, auditLogger plog.AuditLogger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rl := newRequestLogger(req, w, auditLogger, time.Now())

		rl.LogRequestReceived()
		defer rl.LogRequestComplete()

		statusCodeCapturingResponseWriter := responsewriter.WrapForHTTP1Or2(rl)
		handler.ServeHTTP(statusCodeCapturingResponseWriter, req)
	})
}

type requestLogger struct {
	startTime time.Time

	hijacked       bool
	statusRecorded bool
	status         int

	req       *http.Request
	userAgent string
	w         http.ResponseWriter

	auditLogger plog.AuditLogger
}

func newRequestLogger(req *http.Request, w http.ResponseWriter, auditLogger plog.AuditLogger, startTime time.Time) *requestLogger {
	return &requestLogger{
		req:         req,
		w:           w,
		startTime:   startTime,
		userAgent:   req.UserAgent(), // cache this from the req to avoid any possibility of concurrent read/write problems with headers map
		auditLogger: auditLogger,
	}
}

func (rl *requestLogger) LogRequestReceived() {
	r := rl.req
	rl.auditLogger.Audit(plog.AuditEventHTTPRequestReceived,
		r.Context(),
		nil, // no session available yet in this context
		"proto", r.Proto,
		"method", r.Method,
		"host", r.Host,
		"serverName", requestutil.SNIServerName(r),
		"path", r.URL.Path,
		"userAgent", rl.userAgent,
		"remoteAddr", r.RemoteAddr,
	)
}

func (rl *requestLogger) LogRequestComplete() {
	r := rl.req
	rl.auditLogger.Audit(plog.AuditEventHTTPRequestCompleted,
		r.Context(),
		nil,                // no session available yet in this context
		"path", r.URL.Path, // include the path again to make it easy to "grep -v healthz" to watch all other audit events
		"latency", time.Since(rl.startTime),
		"responseStatus", rl.status,
	)
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
