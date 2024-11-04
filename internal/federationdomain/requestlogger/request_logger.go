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

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	apisaudit "k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/endpoints/responsewriter"
	"k8s.io/utils/clock"

	"go.pinniped.dev/internal/config/supervisor"
	"go.pinniped.dev/internal/httputil/requestutil"
	"go.pinniped.dev/internal/plog"
)

func NewRequestWithAuditID(r *http.Request, newAuditIDFunc func() string) (*http.Request, string) {
	ctx := audit.WithAuditContext(r.Context())
	r = r.WithContext(ctx)

	auditID := newAuditIDFunc()
	audit.WithAuditID(ctx, types.UID(auditID))

	return r, auditID
}

func WithAuditID(handler http.Handler, newAuditIDFunc func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r, auditID := NewRequestWithAuditID(r, newAuditIDFunc)

		// Send the Audit-ID response header.
		w.Header().Set(apisaudit.HeaderAuditID, auditID)

		handler.ServeHTTP(w, r)
	})
}

func WithHTTPRequestAuditLogging(handler http.Handler, auditLogger plog.AuditLogger, auditCfg supervisor.AuditSpec) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rl := newRequestLogger(req, w, auditLogger, time.Now(), auditCfg)

		rl.LogRequestReceived()
		defer rl.LogRequestComplete()

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

	auditLogger plog.AuditLogger
	auditCfg    supervisor.AuditSpec
}

func newRequestLogger(req *http.Request, w http.ResponseWriter, auditLogger plog.AuditLogger, startTime time.Time, auditCfg supervisor.AuditSpec) *requestLogger {
	return &requestLogger{
		req:         req,
		w:           w,
		startTime:   startTime,
		clock:       clock.RealClock{},
		userAgent:   req.UserAgent(), // cache this from the req to avoid any possibility of concurrent read/write problems with headers map
		auditLogger: auditLogger,
		auditCfg:    auditCfg,
	}
}

func internalPaths() []string {
	return []string{
		"/healthz",
	}
}

func (rl *requestLogger) LogRequestReceived() {
	r := rl.req

	if rl.auditCfg.InternalPaths != supervisor.AuditInternalPathsEnabled && slices.Contains(internalPaths(), r.URL.Path) {
		return
	}

	rl.auditLogger.Audit(plog.AuditEventHTTPRequestReceived,
		r.Context(),
		plog.NoSessionPersisted(),
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

	if rl.auditCfg.InternalPaths != supervisor.AuditInternalPathsEnabled && slices.Contains(internalPaths(), r.URL.Path) {
		return
	}

	location := rl.Header().Get("Location")
	if location == "" {
		location = "no location header"
	} else {
		parsedLocation, err := url.Parse(location)
		if err != nil {
			location = "unparsable location header"
		} else {
			redactAllParams := sets.New[string]()
			parsedLocation.RawQuery = plog.SanitizeParams(parsedLocation.Query(), redactAllParams)
			location = parsedLocation.String()
		}
	}

	rl.auditLogger.Audit(plog.AuditEventHTTPRequestCompleted,
		r.Context(),
		plog.NoSessionPersisted(),
		"path", r.URL.Path, // include the path again to make it easy to "grep -v healthz" to watch all other audit events
		"latency", rl.clock.Since(rl.startTime),
		"responseStatus", rl.status,
		"location", location,
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
