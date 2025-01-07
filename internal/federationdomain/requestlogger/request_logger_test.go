// Copyright 2024-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package requestlogger

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
	clocktesting "k8s.io/utils/clock/testing"

	"go.pinniped.dev/internal/mocks/mockresponsewriter"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
)

func TestLogRequestReceived(t *testing.T) {
	var noAuditEventsWanted []testutil.WantedAuditLog

	happyAuditEventWanted := func(path string, sourceIPs []any) []testutil.WantedAuditLog {
		return []testutil.WantedAuditLog{
			testutil.WantAuditLog("HTTP Request Received",
				map[string]any{
					"proto":      "some-proto",
					"method":     "some-method",
					"host":       "some-host",
					"serverName": "some-sni-server-name",
					"path":       path,
					"userAgent":  "some-user-agent",
					"sourceIPs":  sourceIPs,
				},
			),
		}
	}

	tests := []struct {
		name               string
		reqPath            string
		reqRemoteAddr      string
		reqHeaders         map[string][]string
		auditInternalPaths bool
		wantAuditLogs      []testutil.WantedAuditLog
	}{
		{
			name:               "when internal paths are not enabled, ignores internal paths",
			reqPath:            "/healthz",
			auditInternalPaths: false,
			wantAuditLogs:      noAuditEventsWanted,
		},
		{
			name:               "when internal paths are not enabled, audits external path",
			reqPath:            "/pretend-to-login",
			reqRemoteAddr:      "1.2.3.4",
			auditInternalPaths: false,
			wantAuditLogs:      happyAuditEventWanted("/pretend-to-login", []any{"1.2.3.4"}),
		},
		{
			name:               "when internal paths are enabled, audits internal paths",
			reqPath:            "/healthz",
			reqRemoteAddr:      "1.2.3.4",
			auditInternalPaths: true,
			wantAuditLogs:      happyAuditEventWanted("/healthz", []any{"1.2.3.4"}),
		},
		{
			name:               "when internal paths are enabled, audits external paths",
			reqPath:            "/pretend-to-login",
			reqRemoteAddr:      "1.2.3.4",
			auditInternalPaths: true,
			wantAuditLogs:      happyAuditEventWanted("/pretend-to-login", []any{"1.2.3.4"}),
		},
		{
			name:               "when X-Forwarded-For header is present, includes its values in sourceIPs before the remoteAddr",
			reqPath:            "/pretend-to-login",
			reqRemoteAddr:      "1.2.3.4",
			reqHeaders:         map[string][]string{"X-Forwarded-For": {"5.6.7.8, 9.10.11.12"}},
			auditInternalPaths: true,
			wantAuditLogs:      happyAuditEventWanted("/pretend-to-login", []any{"5.6.7.8", "9.10.11.12", "1.2.3.4"}),
		},
		{
			name:               "when X-Real-Ip header is present, includes its value in sourceIPs before the remoteAddr",
			reqPath:            "/pretend-to-login",
			reqRemoteAddr:      "1.2.3.4",
			reqHeaders:         map[string][]string{"X-Real-Ip": {"5.6.7.8"}},
			auditInternalPaths: true,
			wantAuditLogs:      happyAuditEventWanted("/pretend-to-login", []any{"5.6.7.8", "1.2.3.4"}),
		},
		{
			name:          "when both X-Forwarded-For and X-Real-Ip headers are present, includes both headers' values in sourceIPs before the remoteAddr",
			reqPath:       "/pretend-to-login",
			reqRemoteAddr: "1.2.3.4",
			reqHeaders: map[string][]string{
				"X-Forwarded-For": {"5.6.7.8, 9.10.11.12"},
				"X-Real-Ip":       {"13.14.15.16"},
			},
			auditInternalPaths: true,
			wantAuditLogs:      happyAuditEventWanted("/pretend-to-login", []any{"5.6.7.8", "9.10.11.12", "13.14.15.16", "1.2.3.4"}),
		},
		{
			name:          "when the X-Real-Ip is the same as remoteAddr, does not duplicate remoteAddr",
			reqPath:       "/pretend-to-login",
			reqRemoteAddr: "1.2.3.4",
			reqHeaders: map[string][]string{
				"X-Forwarded-For": {"5.6.7.8, 9.10.11.12"},
				"X-Real-Ip":       {"1.2.3.4"},
			},
			auditInternalPaths: true,
			wantAuditLogs:      happyAuditEventWanted("/pretend-to-login", []any{"5.6.7.8", "9.10.11.12", "1.2.3.4"}),
		},
		{
			name:               "when the last value of X-Forwarded-For is the same as remoteAddr and there is no X-Real-Ip, does not duplicate remoteAddr",
			reqPath:            "/pretend-to-login",
			reqRemoteAddr:      "1.2.3.4",
			reqHeaders:         map[string][]string{"X-Forwarded-For": {"5.6.7.8, 1.2.3.4"}},
			auditInternalPaths: true,
			wantAuditLogs:      happyAuditEventWanted("/pretend-to-login", []any{"5.6.7.8", "1.2.3.4"}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			auditLogger, actualAuditLog := plog.TestAuditLogger(t)

			subject := requestLogger{
				auditLogger: auditLogger,
				req: &http.Request{
					Method: "some-method",
					Proto:  "some-proto",
					Host:   "some-host",
					URL: &url.URL{
						Path: test.reqPath,
					},
					RemoteAddr: test.reqRemoteAddr,
					Header:     test.reqHeaders,
					TLS: &tls.ConnectionState{
						ServerName: "some-sni-server-name",
					},
				},
				userAgent:          "some-user-agent",
				auditInternalPaths: test.auditInternalPaths,
			}

			subject.logRequestReceived()

			testutil.CompareAuditLogs(t, test.wantAuditLogs, actualAuditLog.String())
		})
	}
}

func TestLogRequestComplete(t *testing.T) {
	wantLatency := time.Minute + 2*time.Second + 345*time.Millisecond

	var noAuditEventsWanted []testutil.WantedAuditLog

	happyAuditEventWanted := func(path, location string) []testutil.WantedAuditLog {
		return []testutil.WantedAuditLog{
			testutil.WantAuditLog("HTTP Request Completed",
				map[string]any{
					"path":           path,
					"latency":        "1m2.345s",
					"responseStatus": 777.0, // JSON serializes this as a float
					"location":       location,
				},
			),
		}
	}

	tests := []struct {
		name               string
		reqPath            string
		location           string
		auditInternalPaths bool
		wantAuditLogs      []testutil.WantedAuditLog
	}{
		{
			name:               "when internal paths are not enabled, ignores internal paths",
			reqPath:            "/healthz",
			auditInternalPaths: false,
			wantAuditLogs:      noAuditEventsWanted,
		},
		{
			name:               "when internal paths are not enabled, audits external path with location (redacting unknown query params)",
			reqPath:            "/pretend-to-login",
			location:           "http://127.0.0.1?foo=bar&foo=quz&lorem=ipsum",
			auditInternalPaths: false,
			wantAuditLogs:      happyAuditEventWanted("/pretend-to-login", "http://127.0.0.1?foo=redacted&foo=redacted&lorem=redacted"),
		},
		{
			name:               "when internal paths are enabled, audits internal paths",
			reqPath:            "/healthz",
			auditInternalPaths: true,
			wantAuditLogs:      happyAuditEventWanted("/healthz", "no location header"),
		},
		{
			name:               "when internal paths are enabled, audits external paths",
			reqPath:            "/pretend-to-login",
			location:           "some-location",
			auditInternalPaths: true,
			wantAuditLogs:      happyAuditEventWanted("/pretend-to-login", "some-location"),
		},
		{
			name:          "audits path without location",
			reqPath:       "/pretend-to-login",
			location:      "", // make it obvious
			wantAuditLogs: happyAuditEventWanted("/pretend-to-login", "no location header"),
		},
		{
			name:          "audits path with invalid location",
			reqPath:       "/pretend-to-login",
			location:      "http://e x a m p l e.com",
			wantAuditLogs: happyAuditEventWanted("/pretend-to-login", "unparsable location header"),
		},
		{
			name:          "audits path with location redacting all query params except err, error, and error_description",
			reqPath:       "/pretend-to-login",
			location:      "http://127.0.0.1:1234?code=pin_ac_FAKE&foo=bar&foo=quz&lorem=ipsum&err=some-err&error=some-error&error_description=some-error-description&zzlast=some-value",
			wantAuditLogs: happyAuditEventWanted("/pretend-to-login", "http://127.0.0.1:1234?code=redacted&err=some-err&error=some-error&error_description=some-error-description&foo=redacted&foo=redacted&lorem=redacted&zzlast=redacted"),
		},
	}

	nowDoesntMatter := time.Date(1122, time.September, 33, 4, 55, 56, 778899, time.Local)
	startTime := nowDoesntMatter.Add(-wantLatency)
	frozenClock := clocktesting.NewFakeClock(nowDoesntMatter)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockResponseWriter := mockresponsewriter.NewMockResponseWriter(ctrl)
			if len(test.wantAuditLogs) > 0 {
				mockResponseWriter.EXPECT().Header().Return(http.Header{
					"Location": []string{test.location},
				})
			}

			auditLogger, actualAuditLog := plog.TestAuditLogger(t)

			subject := requestLogger{
				auditLogger: auditLogger,
				startTime:   startTime,
				clock:       frozenClock,
				req: &http.Request{
					URL: &url.URL{
						Path: test.reqPath,
					},
				},
				status:             777,
				w:                  mockResponseWriter,
				auditInternalPaths: test.auditInternalPaths,
			}

			subject.logRequestComplete()

			testutil.CompareAuditLogs(t, test.wantAuditLogs, actualAuditLog.String())
		})
	}
}
