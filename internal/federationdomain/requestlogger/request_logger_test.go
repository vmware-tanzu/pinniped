// Copyright 2024 the Pinniped contributors. All Rights Reserved.
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

	"go.pinniped.dev/internal/config/supervisor"
	"go.pinniped.dev/internal/mocks/mockresponsewriter"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
)

func TestLogRequestReceived(t *testing.T) {
	var noAuditEventsWanted []testutil.WantedAuditLog

	happyAuditEventWanted := func(path string) []testutil.WantedAuditLog {
		return []testutil.WantedAuditLog{
			testutil.WantAuditLog("HTTP Request Received",
				map[string]any{
					"proto":      "some-proto",
					"method":     "some-method",
					"host":       "some-host",
					"serverName": "some-sni-server-name",
					"path":       path,
					"userAgent":  "some-user-agent",
					"remoteAddr": "some-remote-addr",
				},
			),
		}
	}

	tests := []struct {
		name          string
		path          string
		auditCfg      supervisor.AuditSpec
		wantAuditLogs []testutil.WantedAuditLog
	}{
		{
			name: "when internal paths are not Enabled, ignores internal paths",
			path: "/healthz",
			auditCfg: supervisor.AuditSpec{
				InternalPaths: "Disabled",
			},
			wantAuditLogs: noAuditEventsWanted,
		},
		{
			name: "when internal paths are not Enabled, audits external path",
			path: "/pretend-to-login",
			auditCfg: supervisor.AuditSpec{
				InternalPaths: "Disabled",
			},
			wantAuditLogs: happyAuditEventWanted("/pretend-to-login"),
		},
		{
			name: "when internal paths are Enabled, audits internal paths",
			path: "/healthz",
			auditCfg: supervisor.AuditSpec{
				InternalPaths: "Enabled",
			},
			wantAuditLogs: happyAuditEventWanted("/healthz"),
		},
		{
			name: "when internal paths are Enabled, audits external paths",
			path: "/pretend-to-login",
			auditCfg: supervisor.AuditSpec{
				InternalPaths: "Enabled",
			},
			wantAuditLogs: happyAuditEventWanted("/pretend-to-login"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			logger, log := plog.TestLogger(t)

			subject := requestLogger{
				auditLogger: logger,
				req: &http.Request{
					Method: "some-method",
					Proto:  "some-proto",
					Host:   "some-host",
					URL: &url.URL{
						Path: test.path,
					},
					RemoteAddr: "some-remote-addr",
					TLS: &tls.ConnectionState{
						ServerName: "some-sni-server-name",
					},
				},
				userAgent: "some-user-agent",
				auditCfg:  test.auditCfg,
			}

			subject.logRequestReceived()

			testutil.CompareAuditLogs(t, test.wantAuditLogs, log.String())
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
		name          string
		path          string
		location      string
		auditCfg      supervisor.AuditSpec
		wantAuditLogs []testutil.WantedAuditLog
	}{
		{
			name: "when internal paths are not Enabled, ignores internal paths",
			path: "/healthz",
			auditCfg: supervisor.AuditSpec{
				InternalPaths: "Disabled",
			},
			wantAuditLogs: noAuditEventsWanted,
		},
		{
			name:     "when internal paths are not Enabled, audits external path with location (redacting unknown query params)",
			path:     "/pretend-to-login",
			location: "http://127.0.0.1?foo=bar&foo=quz&lorem=ipsum",
			auditCfg: supervisor.AuditSpec{
				InternalPaths: "Disabled",
			},
			wantAuditLogs: happyAuditEventWanted("/pretend-to-login", "http://127.0.0.1?foo=redacted&foo=redacted&lorem=redacted"),
		},
		{
			name: "when internal paths are Enabled, audits internal paths",
			path: "/healthz",
			auditCfg: supervisor.AuditSpec{
				InternalPaths: "Enabled",
			},
			wantAuditLogs: happyAuditEventWanted("/healthz", "no location header"),
		},
		{
			name:     "when internal paths are Enabled, audits external paths",
			path:     "/pretend-to-login",
			location: "some-location",
			auditCfg: supervisor.AuditSpec{
				InternalPaths: "Enabled",
			},
			wantAuditLogs: happyAuditEventWanted("/pretend-to-login", "some-location"),
		},
		{
			name:          "audits path without location",
			path:          "/pretend-to-login",
			location:      "", // make it obvious
			wantAuditLogs: happyAuditEventWanted("/pretend-to-login", "no location header"),
		},
		{
			name:          "audits path with invalid location",
			path:          "/pretend-to-login",
			location:      "http://e x a m p l e.com",
			wantAuditLogs: happyAuditEventWanted("/pretend-to-login", "unparsable location header"),
		},
		{
			name:          "audits path with location redacting all query params except err, error, and error_description",
			path:          "/pretend-to-login",
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

			logger, log := plog.TestLogger(t)

			subject := requestLogger{
				auditLogger: logger,
				startTime:   startTime,
				clock:       frozenClock,
				req: &http.Request{
					URL: &url.URL{
						Path: test.path,
					},
				},
				status:   777,
				w:        mockResponseWriter,
				auditCfg: test.auditCfg,
			}

			subject.logRequestComplete()

			testutil.CompareAuditLogs(t, test.wantAuditLogs, log.String())
		})
	}
}
