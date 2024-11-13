// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plog

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-semver/semver"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/audit"

	"go.pinniped.dev/internal/here"
)

type fakeSessionGetter struct{}

func (f fakeSessionGetter) GetID() string {
	return "fake-session-id"
}

func TestAudit(t *testing.T) {
	fakeReqContext := audit.WithAuditContext(context.Background())
	audit.WithAuditID(fakeReqContext, "fake-audit-id")

	tests := []struct {
		name      string
		redactPII bool
		run       func(AuditLogger)
		want      string
	}{
		{
			name: "only message, with both nil and empty audit params",
			run: func(a AuditLogger) {
				a.Audit("fake event type 1", nil)
				a.Audit("fake event type 2", &AuditParams{})
			},
			want: here.Doc(`
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestAudit.func1","message":"fake event type 1","auditEvent":true}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestAudit.func1","message":"fake event type 2","auditEvent":true}
			`),
		},
		{
			name: "with request context which has no audit ID",
			run: func(a AuditLogger) {
				a.Audit("fake event type", &AuditParams{ReqCtx: context.Background()})
			},
			want: here.Doc(`
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestAudit.func2","message":"fake event type","auditEvent":true}
			`),
		},
		{
			name: "with request context which has audit ID",
			run: func(a AuditLogger) {
				a.Audit("fake event type", &AuditParams{ReqCtx: fakeReqContext})
			},
			want: here.Doc(`
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestAudit.func3","message":"fake event type","auditEvent":true,"auditID":"fake-audit-id"}
			`),
		},
		{
			name: "with session getter",
			run: func(a AuditLogger) {
				a.Audit("fake event type", &AuditParams{Session: &fakeSessionGetter{}})
			},
			want: here.Doc(`
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestAudit.func4","message":"fake event type","auditEvent":true,"sessionID":"fake-session-id"}
			`),
		},
		{
			name: "with an even number of PII keys and values, nests them under personalInfo and preserves their original order, without redacting PII",
			run: func(a AuditLogger) {
				a.Audit("fake event type", &AuditParams{PIIKeysAndValues: []any{
					"username", "ryan",
					"groups", []string{"g1", "g2"},
					"int", 42,
					"float", 42.75,
					`specialJSONChars"👋\`, `hi"👋\`,
					"map", map[string]int{"k1": 1, "k2": 2},
					"empty_list", []any{},
					"empty_map", map[string]any{},
					"nil_list", []any(nil),
					"nil_map", map[string]any(nil),
					"nil_ptr", (*int)(nil),
					"nil", nil,
				}})
			},
			want: here.Doc(`
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestAudit.func5","message":"fake event type","auditEvent":true,"personalInfo":{"username":"ryan","groups":["g1","g2"],"int":42,"float":42.75,"specialJSONChars\"👋\\":"hi\"👋\\","map":{"k1":1,"k2":2},"empty_list":[],"empty_map":{},"nil_list":[],"nil_map":{},"nil_ptr":null,"nil":null}}
			`),
		},
		{
			name:      "with an even number of PII keys and values and PII configured to be redacted",
			redactPII: true,
			run: func(a AuditLogger) {
				a.Audit("fake event type", &AuditParams{PIIKeysAndValues: []any{
					"username", "ryan",
					"groups", []string{"g1", "g2"},
					"int", 42,
					"float", 42.75,
					`specialJSONChars"👋\`, `hi"👋\`,
					"map", map[string]int{"k1": 1, "k2": 2},
					"empty_list", []any{},
					"empty_map", map[string]any{},
					"nil_list", []any(nil),
					"nil_map", map[string]any(nil),
					"nil_ptr", (*int)(nil),
					"nil", nil,
				}})
			},
			want: here.Doc(`
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestAudit.func6","message":"fake event type","auditEvent":true,"personalInfo":{"username":"redacted","groups":["redacted 2 values"],"int":"redacted","float":"redacted","specialJSONChars\"👋\\":"redacted","map":{"redacted":"redacted 2 keys"},"empty_list":["redacted 0 values"],"empty_map":{"redacted":"redacted 0 keys"},"nil_list":["redacted 0 values"],"nil_map":{"redacted":"redacted 0 keys"},"nil_ptr":"redacted","nil":"redacted"}}
			`),
		},
		{
			name: "with an illegal single PII keys and values, quietly ignores it",
			run: func(a AuditLogger) {
				a.Audit("fake event type", &AuditParams{PIIKeysAndValues: []any{"foo"}})
			},
			want: here.Doc(`
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestAudit.func7","message":"fake event type","auditEvent":true}
			`),
		},
		{
			name: "with an illegal odd number of PII keys and values, quietly ignores the last one",
			run: func(a AuditLogger) {
				a.Audit("fake event type", &AuditParams{PIIKeysAndValues: []any{"foo", 42, "bar"}})
			},
			want: here.Doc(`
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestAudit.func8","message":"fake event type","auditEvent":true,"personalInfo":{"foo":42}}
			`),
		},
		{
			name: "with a PII keys that is not a string, converts it to an error-looking key name rather than having the function return errors or panic",
			run: func(a AuditLogger) {
				a.Audit("fake event type", &AuditParams{PIIKeysAndValues: []any{42, "foo", "bar", "baz"}})
			},
			want: here.Doc(`
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestAudit.func9","message":"fake event type","auditEvent":true,"personalInfo":{"cannotCastKeyNameToString":"foo","bar":"baz"}}
			`),
		},
		{
			name: "with arbitrary keys and values",
			run: func(a AuditLogger) {
				a.Audit("fake event type", &AuditParams{KeysAndValues: []any{"foo", 42, "bar", "baz"}})
			},
			want: here.Doc(`
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestAudit.func10","message":"fake event type","auditEvent":true,"foo":42,"bar":"baz"}
			`),
		},
		{
			name: "with everything, showing order of keys printed in log",
			run: func(a AuditLogger) {
				a.Audit("fake event type", &AuditParams{
					ReqCtx:           fakeReqContext,
					Session:          &fakeSessionGetter{},
					PIIKeysAndValues: []any{"username", "ryan", "groups", []string{"g1", "g2"}, "bat", 14},
					KeysAndValues:    []any{"foo", 42, "bar", "baz"},
				})
			},
			want: here.Doc(`
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestAudit.func11","message":"fake event type","auditEvent":true,"auditID":"fake-audit-id","sessionID":"fake-session-id","personalInfo":{"username":"ryan","groups":["g1","g2"],"bat":14},"foo":42,"bar":"baz"}
			`),
		},
		{
			name:      "with everything, when PII is redacted, showing order of keys printed in log",
			redactPII: true,
			run: func(a AuditLogger) {
				a.Audit("fake event type", &AuditParams{
					ReqCtx:           fakeReqContext,
					Session:          &fakeSessionGetter{},
					PIIKeysAndValues: []any{"username", "ryan", "groups", []string{"g1", "g2"}, "bat", 14},
					KeysAndValues:    []any{"foo", 42, "bar", "baz"},
				})
			},
			want: here.Doc(`
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestAudit.func12","message":"fake event type","auditEvent":true,"auditID":"fake-audit-id","sessionID":"fake-session-id","personalInfo":{"username":"redacted","groups":["redacted 2 values"],"bat":"redacted"},"foo":42,"bar":"baz"}
			`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			l, actualAuditLogs := TestAuditLoggerWithConfig(t, AuditLogConfig{LogUsernamesAndGroupNames: !test.redactPII})
			test.run(l)

			require.Equal(t, strings.TrimSpace(test.want), strings.TrimSpace(actualAuditLogs.String()))
		})
	}
}

func TestPlog(t *testing.T) {
	runtimeVersion := runtime.Version()
	if strings.HasPrefix(runtimeVersion, "go") {
		runtimeVersion, _ = strings.CutPrefix(runtimeVersion, "go")
	}
	runtimeVersionSemver, err := semver.NewVersion(runtimeVersion)
	require.NoError(t, err)

	tests := []struct {
		name string
		run  func(Logger)
		want string
	}{
		{
			name: "basic",
			run:  testAllPlogMethods,
			want: here.Doc(`
				{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"e","panda":2,"error":"some err"}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"w","warning":true,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"we","warning":true,"error":"some err","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"i","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"ie","error":"some err","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"d","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"de","error":"some err","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"t","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"te","error":"some err","panda":2}
				{"level":"all","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"all","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"always","panda":2}
			`),
		},
		{
			name: "with values",
			run: func(l Logger) {
				testAllPlogMethods(l.WithValues("hi", 42))
			},
			want: here.Doc(`
				{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"e","hi":42,"panda":2,"error":"some err"}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"w","hi":42,"warning":true,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"we","hi":42,"warning":true,"error":"some err","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"i","hi":42,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"ie","hi":42,"error":"some err","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"d","hi":42,"panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"de","hi":42,"error":"some err","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"t","hi":42,"panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"te","hi":42,"error":"some err","panda":2}
				{"level":"all","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"all","hi":42,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"always","hi":42,"panda":2}
			`),
		},
		{
			name: "with values conflict", // duplicate key is included twice ...
			run: func(l Logger) {
				testAllPlogMethods(l.WithValues("panda", false))
			},
			want: here.Doc(`
				{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"e","panda":false,"panda":2,"error":"some err"}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"w","panda":false,"warning":true,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"we","panda":false,"warning":true,"error":"some err","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"i","panda":false,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"ie","panda":false,"error":"some err","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"d","panda":false,"panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"de","panda":false,"error":"some err","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"t","panda":false,"panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"te","panda":false,"error":"some err","panda":2}
				{"level":"all","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"all","panda":false,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"always","panda":false,"panda":2}
			`),
		},
		{
			name: "with values nested",
			run: func(l Logger) {
				testAllPlogMethods(l.WithValues("hi", 42).WithValues("not", time.Hour))
			},
			want: here.Doc(`
				{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"e","hi":42,"not":"1h0m0s","panda":2,"error":"some err"}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"w","hi":42,"not":"1h0m0s","warning":true,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"we","hi":42,"not":"1h0m0s","warning":true,"error":"some err","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"i","hi":42,"not":"1h0m0s","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"ie","hi":42,"not":"1h0m0s","error":"some err","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"d","hi":42,"not":"1h0m0s","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"de","hi":42,"not":"1h0m0s","error":"some err","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"t","hi":42,"not":"1h0m0s","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"te","hi":42,"not":"1h0m0s","error":"some err","panda":2}
				{"level":"all","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"all","hi":42,"not":"1h0m0s","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"always","hi":42,"not":"1h0m0s","panda":2}
			`),
		},
		{
			name: "with name",
			run: func(l Logger) {
				testAllPlogMethods(l.WithName("yoyo"))
			},
			want: here.Doc(`
				{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"e","panda":2,"error":"some err"}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"w","warning":true,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"we","warning":true,"error":"some err","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"i","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"ie","error":"some err","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"d","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"de","error":"some err","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"t","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"te","error":"some err","panda":2}
				{"level":"all","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"all","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"always","panda":2}
			`),
		},
		{
			name: "with name nested",
			run: func(l Logger) {
				testAllPlogMethods(l.WithName("yoyo").WithName("gold"))
			},
			want: here.Doc(`
				{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo.gold","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"e","panda":2,"error":"some err"}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo.gold","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"w","warning":true,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo.gold","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"we","warning":true,"error":"some err","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo.gold","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"i","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo.gold","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"ie","error":"some err","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo.gold","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"d","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo.gold","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"de","error":"some err","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo.gold","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"t","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo.gold","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"te","error":"some err","panda":2}
				{"level":"all","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo.gold","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"all","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"yoyo.gold","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"always","panda":2}
			`),
		},
		{
			name: "depth 3",
			run: func(l Logger) {
				testAllPlogMethods(l.withDepth(3))
			},
			want: here.Doc(`
				{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","caller":"testing/testing.go:<line>$testing.tRunner","message":"e","panda":2,"error":"some err"}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"testing/testing.go:<line>$testing.tRunner","message":"w","warning":true,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"testing/testing.go:<line>$testing.tRunner","message":"we","warning":true,"error":"some err","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"testing/testing.go:<line>$testing.tRunner","message":"i","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"testing/testing.go:<line>$testing.tRunner","message":"ie","error":"some err","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"testing/testing.go:<line>$testing.tRunner","message":"d","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"testing/testing.go:<line>$testing.tRunner","message":"de","error":"some err","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"testing/testing.go:<line>$testing.tRunner","message":"t","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"testing/testing.go:<line>$testing.tRunner","message":"te","error":"some err","panda":2}
				{"level":"all","timestamp":"2099-08-08T13:57:36.123456Z","caller":"testing/testing.go:<line>$testing.tRunner","message":"all","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"testing/testing.go:<line>$testing.tRunner","message":"always","panda":2}
			`),
		},
		{
			name: "depth 2",
			run: func(l Logger) {
				testAllPlogMethods(l.withDepth(2))
			},
			want: here.Doc(`
				{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func16","message":"e","panda":2,"error":"some err"}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func16","message":"w","warning":true,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func16","message":"we","warning":true,"error":"some err","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func16","message":"i","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func16","message":"ie","error":"some err","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func16","message":"d","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func16","message":"de","error":"some err","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func16","message":"t","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func16","message":"te","error":"some err","panda":2}
				{"level":"all","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func16","message":"all","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func16","message":"always","panda":2}
			`),
		},
		{
			name: "depth 1",
			run: func(l Logger) {
				testAllPlogMethods(l.withDepth(1))
			},
			want: here.Doc(`
				{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func8","message":"e","panda":2,"error":"some err"}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func8","message":"w","warning":true,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func8","message":"we","warning":true,"error":"some err","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func8","message":"i","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func8","message":"ie","error":"some err","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func8","message":"d","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func8","message":"de","error":"some err","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func8","message":"t","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func8","message":"te","error":"some err","panda":2}
				{"level":"all","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func8","message":"all","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.func8","message":"always","panda":2}
			`),
		},
		{
			name: "depth 0",
			run: func(l Logger) {
				testAllPlogMethods(l.withDepth(0))
			},
			want: here.Doc(`
				{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"e","panda":2,"error":"some err"}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"w","warning":true,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"we","warning":true,"error":"some err","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"i","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"ie","error":"some err","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"d","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"de","error":"some err","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"t","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"te","error":"some err","panda":2}
				{"level":"all","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"all","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.testAllPlogMethods","message":"always","panda":2}
			`),
		},
		{
			name: "depth -1",
			run: func(l Logger) {
				testAllPlogMethods(l.withDepth(-1))
			},
			want: here.Doc(`
				{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.Error","message":"e","panda":2,"error":"some err"}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.Warning","message":"w","warning":true,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.WarningErr","message":"we","warning":true,"error":"some err","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.Info","message":"i","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.InfoErr","message":"ie","error":"some err","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.Debug","message":"d","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.DebugErr","message":"de","error":"some err","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.Trace","message":"t","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.TraceErr","message":"te","error":"some err","panda":2}
				{"level":"all","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.All","message":"all","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.Always","message":"always","panda":2}
			`),
		},
		{
			name: "depth -2",
			run: func(l Logger) {
				testAllPlogMethods(l.withDepth(-2))
			},
			want: here.Doc(`
				{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","caller":"logr@v1.4.2/logr.go:<line>$logr.Logger.Error","message":"e","panda":2,"error":"some err"}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.warningDepth","message":"w","warning":true,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.warningDepth","message":"we","warning":true,"error":"some err","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.infoDepth","message":"i","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.infoDepth","message":"ie","error":"some err","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.debugDepth","message":"d","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.debugDepth","message":"de","error":"some err","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.traceDepth","message":"t","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.traceDepth","message":"te","error":"some err","panda":2}
				{"level":"all","timestamp":"2099-08-08T13:57:36.123456Z","caller":"logr@v1.4.2/logr.go:<line>$logr.Logger.Info","message":"all","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"logr@v1.4.2/logr.go:<line>$logr.Logger.Info","message":"always","panda":2}
			`),
		},
		{
			name: "depth -3",
			run: func(l Logger) {
				testAllPlogMethods(l.withDepth(-3))
			},
			want: here.Doc(`
				{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","caller":"zapr@v1.3.0/zapr.go:<line>$zapr.(*zapLogger).Error","message":"e","panda":2,"error":"some err"}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"logr@v1.4.2/logr.go:<line>$logr.Logger.Info","message":"w","warning":true,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"logr@v1.4.2/logr.go:<line>$logr.Logger.Info","message":"we","warning":true,"error":"some err","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"logr@v1.4.2/logr.go:<line>$logr.Logger.Info","message":"i","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"logr@v1.4.2/logr.go:<line>$logr.Logger.Info","message":"ie","error":"some err","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"logr@v1.4.2/logr.go:<line>$logr.Logger.Info","message":"d","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"logr@v1.4.2/logr.go:<line>$logr.Logger.Info","message":"de","error":"some err","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"logr@v1.4.2/logr.go:<line>$logr.Logger.Info","message":"t","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"logr@v1.4.2/logr.go:<line>$logr.Logger.Info","message":"te","error":"some err","panda":2}
				{"level":"all","timestamp":"2099-08-08T13:57:36.123456Z","caller":"zapr@v1.3.0/zapr.go:<line>$zapr.(*zapLogger).Info","message":"all","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"zapr@v1.3.0/zapr.go:<line>$zapr.(*zapLogger).Info","message":"always","panda":2}
			`),
		},
		{
			name: "closure",
			run: func(l Logger) {
				func() {
					func() {
						testErr := fmt.Errorf("some err")

						l.Error("e", testErr, "panda", 2)
						l.Warning("w", "panda", 2)
						l.WarningErr("we", testErr, "panda", 2)
						l.Info("i", "panda", 2)
						l.InfoErr("ie", testErr, "panda", 2)
						l.Debug("d", "panda", 2)
						l.DebugErr("de", testErr, "panda", 2)
						l.Trace("t", "panda", 2)
						l.TraceErr("te", testErr, "panda", 2)
						l.All("all", "panda", 2)
						l.Always("always", "panda", 2)
					}()
				}()
			},
			want: here.Docf(`
				{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.%[1]s","message":"e","panda":2,"error":"some err"}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.%[1]s","message":"w","warning":true,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.%[1]s","message":"we","warning":true,"error":"some err","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.%[1]s","message":"i","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.%[1]s","message":"ie","error":"some err","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.%[1]s","message":"d","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.%[1]s","message":"de","error":"some err","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.%[1]s","message":"t","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.%[1]s","message":"te","error":"some err","panda":2}
				{"level":"all","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.%[1]s","message":"all","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog_test.go:<line>$plog.TestPlog.%[1]s","message":"always","panda":2}
			`, func() string {
				switch {
				case runtimeVersionSemver.Major == 1 && runtimeVersionSemver.Minor == 21:
					// Format of string for Go 1.21
					return "func13.TestPlog.func13.1.func2"
				case runtimeVersionSemver.Major == 1 && runtimeVersionSemver.Minor >= 22:
					// Format of string for Go 1.22+
					return "func13.TestPlog.func13.1.2"
				default:
					// Format of string for Go 1.20 and below.
					return "func13.1.1"
				}
			}()),
		},
		{
			name: "closure depth -1",
			run: func(l Logger) {
				func() {
					func() {
						testErr := fmt.Errorf("some err")

						l = l.withDepth(-1)
						l.Error("e", testErr, "panda", 2)
						l.Warning("w", "panda", 2)
						l.WarningErr("we", testErr, "panda", 2)
						l.Info("i", "panda", 2)
						l.InfoErr("ie", testErr, "panda", 2)
						l.Debug("d", "panda", 2)
						l.DebugErr("de", testErr, "panda", 2)
						l.Trace("t", "panda", 2)
						l.TraceErr("te", testErr, "panda", 2)
						l.All("all", "panda", 2)
						l.Always("always", "panda", 2)
					}()
				}()
			},
			want: here.Doc(`
				{"level":"error","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.Error","message":"e","panda":2,"error":"some err"}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.Warning","message":"w","warning":true,"panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.WarningErr","message":"we","warning":true,"error":"some err","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.Info","message":"i","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.InfoErr","message":"ie","error":"some err","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.Debug","message":"d","panda":2}
				{"level":"debug","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.DebugErr","message":"de","error":"some err","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.Trace","message":"t","panda":2}
				{"level":"trace","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.TraceErr","message":"te","error":"some err","panda":2}
				{"level":"all","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.All","message":"all","panda":2}
				{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","caller":"plog/plog.go:<line>$plog.pLogger.Always","message":"always","panda":2}
			`),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			testLogger, log := TestLogger(t)
			test.run(testLogger)

			require.Equal(t, strings.TrimSpace(test.want), strings.TrimSpace(log.String()))
		})
	}
}

func testAllPlogMethods(l Logger) {
	testErr := fmt.Errorf("some err")

	l.Error("e", testErr, "panda", 2)
	l.Warning("w", "panda", 2)
	l.WarningErr("we", testErr, "panda", 2)
	l.Info("i", "panda", 2)
	l.InfoErr("ie", testErr, "panda", 2)
	l.Debug("d", "panda", 2)
	l.DebugErr("de", testErr, "panda", 2)
	l.Trace("t", "panda", 2)
	l.TraceErr("te", testErr, "panda", 2)
	l.All("all", "panda", 2)
	l.Always("always", "panda", 2)
}
