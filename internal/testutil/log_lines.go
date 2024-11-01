// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/federationdomain/stateparam"
)

func RequireLogLines(t *testing.T, wantLogs []string, log *bytes.Buffer) {
	t.Helper()

	expectedLogs := ""
	if len(wantLogs) > 0 {
		expectedLogs = strings.Join(wantLogs, "\n") + "\n"
	}
	require.Equal(t, expectedLogs, log.String())
}

type WantedAuditLog struct {
	Message string
	Params  map[string]any
}

func WantAuditLog(message string, params map[string]any, auditID ...string) WantedAuditLog {
	result := WantedAuditLog{
		Message: message,
		Params:  params,
	}
	if len(auditID) > 0 {
		result.Params["auditID"] = auditID[0]
	}
	return result
}

func GetStateParam(t *testing.T, fullURL string) stateparam.Encoded {
	var encodedStateParam stateparam.Encoded
	if fullURL != "" {
		path, err := url.Parse(fullURL)
		require.NoError(t, err)
		encodedStateParam = stateparam.Encoded(path.Query().Get("state"))
	}

	return encodedStateParam
}

func CompareAuditLogs(t *testing.T, wantAuditLogs []WantedAuditLog, actualAuditLogsOneLiner string) {
	t.Helper()

	// There are tests that verify that no audit events were emitted
	if len(wantAuditLogs) == 0 {
		require.Empty(t, actualAuditLogsOneLiner, "no audit events were expected, but some were found")
		return
	}

	wantJsonAuditLogs := make([]map[string]any, 0)
	wantMessages := make([]string, 0)
	for _, wantAuditLog := range wantAuditLogs {
		wantJsonAuditLog := make(map[string]any)
		wantJsonAuditLog["level"] = "info"
		wantJsonAuditLog["message"] = wantAuditLog.Message
		wantMessages = append(wantMessages, wantAuditLog.Message)
		wantJsonAuditLog["auditEvent"] = true
		wantJsonAuditLog["timestamp"] = "2099-08-08T13:57:36.123456Z"
		for k, v := range wantAuditLog.Params {
			wantJsonAuditLog[k] = v
		}
		wantJsonAuditLogs = append(wantJsonAuditLogs, wantJsonAuditLog)
	}

	actualJsonAuditLogs := make([]map[string]any, 0)
	actualMessages := make([]string, 0)
	actualAuditLogs := strings.Split(actualAuditLogsOneLiner, "\n")
	require.GreaterOrEqual(t, len(actualAuditLogs), 2)
	actualAuditLogs = actualAuditLogs[:len(actualAuditLogs)-1] // trim off the last ""
	for _, actualAuditLog := range actualAuditLogs {
		actualJsonAuditLog := make(map[string]any)
		err := json.Unmarshal([]byte(actualAuditLog), &actualJsonAuditLog)
		require.NoError(t, err)

		// we don't care to test exact equality on the caller - just make sure it is a non-empty string
		caller, ok := actualJsonAuditLog["caller"]
		require.True(t, ok)
		require.NotEmpty(t, caller, "caller for message %q must not be empty", actualJsonAuditLog["message"])
		delete(actualJsonAuditLog, "caller")
		actualJsonAuditLogs = append(actualJsonAuditLogs, actualJsonAuditLog)

		actualMessage, ok := actualJsonAuditLog["message"].(string)
		require.True(t, ok, "actual message is not a string, instead %+v", actualJsonAuditLog["message"])
		actualMessages = append(actualMessages, actualMessage)
	}

	// We should check array indices first so that we don't exceed any boundaries.
	// But we also want to be sure to indicate to the caller what went wrong, so compare the messages.
	require.Equal(t, wantMessages, actualMessages)

	// We can expect the audit logs to be ordered deterministically.
	for i := range wantJsonAuditLogs {
		// compare each item individually so we know which message it is
		require.Equal(t, wantJsonAuditLogs[i], actualJsonAuditLogs[i],
			"audit event for message %q does not match", wantJsonAuditLogs[i]["message"])
	}
}
