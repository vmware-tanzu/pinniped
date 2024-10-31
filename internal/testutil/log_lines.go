// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
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

//"message":"HTTP Request Custom Headers Used",
//"auditID":"some-audit-id",
//"Pinniped-Username":false,"Pinniped-Password":false}`,

func CompareAuditLogs(t *testing.T, wantAuditLogs []WantedAuditLog, actualAuditLogsOneLiner string) {
	t.Helper()

	var wantJsonAuditLogs []map[string]any
	var wantMessages []string
	for _, wantAuditLog := range wantAuditLogs {
		wantJsonAuditLog := make(map[string]any)
		wantJsonAuditLog["level"] = "info"
		wantJsonAuditLog["message"] = wantAuditLog.Message
		wantMessages = append(wantMessages, wantAuditLog.Message)
		wantJsonAuditLog["auditEvent"] = true
		for k, v := range wantAuditLog.Params {
			wantJsonAuditLog[k] = v
		}
		wantJsonAuditLogs = append(wantJsonAuditLogs, wantJsonAuditLog)
	}

	var actualJsonAuditLogs []map[string]any
	var actualMessages []string
	actualAuditLogs := strings.Split(actualAuditLogsOneLiner, "\n")
	require.GreaterOrEqual(t, len(actualAuditLogs), 2)
	actualAuditLogs = actualAuditLogs[:len(actualAuditLogs)-1] // trim off the last ""
	for _, actualAuditLog := range actualAuditLogs {
		actualJsonAuditLog := make(map[string]any)
		err := json.Unmarshal([]byte(actualAuditLog), &actualJsonAuditLog)
		require.NoError(t, err)

		// we don't care to test the caller
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
	for i := range len(wantJsonAuditLogs) {
		// compare each item individually so we know which message it is
		require.Equal(t, wantJsonAuditLogs[i], actualJsonAuditLogs[i],
			"audit log for message %q does not match", wantJsonAuditLogs[i]["message"])
	}
}
